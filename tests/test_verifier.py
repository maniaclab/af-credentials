"""Tests for BrokerTokenVerifier (af_credentials.verifier).

Tokens are minted exactly like af_mcp_broker.credentials.broker_issued's
BrokerTokenIssuer.mint() (see conftest.mint_token): iss/sub/aud/exp/iat/jti
always, uid/gid/unixname only when present -- af-credentials is the
consumer side of that same contract (docs/auth.md "AF Broker Identity
Token").
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any

import httpx2
import jwt
import pytest
from conftest import AUDIENCE, ISSUER, mint_token, public_jwk, rfc7638_thumbprint

from af_credentials.verifier import BrokerClaims, BrokerTokenVerifier

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import rsa


def _jwks_client(
    jwks_by_call: list[dict[str, Any]],
) -> tuple[httpx2.AsyncClient, list[str]]:
    """Return a client whose transport serves the successive JWKS documents in *jwks_by_call* (one per call; the last is repeated once exhausted) and a list this appends one entry to per request, for call-count assertions."""
    calls: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(str(request.url))
        index = min(len(calls) - 1, len(jwks_by_call) - 1)
        return httpx2.Response(200, json=jwks_by_call[index])

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler)), calls


class TestVerifyValidToken:
    async def test_returns_claims(self, rsa_keypair: rsa.RSAPrivateKey) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair)

        claims = await verifier.verify(token)

        assert claims is not None
        assert claims == BrokerClaims(
            sub="af|12345", jti="test-jti-0001", exp=claims.exp
        )
        assert claims.uid is None
        assert claims.gid is None
        assert claims.unixname is None

    async def test_returns_posix_claims_when_present(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair, uid=33155, gid=33155, unixname="kratsg")

        claims = await verifier.verify(token)

        assert claims is not None
        assert (claims.uid, claims.gid, claims.unixname) == (33155, 33155, "kratsg")


class TestVerifyRejectsBadClaims:
    async def test_wrong_audience_returns_none(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair, aud="some-other-backend")

        assert await verifier.verify(token) is None

    async def test_wrong_issuer_returns_none(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair, iss="https://not-the-broker.example")

        assert await verifier.verify(token) is None

    async def test_expired_token_returns_none(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair, ttl_seconds=-10)

        assert await verifier.verify(token) is None

    async def test_garbage_token_returns_none(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )

        assert await verifier.verify("not-a-jwt-at-all") is None

    async def test_wrong_signing_key_returns_none(
        self,
        rsa_keypair: rsa.RSAPrivateKey,
        second_rsa_keypair: rsa.RSAPrivateKey,
    ) -> None:
        """A token signed by a key whose kid the JWKS never publishes (not even after refetch) must not verify."""
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(second_rsa_keypair)

        assert await verifier.verify(token) is None


class TestVerifyLogsRejectionReason:
    """Every invalid-token path must leave a debug-level record of WHY (still returning None) -- uniform silent 401s were undiagnosable in production."""

    def _verifier(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> tuple[BrokerTokenVerifier, httpx2.AsyncClient]:
        client, _calls = _jwks_client(
            [{"keys": [public_jwk(rsa_keypair.public_key())]}]
        )
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        return verifier, client

    async def test_malformed_token_logs_header_parse_failure(
        self, rsa_keypair: rsa.RSAPrivateKey, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG, logger="af_credentials.verifier")
        verifier, _client = self._verifier(rsa_keypair)

        assert await verifier.verify("not-a-jwt-at-all") is None
        assert "malformed" in caplog.text
        # PyJWT's own message ("Not enough segments") must be included.
        assert "segments" in caplog.text

    async def test_missing_kid_logs_reason(
        self, rsa_keypair: rsa.RSAPrivateKey, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG, logger="af_credentials.verifier")
        verifier, _client = self._verifier(rsa_keypair)
        now = int(time.time())
        # jwt.encode without an explicit header omits "kid" entirely.
        token = jwt.encode(
            {
                "iss": ISSUER,
                "sub": "af|12345",
                "aud": AUDIENCE,
                "exp": now + 600,
                "iat": now,
                "jti": "test-jti-0001",
            },
            rsa_keypair,
            algorithm="RS256",
        )

        assert await verifier.verify(token) is None
        assert "kid" in caplog.text
        assert token not in caplog.text

    async def test_unknown_kid_logs_kid_and_available_kids(
        self,
        rsa_keypair: rsa.RSAPrivateKey,
        second_rsa_keypair: rsa.RSAPrivateKey,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG, logger="af_credentials.verifier")
        verifier, _client = self._verifier(rsa_keypair)
        token = mint_token(second_rsa_keypair)

        assert await verifier.verify(token) is None
        # Both the token's kid and the kids the JWKS actually carries must
        # appear, so a rotation mismatch is diagnosable from the log alone.
        assert rfc7638_thumbprint(second_rsa_keypair.public_key()) in caplog.text
        assert rfc7638_thumbprint(rsa_keypair.public_key()) in caplog.text
        assert token not in caplog.text

    async def test_decode_failure_logs_pyjwt_reason(
        self, rsa_keypair: rsa.RSAPrivateKey, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG, logger="af_credentials.verifier")
        verifier, _client = self._verifier(rsa_keypair)
        token = mint_token(rsa_keypair, aud="some-other-backend")

        assert await verifier.verify(token) is None
        # PyJWT's InvalidAudienceError message pinpoints the failing check.
        assert "audience" in caplog.text.lower()
        assert token not in caplog.text


class TestKeyRotation:
    async def test_unknown_kid_triggers_one_refetch(
        self,
        rsa_keypair: rsa.RSAPrivateKey,
        second_rsa_keypair: rsa.RSAPrivateKey,
    ) -> None:
        """A token signed by a newly-rotated-in key, whose kid isn't in the verifier's cached JWKS yet, must succeed after exactly one refetch."""
        stale_jwks = {"keys": [public_jwk(rsa_keypair.public_key())]}
        rotated_jwks = {
            "keys": [
                public_jwk(rsa_keypair.public_key()),
                public_jwk(second_rsa_keypair.public_key()),
            ]
        }
        client, calls = _jwks_client([stale_jwks, rotated_jwks])
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        # Prime the cache with the stale JWKS (one fetch already spent).
        await verifier.verify(mint_token(rsa_keypair))
        assert len(calls) == 1

        token = mint_token(second_rsa_keypair)
        claims = await verifier.verify(token)

        assert claims is not None
        assert claims.sub == "af|12345"
        assert len(calls) == 2

    async def test_unknown_kid_that_never_appears_returns_none_after_one_refetch(
        self,
        rsa_keypair: rsa.RSAPrivateKey,
        second_rsa_keypair: rsa.RSAPrivateKey,
    ) -> None:
        jwks = {"keys": [public_jwk(rsa_keypair.public_key())]}
        client, calls = _jwks_client([jwks])
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        # Warm the cache with a known-good token first (1 fetch) so the
        # unknown-kid lookup below is against an already-populated cache,
        # not a cold one -- otherwise the initial populate and the "refetch"
        # would be the same fetch.
        await verifier.verify(mint_token(rsa_keypair))
        assert len(calls) == 1

        token = mint_token(second_rsa_keypair)

        assert await verifier.verify(token) is None
        # One refetch for the unknown kid -- never a second refetch for the
        # same still-missing kid.
        assert len(calls) == 2


class TestCacheTtl:
    async def test_within_ttl_does_not_refetch(
        self, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        client, calls = _jwks_client([{"keys": [public_jwk(rsa_keypair.public_key())]}])
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            cache_ttl=300.0,
            http_client=client,
        )
        token = mint_token(rsa_keypair)

        await verifier.verify(token)
        await verifier.verify(token)
        await verifier.verify(token)

        assert len(calls) == 1

    async def test_ttl_expiry_triggers_refetch(
        self, rsa_keypair: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, calls = _jwks_client([{"keys": [public_jwk(rsa_keypair.public_key())]}])
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            cache_ttl=0.01,
            http_client=client,
        )
        token = mint_token(rsa_keypair)

        await verifier.verify(token)
        await asyncio.sleep(0.02)
        await verifier.verify(token)

        assert len(calls) == 2


class TestTransportErrorsPropagate:
    async def test_connect_error_raises(self, rsa_keypair: rsa.RSAPrivateKey) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("connection refused")

        client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair)

        with pytest.raises(httpx2.ConnectError):
            await verifier.verify(token)

    async def test_server_error_raises(self, rsa_keypair: rsa.RSAPrivateKey) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(500, text="internal error")

        client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
        verifier = BrokerTokenVerifier(
            "https://broker.example/.well-known/jwks.json",
            ISSUER,
            AUDIENCE,
            http_client=client,
        )
        token = mint_token(rsa_keypair)

        with pytest.raises(httpx2.HTTPStatusError):
            await verifier.verify(token)
