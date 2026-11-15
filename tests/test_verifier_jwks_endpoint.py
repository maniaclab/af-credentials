"""BrokerTokenVerifier against a real local HTTP JWKS endpoint.

Covers the refetch policy (docs: contract item U7): an unknown ``kid`` refetches
at most once per cooldown, and a failed refetch keeps serving held keys.
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

import pytest
from conftest import AUDIENCE, ISSUER, mint_token, public_jwk

from af_credentials.verifier import BrokerTokenVerifier

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cryptography.hazmat.primitives.asymmetric import rsa

COOLDOWN = 0.2


class JwksServer:
    """A JWKS endpoint on 127.0.0.1 whose document and availability tests control; ``fetches`` counts every request."""

    def __init__(self) -> None:
        self.document: dict[str, Any] = {"keys": []}
        self.healthy = True
        self.fetches = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                outer.fetches += 1
                if not outer.healthy:
                    self.send_response(503)
                    self.end_headers()
                    return
                body = json.dumps(outer.document).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._httpd.server_port}/.well-known/jwks.json"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join()


@pytest.fixture
def jwks_server() -> Iterator[JwksServer]:
    server = JwksServer()
    server.start()
    yield server
    server.stop()


def _verifier(server: JwksServer, **kwargs: Any) -> BrokerTokenVerifier:
    return BrokerTokenVerifier(server.url, ISSUER, AUDIENCE, **kwargs)


class TestUnknownKidRateLimit:
    async def test_forged_kids_refetch_once_within_cooldown(
        self, jwks_server: JwksServer, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        jwks_server.document = {"keys": [public_jwk(rsa_keypair.public_key())]}
        verifier = _verifier(jwks_server, unknown_kid_cooldown=60.0)
        await verifier.verify(mint_token(rsa_keypair))
        assert jwks_server.fetches == 1

        for i in range(20):
            forged = mint_token(rsa_keypair, kid=f"forged-{i}")
            assert await verifier.verify(forged) is None

        # One early refetch for the first forged kid; the other 19 are absorbed.
        assert jwks_server.fetches == 2

    async def test_refetch_allowed_again_after_cooldown(
        self, jwks_server: JwksServer, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        jwks_server.document = {"keys": [public_jwk(rsa_keypair.public_key())]}
        verifier = _verifier(jwks_server, unknown_kid_cooldown=COOLDOWN)
        await verifier.verify(mint_token(rsa_keypair))

        await verifier.verify(mint_token(rsa_keypair, kid="forged-a"))
        await verifier.verify(mint_token(rsa_keypair, kid="forged-b"))
        assert jwks_server.fetches == 2

        await asyncio.sleep(COOLDOWN + 0.05)
        await verifier.verify(mint_token(rsa_keypair, kid="forged-c"))
        assert jwks_server.fetches == 3

    async def test_rotation_picked_up_by_one_refetch(
        self,
        jwks_server: JwksServer,
        rsa_keypair: rsa.RSAPrivateKey,
        second_rsa_keypair: rsa.RSAPrivateKey,
    ) -> None:
        jwks_server.document = {"keys": [public_jwk(rsa_keypair.public_key())]}
        verifier = _verifier(jwks_server, unknown_kid_cooldown=60.0)
        await verifier.verify(mint_token(rsa_keypair))

        jwks_server.document = {
            "keys": [
                public_jwk(rsa_keypair.public_key()),
                public_jwk(second_rsa_keypair.public_key()),
            ]
        }
        rotated = mint_token(second_rsa_keypair)

        assert await verifier.verify(rotated) is not None
        assert await verifier.verify(rotated) is not None
        assert jwks_server.fetches == 2


class TestEndpointOutage:
    async def test_known_kid_still_verifies_when_ttl_refetch_fails(
        self, jwks_server: JwksServer, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        jwks_server.document = {"keys": [public_jwk(rsa_keypair.public_key())]}
        verifier = _verifier(jwks_server, cache_ttl=0.01, unknown_kid_cooldown=COOLDOWN)
        token = mint_token(rsa_keypair)
        assert await verifier.verify(token) is not None

        jwks_server.healthy = False
        await asyncio.sleep(0.02)

        assert await verifier.verify(token) is not None

    async def test_unknown_kid_rejected_not_raised_when_endpoint_down(
        self, jwks_server: JwksServer, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        jwks_server.document = {"keys": [public_jwk(rsa_keypair.public_key())]}
        verifier = _verifier(jwks_server, unknown_kid_cooldown=COOLDOWN)
        await verifier.verify(mint_token(rsa_keypair))

        jwks_server.healthy = False

        assert await verifier.verify(mint_token(rsa_keypair, kid="unknown")) is None
        assert await verifier.verify(mint_token(rsa_keypair)) is not None

    async def test_failed_ttl_refetch_is_not_retried_every_request(
        self, jwks_server: JwksServer, rsa_keypair: rsa.RSAPrivateKey
    ) -> None:
        jwks_server.document = {"keys": [public_jwk(rsa_keypair.public_key())]}
        verifier = _verifier(jwks_server, cache_ttl=0.01, unknown_kid_cooldown=60.0)
        token = mint_token(rsa_keypair)
        await verifier.verify(token)

        jwks_server.healthy = False
        await asyncio.sleep(0.02)
        for _ in range(10):
            assert await verifier.verify(token) is not None

        # The first failed attempt only; the rest wait out the cooldown.
        assert jwks_server.fetches == 2

    async def test_recovers_after_outage(
        self,
        jwks_server: JwksServer,
        rsa_keypair: rsa.RSAPrivateKey,
        second_rsa_keypair: rsa.RSAPrivateKey,
    ) -> None:
        jwks_server.document = {"keys": [public_jwk(rsa_keypair.public_key())]}
        verifier = _verifier(jwks_server, unknown_kid_cooldown=COOLDOWN)
        await verifier.verify(mint_token(rsa_keypair))

        jwks_server.healthy = False
        rotated = mint_token(second_rsa_keypair)
        assert await verifier.verify(rotated) is None

        jwks_server.healthy = True
        jwks_server.document = {"keys": [public_jwk(second_rsa_keypair.public_key())]}
        await asyncio.sleep(COOLDOWN + 0.05)

        assert await verifier.verify(rotated) is not None
