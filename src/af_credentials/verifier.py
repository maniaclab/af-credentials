"""Async verification of AF Broker Identity Tokens.

The token format is documented in docs/auth.md ("AF Broker Identity Token",
issue #162) and minted by ``af_mcp_broker.credentials.broker_issued``: an
identity assertion only -- ``iss``/``sub``/``aud``/``exp``/``iat``/``jti``
always present, ``uid``/``gid``/``unixname`` present only for targets whose
broker config sets ``include_posix``. Deliberately absent: capabilities,
groups, or any authorization claim -- this module surfaces nothing beyond
what the token itself carries.

This module has no dependency on af_mcp_broker or any web framework: it is
the client half of the contract, meant to be embedded in any backend that
trusts the broker as a token issuer (ami-mcp's broker mode, later
rucio-mcp), verifying against the broker's own published JWKS
(``GET /.well-known/jwks.json``) with a standard JWT library.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx2
import jwt
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BrokerClaims:
    """Decoded, verified claims from an AF Broker Identity Token.

    Mirrors the claim set ``BrokerTokenIssuer.mint()`` signs: ``sub``,
    ``jti``, and ``exp`` are always present on a verified token; ``uid``/
    ``gid``/``unixname`` are ``None`` unless the issuing broker included
    POSIX identity claims for this token's audience.
    """

    sub: str
    jti: str
    exp: int
    uid: int | None = None
    gid: int | None = None
    unixname: str | None = None


class BrokerTokenVerifier:
    """Verifies AF Broker Identity Tokens (RS256) against a broker's published JWKS.

    JWKS keys are cached in-process for *cache_ttl* seconds, keyed by
    ``kid``. A token whose ``kid`` isn't in the current cache triggers an
    early refetch (to pick up a key rotated in since the last fetch, per
    docs/auth.md's rotation procedure), but at most one per
    *unknown_kid_cooldown* seconds, so a stream of forged ``kid`` values
    cannot turn every request into a JWKS fetch. A token whose ``kid`` is
    still unknown after that refetch (or while the cooldown is running) is
    rejected as invalid.

    When a refetch fails and keys are already held, the held keys keep
    serving: tokens with a known ``kid`` verify, tokens with an unknown
    ``kid`` are rejected, and the failure is logged at WARNING. The next
    attempt waits out the same cooldown. Only a verifier that holds no keys
    at all (nothing fetched yet) cannot judge a token, so it lets the
    transport error propagate.

    ``verify()`` returns ``None`` for every way a token can be *invalid*
    (bad signature, wrong issuer/audience, expired, malformed, unknown
    key) so callers can treat "not authenticated" uniformly; the specific
    rejection reason is logged at DEBUG level (never the token itself --
    it is a bearer credential) so operators can tell the paths apart
    without changing the contract. It does NOT
    catch transport-level failures (a network error, or the JWKS endpoint
    itself returning a non-2xx status) when no keys are held yet -- those
    propagate as exceptions, so a caller can distinguish "the broker is
    unreachable" from "this token is bad" and respond accordingly (e.g. a
    503 vs. a 401).
    """

    def __init__(
        self,
        jwks_url: str,
        issuer: str,
        audience: str,
        *,
        cache_ttl: float = 300.0,
        unknown_kid_cooldown: float = 30.0,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        """Construct a verifier for tokens issued by *issuer* naming *audience* as the audience.

        *cache_ttl* is how long fetched keys are used before a refetch.
        *unknown_kid_cooldown* is the minimum number of seconds between
        refetches triggered by an unknown ``kid``, and between retries after
        a failed refetch.

        *http_client*, when given, is used for every JWKS fetch instead of
        a short-lived client created per fetch -- primarily a test seam
        (inject an ``httpx2.AsyncClient`` backed by ``httpx2.MockTransport``)
        but also usable by callers who want connection pooling across
        verifiers. The verifier never closes an injected client; it owns
        the lifecycle of one it creates itself, closing it after each
        fetch.
        """
        self._jwks_url = jwks_url
        self._issuer = issuer
        self._audience = audience
        self._cache_ttl = cache_ttl
        self._http_client = http_client
        self._keys_by_kid: dict[str, dict[str, Any]] = {}
        self._fetched_at: float | None = None
        self._unknown_kid_cooldown = unknown_kid_cooldown
        # Monotonic time before which a TTL refetch is not retried (set after a failed refetch).
        self._retry_after = 0.0
        # Monotonic time of the last early refetch for an unknown kid; None until the first.
        self._last_unknown_kid_refetch: float | None = None
        # Monotonic time of the last ensure_keys() fetch attempt; None until the first.
        self._last_ensure_keys_attempt: float | None = None

    async def verify(self, token: str) -> BrokerClaims | None:
        """Verify *token* and return its claims, or ``None`` if it is not a currently-valid AF Broker Identity Token for this verifier's issuer/audience.

        Raises whatever ``httpx2`` raises (connection errors, timeouts, a
        non-2xx JWKS response) if a JWKS fetch is needed, fails, and no keys
        are held to fall back on -- see
        the class docstring on why that is deliberately not folded into a
        ``None`` return.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            logger.debug("Rejecting malformed token: cannot parse JWT header: %s", exc)
            return None
        kid = header.get("kid")
        if not isinstance(kid, str):
            logger.debug("Rejecting token: header 'kid' is missing or not a string")
            return None

        key_data = await self._get_key(kid)
        if key_data is None:
            logger.debug(
                "Rejecting token: kid %r not in JWKS after refresh (available kids: %s)",
                kid,
                sorted(self._keys_by_kid),
            )
            return None

        try:
            public_key = RSAAlgorithm.from_jwk(key_data)
            claims = jwt.decode(
                token,
                public_key,  # type: ignore[arg-type]  # JWKS only ever carries public keys
                algorithms=["RS256"],
                issuer=self._issuer,
                audience=self._audience,
                options={"verify_exp": True},
            )
        except jwt.InvalidTokenError as exc:
            # PyJWT's message already distinguishes expired / bad signature /
            # wrong issuer / audience mismatch -- pass it through verbatim.
            logger.debug("Rejecting token: signature/claims validation failed: %s", exc)
            return None

        return BrokerClaims(
            sub=claims["sub"],
            jti=claims["jti"],
            exp=claims["exp"],
            uid=claims.get("uid"),
            gid=claims.get("gid"),
            unixname=claims.get("unixname"),
        )

    def has_keys(self) -> bool:
        """Return whether the verifier currently holds any JWKS keys (for readiness checks); never fetches."""
        return bool(self._keys_by_kid)

    async def ensure_keys(self) -> bool:
        """Fetch the JWKS only if no keys are held, and return whether keys are held afterwards (for readiness checks).

        Never raises on a failed fetch. Attempts are spaced by
        *unknown_kid_cooldown*, so a probe calling this on every request
        does not turn an outage into a fetch per probe.
        """
        if self._keys_by_kid:
            return True
        now = time.monotonic()
        last = self._last_ensure_keys_attempt
        if last is not None and now - last < self._unknown_kid_cooldown:
            return False
        self._last_ensure_keys_attempt = now
        try:
            await self._refresh()
        except (httpx2.HTTPError, KeyError, ValueError):
            logger.warning("JWKS fetch from %s failed", self._jwks_url, exc_info=True)
        return bool(self._keys_by_kid)

    async def _get_key(self, kid: str) -> dict[str, Any] | None:
        """Return the JWK for *kid*, refetching when the cache is stale or a rate-limited early refetch for an unknown *kid* is due."""
        now = time.monotonic()
        cache_is_stale = (
            self._fetched_at is None or (now - self._fetched_at) > self._cache_ttl
        )
        if cache_is_stale:
            if now >= self._retry_after:
                await self._refresh()
        elif kid not in self._keys_by_kid and self._unknown_kid_refetch_due(now):
            self._last_unknown_kid_refetch = now
            await self._refresh()
        return self._keys_by_kid.get(kid)

    def _unknown_kid_refetch_due(self, now: float) -> bool:
        return (
            self._last_unknown_kid_refetch is None
            or now - self._last_unknown_kid_refetch >= self._unknown_kid_cooldown
        )

    async def _refresh(self) -> None:
        """Refetch the JWKS and replace the key cache with its contents; on failure keep serving held keys, or re-raise if there are none."""
        try:
            keys = await self._fetch_jwks()
        except (httpx2.HTTPError, KeyError, ValueError):
            if not self._keys_by_kid:
                raise
            logger.warning(
                "JWKS refetch from %s failed; serving cached keys",
                self._jwks_url,
                exc_info=True,
            )
            self._retry_after = time.monotonic() + self._unknown_kid_cooldown
            return
        self._keys_by_kid = {
            key_data["kid"]: key_data for key_data in keys if "kid" in key_data
        }
        self._fetched_at = time.monotonic()
        self._retry_after = 0.0

    async def _fetch_jwks(self) -> list[dict[str, Any]]:
        if self._http_client is not None:
            response = await self._http_client.get(self._jwks_url)
            response.raise_for_status()
            return response.json()["keys"]  # type: ignore[no-any-return]

        async with httpx2.AsyncClient(timeout=10.0) as client:
            response = await client.get(self._jwks_url)
            response.raise_for_status()
            return response.json()["keys"]  # type: ignore[no-any-return]
