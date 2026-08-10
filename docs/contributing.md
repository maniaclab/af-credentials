---
icon: lucide/code
---

# Contributing

## Architecture

```
MCP backend --import--> af_credentials.verifier.BrokerTokenVerifier --HTTPS--> AF broker JWKS
                     \-> af_credentials.proxy.ProxyClient          --HTTPS--> AF broker (x509 redeem)
                     \-> af_credentials.mcp.mcp_token_verifier (optional, requires the `mcp` extra)
```

`af-credentials` is a thin client library with no dependency on `af_mcp_broker`,
FastAPI, or Kubernetes: `BrokerTokenVerifier` verifies AF Broker Identity Tokens
against a broker's published JWKS, `ProxyClient` redeems brokered x509/VOMS
proxies, and `af_credentials.mcp` optionally adapts the verifier to the `mcp`
SDK's `TokenVerifier` protocol.

## Development setup

```bash
git clone https://github.com/maniaclab/af-credentials
cd af-credentials
pixi install
pixi run pre-commit-install
```

## Build and test commands

```bash
pixi run test          # run tests
pixi run lint           # pre-commit + pylint
pixi run build          # build sdist + wheel
pixi run docs-serve     # build and serve docs locally
```

## Tests

- `tests/test_verifier.py` — `BrokerTokenVerifier`, including JWKS caching and
  key-rotation refetch behavior
- `tests/test_proxy.py` — `ProxyClient`, mocking the broker's redeem endpoint
  via `httpx2.MockTransport`
- `tests/test_mcp.py` — the optional `mcp` SDK adapter; requires the `mcp`
  package to be installed (it is, in every `pixi run -e pyXXX test` environment)
  or the module is skipped via `pytest.importorskip("mcp")`

`tests/conftest.py` mints RSA-signed test tokens shaped exactly like
`af_mcp_broker.credentials.broker_issued.BrokerTokenIssuer.mint()` produces, so
`BrokerTokenVerifier` is exercised against realistic tokens without any
dependency on the broker itself.
