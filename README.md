# Auth0 JWT API Demo

Dependency-light Node.js proof that shows how Kobey Dev Services can protect an API route with Auth0-issued RS256 JWTs.

This repo does not connect to Kobey's Auth0 tenant and does not include tenant secrets. It is a clean implementation pattern with offline tests that generate their own RSA key pair.

## What It Shows

- Validates the JWT shape, `alg`, `kid`, issuer, audience, time claims, signature, and required scopes.
- Fetches and caches a JWKS document when a live `AUTH0_JWKS_URI` is configured.
- Supports dependency injection for tests, so the verification logic can run offline.
- Includes a tiny HTTP API with one public health route and one protected route.
- Uses only Node built-ins: `http`, `crypto`, and `node:test`.

## Quick Start

```bash
npm test
```

Optional local server:

```bash
cp .env.example .env
# fill AUTH0_ISSUER, AUTH0_AUDIENCE, AUTH0_JWKS_URI
npm start
```

Routes:

- `GET /health` returns a public status check.
- `GET /api/private` requires `Authorization: Bearer <jwt>` and the `read:messages` scope.

## Why This Is Useful

Small businesses and startups often have one internal API that needs simple auth hardening before a bigger app build. This project shows the core verification boundary without hiding it inside a framework or paid service.

## Guardrails

- No Auth0 client secret is needed for JWT verification.
- No tenant cookies, browser sessions, or dashboard tokens are used.
- No secrets are committed.
- Tests do not call Auth0.
- A live JWKS fetch is optional and controlled by environment variables.

## Public Proof Context

Built by Kobey Dev Services as an identity/API security proof.

- Portfolio: https://kobeydev.web.app
- GitHub org: https://github.com/git-agent-swarm
- Google Developer profile: https://me.developers.google.com/u/116492041557080639666

## License

MIT. See `LICENSE`.
