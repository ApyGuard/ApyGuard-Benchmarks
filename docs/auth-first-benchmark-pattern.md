# Auth-First Benchmark Pattern

Use this pattern for all ApyGuard API benchmarks so the solver authenticates once and then performs the exploit with the same bearer token.

## Standard flow

1. `POST /api/auth/login`
2. Extract `access_token`
3. Send `Authorization: Bearer <token>` on all other API requests

## Recommended endpoint contract

- `POST /api/auth/login`
- `GET /api/me`
- vulnerability-specific routes under `/api/...`
- `GET /ping` for health checks

## Recommended login response

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer"
}
```

## Why this pattern

- Keeps the benchmarks realistic
- Avoids mixing unauthenticated and authenticated attack paths unless the benchmark is explicitly about auth bypass
- Makes evaluation easier because every benchmark begins the same way
- Lets you vary the vulnerability while keeping the harness stable

## Current benchmarks using this pattern

All current `APY-*` benchmarks in this repository follow the auth-first pattern unless a scenario is explicitly about authentication bypass behavior.
