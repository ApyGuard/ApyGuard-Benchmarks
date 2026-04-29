# ApyGuard Validation Benchmarks

![Version](https://img.shields.io/badge/version-v1.0.0-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)

ApyGuard Validation Benchmarks is an API-focused benchmark suite for testing authenticated attack paths against intentionally vulnerable services.

> [!WARNING]
> This repository contains intentionally vulnerable systems and must only be used in controlled environments.
> Do not use, deploy, or adapt these benchmark services for production environments.

---

## Table of Contents

- [Goals](#goals)
- [Prerequisites](#prerequisites)
- [What This Is](#what-this-is)
- [Who This Is For](#who-this-is-for)
- [Quick Start](#quick-start)
- [Benchmark Catalog](#benchmark-catalog)
- [OWASP API Top 10 Coverage](#owasp-api-top-10-coverage)
- [Project Structure](#project-structure)
- [Auth-First Design](#auth-first-design)
- [Using The Root Makefile](#using-the-root-makefile)
- [Authoring Rules](#authoring-rules)
- [Documentation](#documentation)
- [Safety](#safety)
- [License](#license)

---

## Goals

- Evaluate API security testing capability instead of browser-only behavior
- Cover common OWASP-style API and application risks
- Keep each benchmark focused on one primary exploit objective
- Make benchmarks easy to build, run, and extend locally

## Prerequisites

- Docker Engine with `docker compose` plugin
- GNU Make
- OpenSSL (used by benchmark build logic for deterministic flag generation)
- Python 3.10+ (for `tools/benchmark_ui.py`)

## What This Is

ApyGuard Validation Benchmarks is a structured dataset of intentionally vulnerable APIs designed to evaluate:

- API security scanners
- behavior-based anomaly detection systems
- automated vulnerability discovery tools

Unlike traditional web benchmarks, this suite focuses on authenticated API attack paths and real-world exploit chains.

## Who This Is For

- API security engineers
- red teamers and pentesters
- security tool vendors
- researchers evaluating detection systems

---

## Quick Start

```bash
# 1. List all available benchmarks
make list

# 2. Build a benchmark
make build BENCHMARK=APY-001-26

# 3. Start it
make run BENCHMARK=APY-001-26

# 4. Stop it when done
make stop BENCHMARK=APY-001-26
```

To run all benchmarks via a browser dashboard:

```bash
python tools/benchmark_ui.py
# then open http://127.0.0.1:8090
```

---

## Benchmark Catalog

36 benchmarks across authorization, injection, authentication, and other vulnerability classes.

### Authorization

| ID | Title | Vulnerability Class |
|----|-------|---------------------|
| `APY-001-26` | Order Management API | BOLA |
| `APY-002-26` | Support Admin API | BFLA |
| `APY-006-26` | Workspace API | Broken Object Property Level Authorization |
| `APY-014-26` | BOLA to Account Takeover | Chained Exploit |
| `APY-015-26` | Invoice API | Multi-Tenant BOLA |
| `APY-016-26` | Orders API | Bulk Authorization Gap |
| `APY-017-26` | Profile API | Method-Level Authorization Mismatch |
| `APY-018-26` | Billing API | Token Scope Confusion |
| `APY-019-26` | Admin API | Policy Shadowing Route Conflict |
| `APY-020-26` | Audit API | Wildcard Role Matching |
| `APY-021-26` | API Key Service | Delegation Token Scope Escalation |
| `APY-022-26` | Projects API | Ownership Transfer Bypass |
| `APY-023-26` | Records API | Soft-Deleted Object Recovery BOLA |
| `APY-024-26` | Billing API | Tenant Filter Isolation Bypass |
| `APY-025-26` | Reporting API | Async Job Authorization |
| `APY-026-26` | Files API | Upload Metadata Privilege Abuse |
| `APY-027-26` | Discovery API | Admin Route Guard Parity Gap |

### Injection

| ID | Title | Vulnerability Class |
|----|-------|---------------------|
| `APY-005-26` | Reports API | SQL Injection |
| `APY-012-26` | Auth API | NoSQL Injection |
| `APY-028-26` | Search API | NoSQL Operator Injection |
| `APY-031-26` | Rules API | Expression Injection |
| `APY-032-26` | Ledger API | SQL Injection — Column Selection |
| `APY-033-26` | Tools API | Command Injection in Diagnostics |
| `APY-034-26` | Messaging API | Server-Side Template Injection |
| `APY-035-26` | Catalog API | XXE Import |

### Authentication

| ID | Title | Vulnerability Class |
|----|-------|---------------------|
| `APY-004-26` | Partner API | JWT Forgery |

### Mass Assignment & Data Exposure

| ID | Title | Vulnerability Class |
|----|-------|---------------------|
| `APY-003-26` | Workspace API | Mass Assignment |
| `APY-007-26` | — | Excessive Data Exposure |

### Business Logic

| ID | Title | Vulnerability Class |
|----|-------|---------------------|
| `APY-008-26` | Coupon API | Business Flow Abuse |

### SSRF

| ID | Title | Vulnerability Class |
|----|-------|---------------------|
| `APY-009-26` | Integration Fetch API | SSRF |
| `APY-030-26` | Integrations API | Decimal-IP SSRF Bypass |

### Security Misconfiguration & Inventory

| ID | Title | Vulnerability Class |
|----|-------|---------------------|
| `APY-010-26` | Debug API | Security Misconfiguration |
| `APY-011-26` | Legacy Admin API | Improper Inventory Management |

### File Upload & Path Traversal

| ID | Title | Vulnerability Class |
|----|-------|---------------------|
| `APY-013-26` | — | File Upload Abuse — Path Traversal Download |

### Resource Consumption & Parameter Abuse

| ID | Title | Vulnerability Class |
|----|-------|---------------------|
| `APY-029-26` | Analytics API | Numeric Notation Limit Bypass |
| `APY-036-26` | Projects API | Duplicate Parameter Pollution |

---

## OWASP API Top 10 Coverage

Coverage mapped to the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).

| OWASP Category | Benchmarks |
|----------------|------------|
| **API1** — Broken Object Level Authorization | `APY-001`, `APY-014`, `APY-015`, `APY-016`, `APY-022`, `APY-023`, `APY-024`, `APY-025` |
| **API2** — Broken Authentication | `APY-004` |
| **API3** — Broken Object Property Level Authorization | `APY-006`, `APY-007`, `APY-003`, `APY-026` |
| **API4** — Unrestricted Resource Consumption | `APY-029` |
| **API5** — Broken Function Level Authorization | `APY-002`, `APY-017`, `APY-018`, `APY-019`, `APY-020`, `APY-021`, `APY-027` |
| **API6** — Unrestricted Access to Sensitive Business Flows | `APY-008` |
| **API7** — Server Side Request Forgery | `APY-009`, `APY-030` |
| **API8** — Security Misconfiguration | `APY-010`, `APY-036` |
| **API9** — Improper Inventory Management | `APY-011` |
| **API10** — Unsafe Consumption of APIs | — |

Additional coverage beyond the OWASP Top 10:

| Class | Benchmarks |
|-------|------------|
| SQL Injection | `APY-005`, `APY-032` |
| NoSQL Injection | `APY-012`, `APY-028` |
| Expression / Template / Command Injection | `APY-031`, `APY-033`, `APY-034` |
| XXE | `APY-035` |
| File Upload / Path Traversal | `APY-013` |
| Chained Exploits | `APY-014` |

---

## Project Structure

```
.
├── benchmarks/<BENCHMARK_ID>/   # One folder per benchmark
├── common.mk                    # Shared build and run logic
├── docs/                        # Design notes and conventions
├── tools/                       # benchmark_ui.py dashboard
└── assets/                      # Logo and static assets
```

Each benchmark folder contains:

```
benchmarks/APY-001-26/
├── benchmark.yaml
├── benchmark.json
├── docker-compose.yml
├── Makefile
└── app/                         # Service source code
```

---

## Auth-First Design

All benchmarks follow the same base authentication workflow:

1. `POST /api/auth/login` — exchange credentials for a token
2. Extract `access_token` from the response
3. Send `Authorization: Bearer <token>` on all subsequent requests

This makes the evaluation flow consistent across the entire suite and keeps scenarios realistic.

See [docs/auth-first-benchmark-pattern.md](docs/auth-first-benchmark-pattern.md) for full details.

---

## Using The Root Makefile

| Command | Description |
|---------|-------------|
| `make list` | List all available benchmarks |
| `make build BENCHMARK=<ID>` | Build a single benchmark |
| `make run BENCHMARK=<ID>` | Start a benchmark |
| `make stop BENCHMARK=<ID>` | Stop a running benchmark |
| `make build BENCHMARK=<ID> FLAG=FLAG{custom}` | Build with a custom flag |

**Browser dashboard** — start all benchmarks from a single UI:

```bash
python tools/benchmark_ui.py
```

Then open `http://127.0.0.1:8090` (or `http://<your-lan-ip>:8090`).

The dashboard supports per-benchmark start/stop, search, filtering, bulk actions, and URL copy. Place your logo at `assets/Logo.png` and it will appear automatically.

---

## Authoring Rules

- Keep each benchmark centered on one exploit objective
- Put the flag behind the vulnerability, not behind unrelated guessing
- Require authentication up front unless the benchmark is explicitly about auth bypass
- Keep the API surface small and intentional
- Use health checks so `docker compose up --wait` is stable

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/apyguard-api-benchmark-cases.md](docs/apyguard-api-benchmark-cases.md) | Full benchmark case descriptions |
| [docs/apyguard-api-benchmark-cases.yaml](docs/apyguard-api-benchmark-cases.yaml) | Machine-readable case definitions |
| [docs/auth-first-benchmark-pattern.md](docs/auth-first-benchmark-pattern.md) | Auth pattern design reference |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |
| [SUPPORT.md](SUPPORT.md) | How to get help |

---

## Safety

These benchmarks intentionally contain vulnerabilities.

- Do not deploy them in production
- Run them only in isolated lab or sandbox environments
- Treat any included secrets, credentials, and flags as test data only

---

## License

This project is licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).
