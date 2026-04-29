# Changelog

All notable changes to this project are documented in this file.

## v1.0.0 - 2026-03-31

- Initial open-source release preparation for ApyGuard Validation Benchmarks.
- Expanded benchmark suite through `APY-034-26`.
- Added non-authorization vulnerability scenarios including:
  - SQL injection column selection (`APY-032-26`)
  - Command injection (`APY-033-26`)
  - Server-side template injection (`APY-034-26`)
- Standardized canary string coverage across benchmark READMEs.
- Improved project policy docs (`SECURITY.md` , `CODE_OF_CONDUCT.md` , `SUPPORT.md`).
- Added an explicit top-level README warning that this suite is benchmark-only and must not be used in production.
- Added Apache 2.0 `LICENSE`.
