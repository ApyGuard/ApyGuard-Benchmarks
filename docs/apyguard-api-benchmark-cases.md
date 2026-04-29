# ApyGuard API Benchmark Cases

This file documents the currently implemented ApyGuard benchmarks and shared auth contract.

## Shared Auth Contract

1. `POST /api/auth/login`
2. Extract `access_token` and `token_type`
3. Send `Authorization: Bearer <token>` on subsequent requests

Shared metadata used across the suite:

- `openapi_path`: `/openapi.json`
- `docs_path`: `/docs`
- `health_path`: `/ping`

## Benchmark Index

| ID | Name | Level | Category | Vulnerability | Primary Endpoint |
|---|---|---:|---|---|---|
| APY-001-26 | BOLA - Order Management API | 1 | broken_object_level_authorization | BOLA | GET /api/orders/{order_id} |
| APY-002-26 | BFLA - Support Admin API | 2 | broken_function_level_authorization | BFLA | POST /api/admin/export |
| APY-003-26 | Mass Assignment - Workspace API | 2 | mass_assignment | Mass Assignment | PATCH /api/me |
| APY-004-26 | JWT Forgery - Partner API | 3 | jwt_forgery | JWT alg=none acceptance | GET /api/partner/billing |
| APY-005-26 | SQL Injection - Reports API | 3 | sql_injection | SQL Injection | GET /api/reports/search |
| APY-006-26 | Broken Object Property Level Authorization | 2 | broken_object_property_level_authorization | Broken Object Property Level Authorization | GET /api/profile |
| APY-007-26 | Excessive Data Exposure | 2 | excessive_data_exposure | Excessive Data Exposure | GET /api/account/summary |
| APY-008-26 | Business Flow Abuse - Coupon API | 2 | sensitive_business_flow_abuse | Sensitive Business Flow Abuse | POST /api/coupons/redeem |
| APY-009-26 | SSRF - Integration Fetch API | 3 | ssrf | SSRF | POST /api/integrations/fetch |
| APY-010-26 | Security Misconfiguration - Debug API | 1 | security_misconfiguration | Security Misconfiguration | GET /api/debug/config |
| APY-011-26 | Improper Inventory Management - Legacy Admin API | 2 | improper_inventory_management | Improper Inventory Management | GET /api/v1/admin/reports |
| APY-012-26 | NoSQL Injection - Auth API | 3 | nosql_injection | NoSQL Injection | POST /api/auth/login |
| APY-013-26 | File Upload Abuse - Path Traversal Download | 2 | file_upload_abuse | File Upload Abuse / Path Traversal | GET /api/files/download |
| APY-014-26 | Chained Exploit - BOLA to Account Takeover | 3 | chained_attack | Chained Exploit | GET /api/orders/{order_id} |
| APY-015-26 | Multi-Tenant BOLA - Invoice API | 2 | multi_tenant_bola | Multi-Tenant BOLA | GET /api/tenants/{tenant_id}/invoices/{invoice_id} |
| APY-016-26 | Bulk Authorization Gap - Orders API | 2 | bulk_authorization_gap | Bulk Authorization Gap | POST /api/orders/bulk-export |
| APY-017-26 | Method-Level Authorization Mismatch - Profile API | 2 | method_level_authorization_mismatch | Method-Level Authorization Mismatch | PATCH /api/profiles/{user_id} |
| APY-018-26 | Token Scope Confusion - Billing API | 2 | token_scope_confusion | Token Scope Confusion | GET /api/billing/ledger |
| APY-019-26 | Policy Shadowing Route Conflict - Admin API | 2 | policy_shadowing_route_conflict | Policy Shadowing Route Conflict | POST /api/users/{user_id}/admin/export |
| APY-020-26 | Wildcard Role Matching - Audit API | 2 | wildcard_role_matching | Wildcard Role Matching | GET /api/audit/admin/logs |
| APY-021-26 | Delegation Token Scope Escalation - API Key Service | 3 | delegation_token_scope_escalation | Delegation Token Scope Escalation | POST /api/keys/delegate |
| APY-022-26 | Ownership Transfer Bypass - Projects API | 2 | ownership_transfer_bypass | Ownership Transfer Bypass | POST /api/projects/{project_id}/transfer |
| APY-023-26 | Soft-Deleted Object Recovery BOLA - Records API | 2 | soft_deleted_object_recovery_bola | Soft-Deleted Object Recovery BOLA | POST /api/records/{record_id}/restore |
| APY-024-26 | Tenant Filter Isolation Bypass - Billing API | 2 | broken_object_level_authorization | Tenant Isolation Bypass | GET /api/invoices |
| APY-025-26 | Async Job Authorization - Reporting API | 2 | broken_object_level_authorization | Async Job Authorization | GET /api/jobs/result |
| APY-026-26 | Upload Metadata Privilege Abuse - Files API | 2 | broken_object_property_level_authorization | Upload Metadata Privilege Abuse | POST /api/files/upload |
| APY-027-26 | Admin Route Guard Parity Gap - Discovery API | 1 | broken_function_level_authorization | Route Guard Parity Gap | GET /api/internal/admin/stats |
| APY-028-26 | NoSQL Operator Injection - Search API | 2 | injection | NoSQL Operator Injection | GET /api/search |
| APY-029-26 | Numeric Notation Limit Bypass - Analytics API | 2 | unrestricted_resource_consumption | Numeric Notation Limit Bypass | GET /api/analytics/export |
| APY-030-26 | Decimal-IP SSRF Bypass - Integrations API | 3 | ssrf | Decimal-IP SSRF Bypass | POST /api/integrations/fetch |
| APY-031-26 | Expression Injection - Rules API | 2 | injection | Expression Injection | POST /api/rules/preview |
| APY-032-26 | SQL Injection Column Selection - Ledger API | 3 | sql_injection | SQL Injection Column Selection | GET /api/ledger/export |
| APY-033-26 | Command Injection in Diagnostics - Tools API | 2 | injection | Command Injection | POST /api/tools/resolve |
| APY-034-26 | Server-Side Template Injection - Messaging API | 2 | injection | Server-Side Template Injection | POST /api/messages/preview |
| APY-035-26 | XXE Import - Catalog API | 3 | injection | XXE Import | POST /api/catalog/import |
| APY-036-26 | Duplicate Parameter Pollution - Projects API | 2 | broken_object_level_authorization | Duplicate Parameter Pollution | GET /api/projects/export |

## OWASP API Top 10 (Non-Authorization) Coverage

- API2 Broken Authentication: `APY-004-26`
- API4 Unrestricted Resource Consumption: `APY-029-26`
- API6 Unrestricted Access to Sensitive Business Flows: `APY-008-26`
- API7 SSRF: `APY-009-26`, `APY-030-26`
- API8 Security Misconfiguration: `APY-010-26`
- API9 Improper Inventory Management: `APY-011-26`
- API10 Unsafe Consumption of APIs: (none)

## Notes

- Keep benchmark metadata in each `benchmarks/APY-*/benchmark.yaml` as the source of truth.
- Regenerate this file if benchmark metadata changes.
