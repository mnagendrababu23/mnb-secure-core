# Changelog

All notable changes to `mnb-secure-core` are documented here.

## v1.0.1 — Secure Database Governance and Query Lifecycle Engine

MNB Secure Core v1.0.1 adds the Secure Database Governance and Query Lifecycle Engine, strengthening secure database connection, retrieval, creation, update, deletion, search, transaction, and schema alteration workflows with policy-based access, tenant scoping, query complexity limits, field-level protection, safe schema plans, audit logging, and vulnerability matrix coverage for database security risks.

### Added
- Added `DatabasePolicyRegistry`, `DatabaseOperationPolicy`, `QueryCostPolicy`, `QueryComplexityGuard`, `DatabaseSearchFilter`, and `DatabaseFilterOperator` for policy-driven database query lifecycle governance.
- Added advanced safe filters for `eq`, `neq`, `in`, `not_in`, `between`, comparison, null checks, and escaped LIKE-style searches.
- Added `DatabaseFieldProtection` and `DatabaseResultFilter` for hiding password/token columns, permission-gated fields, and masking sensitive result values.
- Added `RawQueryGuard`, `SafeTransaction`, `SchemaChangePolicy`, `SchemaChangePlan`, `SchemaMigrationGuard`, `DatabaseHealthChecker`, `DatabasePrivilegeInspector`, and `DatabaseAuditEvents`.
- Added CLI commands: `db:health`, `db:check-connection`, `db:policy`, `db:query-limits`, `db:schema-plan`, and `db:privileges`.
- Added demo `32-secure-database-governance-query-lifecycle-engine.php`.

### Changed
- Extended `SecureDatabase` with registry-backed policy lookup, result filtering, restore support, safe transactions, and schema dry-run plan helpers while preserving existing method signatures.
- Extended `SecureQueryBuilder` with advanced allow-listed filter operators and query complexity enforcement while preserving scalar equality filters.
- Extended `TableSecurityPolicy` with optional sensitive, hidden, masked, and permission-required columns.
- Extended `SecurityKernel`, config validation, and vulnerability matrix coverage for database governance risks including mass assignment, unbounded query DoS, dangerous schema alteration, unsafe hard delete, and database audit gaps.

## v1.0.1 - Public Package Hardening

### Added
- MIT license file for public GitHub/package use.
- GitHub Actions CI workflow for PHP 8.1, 8.2, 8.3, and 8.4.
- `.gitattributes` release hygiene rules to exclude `.git`, CI metadata, and generated storage content from exported archives.
- `SECURITY.md` with responsible disclosure guidance.
- `TRUSTED_PROXIES` configuration for safe reverse-proxy HTTPS detection.

### Changed
- Composer metadata now declares required PHP extensions and removes the inline Composer `version` field so Git tags can be the package source of truth.
- `Request::isSecure()` now trusts `X-Forwarded-Proto` only when the request comes from a configured trusted proxy.
- `ApiTokenMiddleware` now exposes validated token context through request attributes: `auth_token`, `auth_user_id`, and `auth_scopes`.
- Database cache, rate limiter, and token store constructors validate configured SQL table identifiers before interpolating table names into SQL.
- ClamAV scanner now enforces the configured timeout instead of allowing a long-running scanner process to hang indefinitely.
- Redis token store no longer shortens the per-user token index TTL when a shorter-lived token is stored.
- Production checker now warns when production ClamAV/composite upload scanning is configured to fail open.
- Demo 10 now includes origin-protection configuration so the complete demo suite remains green.

### Compatibility
- No namespaces, class names, or existing public methods were removed.
- `Request::fromGlobals()` accepts an optional trusted-proxies array while existing zero-argument usage remains valid.
- `Request` now includes optional `withAttribute()` / `attribute()` helpers for downstream auth context without breaking existing request handling.


### v1.0.1 Auto Audit, CORS, and Suggestions Add-on

- Added `AutoAuditLogger` and `AutoAuditMiddleware` for safe automatic audit events around add, edit, update, delete, submissions, email sent, login, register, and password-verification flows.
- Added richer CORS handling with credential-safe origin reflection, preflight method/header validation, origin patterns, exposed headers, max-age, private-network opt-in, and stronger config validation.
- Added `AutoSuggestionEngine` for developer/app suggestions based on typed words or pasted PHP code snippets.
- Added kernel helpers: `autoAuditLogger()`, `autoAuditMiddleware()`, `corsMiddleware()`, and `suggestionEngine()`.
- Added config/env options for automatic audit logging, CORS policy, and suggestions.

### v1.0.1 Release Readiness Pack

- Added GitHub pull request template with compatibility, security, and verification checklist.
- Added issue templates for bug reports, feature requests, and configuration questions.
- Added GitHub issue template config that redirects vulnerability reports to private security reporting.
- Added pre-merge checklist for the `v1.0.1-public-hardening` branch.
- Added v1.0.1 release notes and public usage examples.
- Extended CI to run `config:validate` and `doctor` diagnostics with a temporary safe CI `.env`.



### v1.0.1 Request Input Validation and Sanitization Add-on

- Expanded `InputValidator` with common request validation rules while preserving existing `validate(array $data, array $rules)` usage.
- Added `InputSanitizer` for safe text normalization, blocked-key removal, strict field allow-listing, and recursive depth/string-length limits.
- Added `InputValidationMiddleware` for route/path/method-based query/body validation before controllers run.
- Added request helpers: `queryParams()`, `body()`, `validated()`, `withQuery()`, and `withBody()`.
- Added kernel helpers: `inputValidator()`, `inputSanitizer()`, and `inputValidationMiddleware()`.
- Added config/env settings and production/config validation for request validation policies.

## v1.0.1 - Trust Zone Boundary Engine

- Added production-grade trust boundary policies, decisions, context, registry, zone resolver, and middleware.
- Preserved legacy `BoundaryGuard` behavior while allowing multiple boundaries per zone.
- Added tenant-aware resource boundary decisions with safe allow/deny reasons.
- Added output field filtering by resource classification and resolved trust zone.
- Added trust boundary audit events without logging raw sensitive payloads.
- Added config validation and production readiness checks for `trust_boundaries`.
- Added demo `19-trust-zone-boundary-engine.php`.

### v1.0.1 — Improvement 16: Secure Request Receiving Strategy Engine

Added a named request receiving engine that composes existing controls in a safe front-door order without removing older middleware usage.

- Added `RequestReceivingProfile`, `RequestReceivingRegistry`, and `SecureRequestReceiver`.
- Added `RequestIdMiddleware`, `RequestMethodMiddleware`, `ContentTypeMiddleware`, `JsonBodyParserMiddleware`, `SuspiciousRequestMiddleware`, and `WebhookSignatureMiddleware`.
- Added `WebhookSignatureVerifier` for HMAC/timestamp webhook receiving.
- Added `SecurityKernel::secureRequestReceiver()` and `SecurityKernel::requestReceivingPipeline()` helpers.
- Added request receiving config profiles for public, API, admin, upload, webhook, and internal-system routes.
- Added config and production-readiness validation for request receiving profiles.
- Added demo 20 and tests for named profiles, method/content-type checks, JSON parsing, suspicious request blocking, and webhook signatures.

## v1.0.1 - Authentication Strategy Engine

Added a central authentication strategy layer while preserving existing token/session/webhook primitives.

- Added named authentication strategies for bearer, optional bearer, session, webhook signature, admin, and internal-system routes.
- Added `AuthenticationMiddleware`, `AuthenticationRegistry`, `AuthenticationStrategy`, and `AuthenticationResult`.
- Added `AuthWorkflowService` and `UserProviderInterface` for safe framework-independent login/register flows.
- Added `PasswordPolicy` and `PasswordPolicyResult` for password policy checks.
- Added `AuthAuditEvents` constants for consistent authentication event names.
- Extended `OpaqueTokenService::issue()` to optionally store roles and permissions in token records.
- Extended `SessionGuard::login()` to persist roles, scopes, and tenant metadata for `AuthContext::fromSession()`.
- Integrated `auth_strategy` support into secure request receiving profiles.
- Added configuration and production-readiness validation for authentication strategies and password policy.

## v1.0.1 - Authorization Strategy Engine

Added a unified authorization layer while preserving existing `Auth\PermissionGuard`, `Authz\PermissionGuard`, tenant guards, trust boundaries, and database policies.

- Added `AuthorizationPolicy`, `AuthorizationDecision`, `AuthorizationContext`, `AuthorizationRegistry`, `FieldAuthorization`, `PolicyExplainer`, and `AuthorizationAuditEvents`.
- Added `AuthorizationMiddleware` for route/resource/action checks before controller logic.
- Added kernel helpers: `authorizationRegistry()`, `authorizationPolicy()`, and `authorizationMiddleware()`.
- Added deny-by-default authorization config with role, scope, permission, tenant, data-class, trust-boundary, and field-level rules.
- Added field-level read/write filtering for authorization policies.
- Added safe structured authorization audit events without logging raw sensitive resource payloads.
- Integrated `authorization` into secure request receiving profile options.
- Added config validation and production readiness warnings for authorization policies.
- Added demo `22-authorization-strategy-engine.php` and tests for decisions, middleware, audit, field filtering, validation, and suggestions.

### v1.0.1 — Data Protection Strategy Engine

Added a unified data protection layer for classification, encryption, masking, searchable hashes, safe exports, and encrypted private storage while preserving existing `Encryption`, `DataClassifier`, `DataMasker`, and `FieldFilter` APIs.

- Added `DataProtectionRegistry`, `DataProtectionPolicy`, `ProtectedField`, `FieldProtector`, `KeyRing`, `SearchHash`, `SafeCsvExporter`, and `EncryptedStorage`.
- Added field-level protection policies for storage, response, logs, and exports.
- Added AES-256-GCM payloads with key ids and AAD support for future key rotation.
- Added keyed search hashes for encrypted lookup fields.
- Added CSV injection protection for exports.
- Added data-protection config validation and production readiness checks.
- Added `SecurityKernel` helpers for data protection, safe CSV export, key ring, and encrypted private storage.
- Added demo `23-data-protection-strategy-engine.php`.

## v1.0.1 - Web Application Security Controls Engine

Added a unified web security controls layer for browser/API output safety while preserving existing request receiving, CORS, CSRF, and security header middleware.

- Added `OutputEscaper` for HTML, attribute, JavaScript, URL, and CSS output contexts.
- Added `HtmlSanitizer` for conservative dependency-free rich-text sanitization.
- Added `SafeRedirector` to block open redirects, dangerous schemes, protocol-relative URLs, and untrusted external hosts.
- Added `SecureCookieBuilder` for Secure, HttpOnly, SameSite, `__Host-`, and `__Secure-` cookie safety rules.
- Added `CacheControlPolicy` and `CacheControlMiddleware` with public, private, no-store, sensitive, and download profiles.
- Added `SignedUrl` for HMAC-signed, purpose-bound, expiring URLs.
- Added `WebSecurityProfile`, `WebSecurityRegistry`, and `WebSecurityControls` for named web security profiles.
- Added kernel helpers for escaping, sanitization, redirects, cookies, cache-control, signed URLs, and web security controls.
- Added config validation and production readiness checks for `web_security`.
- Added demo `24-web-application-security-controls-engine.php` and tests for output escaping, sanitization, redirects, cookies, cache headers, signed URLs, profiles, validation, and suggestions.

### v1.0.1 — Improvement 21: File Upload, Download, and Document Security Engine

Added a file lifecycle security layer around the existing upload profiles and private storage controls.

- Added `FileSecurityRegistry`, `FileSecurityPolicy`, `FileSecurityRecord`, and `FileSecurityDecision` for named download/delete/document policies.
- Added `ProtectedDownloadManager` and `SafeDownloadResponse` for scan-gated, tenant-aware downloads with safe attachment headers, no-sniff, no-store cache headers, checksums, ETags, and policy metadata.
- Added purpose-bound signed download URL helpers through the existing `SignedUrl` primitive.
- Added document/archive inspection hooks with `DocumentInspectorInterface`, `ArchiveInspector`, `DocumentInspectionResult`, `DocumentSanitizerInterface`, and `NullDocumentSanitizer`.
- Added `FileChecksum` and richer upload metadata: file id, checksum, scan status, scanner driver/message, owner/tenant fields, data class, and creation timestamp.
- Added `FileRetentionManager` for quarantine, rejected-file, and temporary-export cleanup.
- Added file security config validation, production-readiness warnings, auto-suggestions, kernel helpers, and demo `25-file-upload-download-document-security-engine.php`.

### v1.0.1 — Caching Strategy Engine

Added a security-aware caching strategy layer around the existing file, Redis, and database cache drivers.

- Added named cache policies with TTL, data class, scope, tags, encryption, stale settings, and audit options.
- Added tenant/user-aware `CacheKeyBuilder` to reduce cross-tenant cache leakage risk.
- Added `SecureCache` for policy-based `get`, `put`, `remember`, `forget`, and tag invalidation.
- Added `EncryptedCache`, `TaggedCache`, `CacheInvalidator`, `CacheStampedeGuard`, and `SafeCacheSerializer`.
- Added kernel helpers: `secureCache()`, `cacheRegistry()`, `cachePolicy()`, `cacheKeyBuilder()`, `encryptedCache()`, `taggedCache()`, `cacheInvalidator()`, and `cacheStampedeGuard()`.
- Added caching config validation, production readiness warnings, auto suggestions, tests, and demo 26.

### Improvement 23 — Environment and Secret Management Engine

- Added `SecretManager`, env/array secret providers, secret definitions, inventory and health reports.
- Added `SecretRedactor`, `KeyDeriver`, environment validation, rotation reports, and expanded `SecretScanner` reporting.
- Added kernel helpers and CLI commands: `secrets:inventory`, `secrets:audit`, `secrets:rotate-plan`, `secrets:env-check`, and improved `secrets:scan`.
- Added config validation and production readiness checks for secret provider, redaction, derivation, definitions, rotation, and scanning.

### v1.0.1 — Improvement 24: Logging, Audit, and Monitoring Engine

Added a centralized logging, audit integrity, metrics, alerting, and retention layer while preserving existing tamper-evident audit logging and auto audit behavior.

- Added JSONL/file log channels with final log redaction.
- Added `Logger`, `LogRecord`, log handlers, and `LogDataProtector`.
- Added audit chain verification and audit export helpers.
- Added file-based metrics registry, alert rules, alert manager, and alert channels.
- Added monitoring summary and trace context helpers.
- Added log retention/purge manager.
- Added CLI commands: `audit:verify`, `audit:export`, `logs:purge`, `monitor:summary`, `monitor:alerts`.
- Added config validation, production readiness checks, demo, tests, and public examples.

## v1.0.1 - Backup, Recovery, and Incident Response Engine

- Added secure backup policy, encrypted/signed backup creation, backup manifests, backup integrity verification, retention purge, restore dry-run, and recovery status reporting.
- Added incident cases, severity/status helpers, incident playbooks, containment action runner, evidence collector, incident reports, and incident response manager.
- Added CLI commands: `backup:create`, `backup:verify`, `backup:list`, `backup:purge`, `recovery:status`, `recovery:drill`, `restore:dry-run`, `incident:open`, `incident:run-playbook`, and `incident:report`.
- Added `SecurityKernel` helpers for secure backup, restore, recovery status, incident response, playbooks, containment, and evidence collection.
- Added config/env settings and validation for `recovery` and `incident_response`.
- Added demo `29-backup-recovery-incident-response-engine.php` and tests for encrypted/signed backups, restore dry-run, retention, incidents, playbooks, evidence, and kernel helpers.

## v1.0.1 - Improvement 26: Vulnerability Blocking Matrix Engine

Added a vulnerability coverage layer that maps common vulnerability classes to built-in security controls, OWASP Top 10 2021 entries, CWE IDs, status, scores, evidence, gaps, config dependencies, and recommendations.

Added:
- `src/Vulnerability/VulnerabilityDefinition.php`
- `src/Vulnerability/VulnerabilityStatus.php`
- `src/Vulnerability/VulnerabilityMatrix.php`
- `src/Vulnerability/VulnerabilityCoverageReport.php`
- `src/Vulnerability/VulnerabilityControlMapper.php`
- `src/Vulnerability/VulnerabilityEvidence.php`
- `src/Vulnerability/VulnerabilityScore.php`
- `src/Vulnerability/VulnerabilityAdvisor.php`
- `src/Vulnerability/OwaspMapper.php`
- `src/Vulnerability/CweMapper.php`
- `src/Vulnerability/VulnerabilityReportExporter.php`
- `demos/30-vulnerability-blocking-matrix-engine.php`

Added CLI commands:
- `php bin/mnb-secure vulnerabilities:matrix`
- `php bin/mnb-secure vulnerabilities:report`
- `php bin/mnb-secure vulnerabilities:check <id>`
- `php bin/mnb-secure vulnerabilities:owasp`
- `php bin/mnb-secure vulnerabilities:export`

The legacy `matrix:export` command and `Security\VulnerabilityMatrix` class remain compatible.

## v1.0.1 - Improvement 27: Runtime Execution and Outbound Network Security Engine

MNB Secure Core v1.0.1 adds the Runtime Execution and Outbound Network Security Engine, introducing safe process execution, command allow-listing, outbound HTTP protection, SSRF blocking, DNS and redirect guards, protected webhook dispatch, and vulnerability matrix coverage for runtime and integration security risks.

Added:
- `src/Runtime/ProcessPolicy.php`
- `src/Runtime/CommandDefinition.php`
- `src/Runtime/CommandAllowList.php`
- `src/Runtime/SafeArgumentBuilder.php`
- `src/Runtime/ProcessRequest.php`
- `src/Runtime/ProcessResult.php`
- `src/Runtime/SafeProcessRunner.php`
- `src/Runtime/RuntimeAuditEvents.php`
- `src/Network/OutboundRequestPolicy.php`
- `src/Network/OutboundRequest.php`
- `src/Network/OutboundResponse.php`
- `src/Network/AllowedHostPolicy.php`
- `src/Network/BlockedIpRangePolicy.php`
- `src/Network/DnsResolutionGuard.php`
- `src/Network/RedirectGuard.php`
- `src/Network/OutboundHttpClient.php`
- `src/Network/NetworkAuditEvents.php`
- `demos/31-runtime-execution-outbound-network-security-engine.php`

Changed:
- Added `runtime` and `network.outbound` configuration blocks.
- Added `SecurityKernel` helpers for process policy, safe process runner, outbound request policy, and outbound HTTP client.
- Updated `WebhookAlertChannel` to send webhook alerts through the guarded outbound client.
- Updated `ClamAvMalwareScanner` to support safe process execution through `SafeProcessRunner`.
- Updated the vulnerability matrix so SSRF, command injection, unsafe runtime execution, and unsafe webhook dispatch are covered by concrete runtime/network controls.

Added CLI commands:
- `php bin/mnb-secure runtime:list-commands`
- `php bin/mnb-secure runtime:check-command <command> [args...]`
- `php bin/mnb-secure outbound:policy`
- `php bin/mnb-secure outbound:check-url <url>`

Validation:
- Expanded the test suite to cover runtime command allow-listing, unsafe arguments, working directory/env blocking, timeouts, max output handling, outbound SSRF blocking, guarded webhooks, ClamAV runner delegation, kernel helpers, and vulnerability matrix status.

