# mnb-secure-core v1.0.1 Release Notes

`v1.0.1` is a public package hardening release. It keeps the original library direction but improves public-use readiness, production diagnostics, integration examples, and developer onboarding.

## Release theme

Public package hardening without breaking existing users.

## Highlights

- Public license and release hygiene improvements.
- Auth context and permission guard for token/session-aware apps.
- Security config validator and CLI doctor diagnostics.
- Safer storage driver resolution for file, database, and Redis drivers.
- Named rate-limit policies for IP, user, route, path, method, and auth-aware keys.
- Request trust layer for real client IP, forwarded proto/host/port, trusted proxies, and CDN-aware origin protection.
- Upload security profiles for images, documents, videos, archives, and strict production mode.
- Structured audit logger for auth, token, upload, admin, database, sensitive, and system actions.
- Security headers builder with CSP nonce support, HSTS rules, and Permissions-Policy presets.
- Plain PHP and Slim integration examples.
- Production quickstart files, install checklist, and first-token bootstrap workflow.
- Release readiness templates for GitHub pull requests and issues.

## Backward compatibility

This release is intended to be additive:

- Existing namespaces are preserved.
- Existing demos are preserved.
- Existing `RateLimiterInterface::attempt()` behavior is preserved.
- Existing middleware patterns are preserved.
- New helpers are added without forcing an application rewrite.

## Recommended verification

Run from the repository root:

```bash
php tests/run-tests.php
php demos/run-all-demos.php
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
```

Composer users should also run:

```bash
composer validate --strict --no-check-publish
```

## Important production notes

- Set a real 32+ character `APP_KEY` before production use.
- Configure `TRUSTED_HOSTS` and, when behind a CDN/reverse proxy, configure `TRUSTED_PROXIES`.
- Keep storage, token, audit, backup, and quarantine paths outside public web roots.
- Enable HTTPS and HSTS only after TLS is stable.
- Prefer ClamAV/composite upload scanning with fail-closed behavior for production uploads.
- Do not log raw API tokens; use the structured audit helpers that store safe fingerprints.

## GitHub release checklist

Before creating the final tag:

- [ ] PR reviewed and merged into `main`.
- [ ] CI passed.
- [ ] Tests and demos passed locally.
- [ ] `doctor` blocking issues are zero for release config.
- [ ] Release ZIP excludes `.git` and duplicate nested project folders.
- [ ] `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, and docs are present.

Tag after merge:

```bash
git checkout main
git pull origin main
git tag v1.0.1
git push origin v1.0.1
```


## Auto audit, CORS, and suggestions add-on

Additional v1.0.1 additions include:

- `AutoAuditLogger` and `AutoAuditMiddleware` for safe automatic add/edit/delete/submission/email/auth/password-verification audit events.
- Improved `CorsMiddleware` and `CorsPolicy` with credential-safe origin reflection, preflight validation, exposed headers, origin patterns, max-age, and private-network opt-in.
- `AutoSuggestionEngine` for suggestions from typed words or pasted PHP code snippets.
- Kernel helpers: `autoAuditLogger()`, `autoAuditMiddleware()`, `corsMiddleware()`, and `suggestionEngine()`.

## Request input validation and sanitization add-on

Additional v1.0.1 additions include:

- Expanded `InputValidator` with common request rules for body/query validation.
- Added `InputSanitizer` for safe normalization, blocked-key removal, allow-listed fields, max depth, and max string length.
- Added `InputValidationMiddleware` for route/path/method-based validation before controllers run.
- Added request helpers for sanitized/validated data: `queryParams()`, `body()`, `validated()`, `withQuery()`, and `withBody()`.
- Added kernel helpers: `inputValidator()`, `inputSanitizer()`, and `inputValidationMiddleware()`.
- Added config/env and production/config validator checks for request validation policy safety.

### Trust Zone Boundary Engine

v1.0.1 now includes a production-ready trust boundary engine:

- `TrustBoundaryPolicy`
- `TrustBoundaryDecision`
- `TrustBoundaryContext`
- `TrustZoneResolver`
- `TrustBoundaryRegistry`
- `TrustBoundaryMiddleware`

This connects trust zones, data classes, resources, tenant context, permissions/scopes/roles, safe output filtering, and structured audit events.

## Improvement 16 — Secure Request Receiving Strategy Engine

This adds a unified request intake layer for applications that want one safe front door instead of manually ordering every middleware.

New public API:

```php
$kernel->secureRequestReceiver('api_authenticated');
$kernel->requestReceivingPipeline('api_authenticated');
$kernel->requestReceivingRegistry();
$kernel->requestReceivingProfile('api_authenticated');
$kernel->webhookSignatureMiddleware();
```

New controls:

- request correlation ID
- allowed HTTP methods
- request body size
- content-type enforcement
- JSON body parsing with invalid JSON rejection
- suspicious request detection
- HMAC/timestamp webhook signature verification
- named receiving profiles for public, API, admin, upload, webhook, and internal-system routes

Existing direct middleware usage remains supported.

### Authentication Strategy Engine

- Added named authentication strategies for bearer, optional bearer, session, webhook signature, admin, and internal-system routes.
- Added authentication middleware, registry, result object, password policy, user provider contract, and auth workflow service.
- Integrated `auth_strategy` into request receiving profiles.
- Added authentication config validation and production readiness warnings.

### Authorization Strategy Engine

v1.0.1 now includes a unified authorization strategy engine:

- named authorization policies
- unified allow/deny decision object
- RBAC role checks
- permission checks
- scope checks
- tenant/resource ownership checks
- optional trust-boundary integration
- field-level read/write filtering
- safe audit events for allowed/denied decisions
- middleware and kernel helpers

New public API:

```php
$decision = $kernel->authorizationRegistry()->decide(
    policyName: 'students.update',
    request: $request,
    resource: ['id' => 44, 'school_id' => 10],
    action: 'update',
    resourceName: 'students',
    dataClass: 'sensitive'
);

$middleware = $kernel->authorizationMiddleware('students.update');
```

Existing direct guards and trust-boundary APIs remain supported.

### Data Protection Strategy Engine

This release line now includes the Data Protection Strategy Engine. It unifies field classification, AES-256-GCM encrypted fields, keyed search hashes, response masking, log redaction, safe CSV exports, and encrypted private storage wrappers.

### Web Application Security Controls Engine

- Adds output escaping, HTML sanitization, safe redirects, secure cookie building, cache-control profiles, signed URLs, and named web security profiles.
- Adds config/production validation for `web_security` and a new demo showing browser/API web controls.

### Improvement 21 — File Upload, Download, and Document Security Engine

This improvement completes the file lifecycle by adding protected downloads, file security policies, scan-status gates, tenant-aware file access, safe download responses, checksums, signed download URLs, archive/document inspection hooks, and file retention cleanup.

### Caching Strategy Engine

Added policy-based secure caching with tenant/user-aware keys, safe serialization, sensitive-data encryption, tags/invalidation, stampede protection, config validation, production warnings, auto suggestions, and demo coverage.

### Improvement 23 — Environment and Secret Management Engine

Added provider-backed secret reads, secret definitions, redaction, inventory/health reports, purpose-based key derivation, environment validation, rotation reports, improved secret scanning, kernel helpers, and CLI commands for secret audit, inventory, rotation plans, and environment checks.

## Improvement 24 — Logging, Audit, and Monitoring Engine

This release adds centralized logging and monitoring helpers around existing audit functionality:

- JSONL log records and log handlers
- final log data protection/redaction
- audit integrity verifier and audit exporter
- metrics registry
- alert rules, alert manager, file/webhook alert channels
- trace context helper
- log retention manager
- monitoring summary reports
- CLI commands for audit verification, audit export, log purge, and monitoring summary

### Backup, Recovery, and Incident Response Engine

Added secure backup creation, manifests, HMAC signatures, restore dry-runs, recovery status reports, backup retention cleanup, incident cases, playbooks, containment actions, evidence collection, and CLI commands for backup/recovery/incident workflows.

### Improvement 26 — Vulnerability Blocking Matrix Engine

Adds a coverage matrix for SQL injection, XSS, CSRF, broken access control, IDOR, authentication failures, authorization failures, sensitive data exposure, secrets exposure, file upload/download risks, path traversal, open redirects, CORS misconfiguration, weak security headers, cache data leakage, audit/backup tampering, SSRF, command injection, CSV injection, webhook spoofing, and tenant boundary bypass.

This engine makes protection coverage visible through PHP helpers and CLI commands while preserving the legacy `matrix:export` command.

### Improvement 27 — Runtime Execution and Outbound Network Security Engine

Adds safe runtime and outbound integration controls for SSRF, command injection, unsafe webhooks, unsafe process execution, redirect-to-private-IP attacks, DNS/private-network abuse, timeout abuse, and oversized response/output handling.

New public API examples:

```php
$result = $kernel->safeProcessRunner()->run('clamav_scan', [$uploadedFilePath]);

$response = $kernel->outboundHttpClient()->postJson($webhookUrl, [
    'event' => 'security.alert',
]);
```

New CLI commands:

```bash
php bin/mnb-secure runtime:list-commands
php bin/mnb-secure runtime:check-command clamav_scan /path/to/file
php bin/mnb-secure outbound:policy
php bin/mnb-secure outbound:check-url https://example.com
```

The vulnerability matrix now maps SSRF and command injection to concrete controls including `OutboundHttpClient`, `OutboundRequestPolicy`, `DnsResolutionGuard`, `RedirectGuard`, `BlockedIpRangePolicy`, `SafeProcessRunner`, `CommandAllowList`, `SafeArgumentBuilder`, and `ProcessPolicy`.



## Add-on: Secure Database Governance and Query Lifecycle Engine

MNB Secure Core v1.0.1 adds the Secure Database Governance and Query Lifecycle Engine, strengthening secure database connection, retrieval, creation, update, deletion, search, transaction, and schema alteration workflows with policy-based access, tenant scoping, query complexity limits, field-level protection, safe schema plans, audit logging, and vulnerability matrix coverage for database security risks.

### Database governance highlights

- Policy registry for reusable table/resource access policies.
- Query complexity limits for pagination, search length, filter count, and leading wildcard control.
- Advanced safe filter operators for exact match, ranges, IN lists, comparisons, null checks, and escaped LIKE searches.
- Field-level result protection for hidden password/token columns, masked sensitive columns, and permission-required fields.
- Safe transaction workflow with begin/commit/rollback audit events.
- Schema change dry-run plans with destructive schema operations blocked by default.
- Database health and privilege inspection helpers for production readiness.

### New database CLI commands

```bash
php bin/mnb-secure db:health
php bin/mnb-secure db:check-connection
php bin/mnb-secure db:policy
php bin/mnb-secure db:query-limits
php bin/mnb-secure db:schema-plan add_column students admission_number 'VARCHAR(100)'
php bin/mnb-secure db:privileges
```

## Improvement 29 — Security Verification, Remediation, and Evidence Automation Engine

MNB Secure Core v1.0.1 adds a verification lifecycle layer for proving security readiness. It extends the existing pentest checklist/reporting toolkit with verification profiles, safe verification run records, redacted evidence bundles, remediation SLA planning, retest gates, release gates, and coverage analysis.

### New CLI commands

```bash
php bin/mnb-secure pentest:run-checklist production_release
php bin/mnb-secure pentest:verify PT-INJ-001
php bin/mnb-secure pentest:evidence
php bin/mnb-secure pentest:coverage production_release
php bin/mnb-secure pentest:remediation-plan
php bin/mnb-secure pentest:retest
php bin/mnb-secure security:release-gate production_release
```

### Release-gate behavior

The release gate can block release when Critical/High findings are open, required retest evidence is missing, or verification coverage is below the configured threshold. Evidence is redacted before storage so secrets, tokens, cookies, credentials, private paths, and sensitive headers are not copied into verification reports.

## Improvement 30 — Safe Error Response and Technical Log Isolation Engine

MNB Secure Core v1.0.1 adds the Safe Error Response and Technical Log Isolation Engine, strengthening exception governance with policy-driven safe responses, structured error catalogs, request correlation IDs, technical log isolation, secret and path redaction, stack trace sanitization, validation error normalization, problem+JSON support, error fingerprinting, escalation rules, and vulnerability matrix coverage for error disclosure and sensitive log exposure risks.

### Highlights

- Safe frontend JSON, HTML, text, and `application/problem+json` error responses.
- Hidden internal technical diagnostics with request IDs and error fingerprints.
- Secret, token, cookie, credential, path, and PII redaction for error logs.
- Stack trace sanitization with frame limits and root-path hiding.
- Validation error normalization to avoid internal field/column leakage.
- Error deduplication and escalation rules for security exceptions and repeated 500s.

### New CLI commands

```bash
php bin/mnb-secure errors:policy
php bin/mnb-secure errors:catalog
php bin/mnb-secure errors:simulate internal
php bin/mnb-secure errors:simulate validation
php bin/mnb-secure errors:simulate security
php bin/mnb-secure errors:fingerprint
php bin/mnb-secure errors:check-production
```

### Upgrade 31 — Memory Governance and Resource Safety Engine

Adds policy-driven memory/resource protection for large requests, upload scans, database/audit exports, and long-running workers.

New capabilities include operation memory profiles, allocation decisions, safe stream reader/writer guards, bounded buffers, payload size/depth guards, output buffer limits, resource scopes, temporary file budgets, temp cleanup planning, memory leak detection, worker restart recommendations, CLI diagnostics, and vulnerability matrix coverage for `memory_exhaustion`, `large_payload_dos`, `deep_json_dos`, `unbounded_buffering`, `unsafe_bulk_export`, `resource_leak`, `temporary_file_exhaustion`, `worker_memory_leak`, `unsafe_stream_read`, and `unsafe_stream_write`.

## Upgrade 32 — Throughput Governance and Performance Capacity Engine

MNB Secure Core v1.0.1 adds the Throughput Governance and Performance Capacity Engine, strengthening performance safety with operation-specific throughput profiles, latency budgets, concurrency limiting, adaptive throttling, queue pressure monitoring, SLO evaluation, degradation policy, safe load simulation, capacity risk reporting, performance release gates, audit events, CLI diagnostics, and vulnerability matrix coverage for performance denial-of-service and capacity exhaustion risks.

### Highlights

- Operation-specific profiles for API requests, login, file scans, database exports, webhooks, and backups.
- Latency budgets with warning, critical, queue, degrade, throttle, and reject decisions.
- Concurrency limiter with in-memory and file-backed stores.
- Queue pressure reporting with drain-time estimation and worker recommendations.
- Performance SLO evaluation for p95/p99 latency, error rate, queue drain, and sync execution rules.
- Degradation policy to protect login, CSRF, audit, security alerts, authorization, and rate limiting while deferring non-critical features.
- Capacity risk analyzer and safe load simulator for local capacity planning.
- Performance release gate to block failed SLO or critical capacity risk releases.

### New CLI commands

```bash
php bin/mnb-secure throughput:policy
php bin/mnb-secure throughput:profile api_request
php bin/mnb-secure throughput:budget api_request 1200 1
php bin/mnb-secure throughput:concurrency api_request
php bin/mnb-secure throughput:throttle api_request 1800 55
php bin/mnb-secure throughput:queue 1200 10 250
php bin/mnb-secure throughput:slo
php bin/mnb-secure throughput:capacity-risk
php bin/mnb-secure throughput:simulate api_request 100 750
php bin/mnb-secure performance:release-gate
```

### Upgrade 33 — Origin Identity Protection and Exposure Hardening Engine

MNB Secure Core v1.0.1 adds the Origin Identity Protection and Exposure Hardening Engine, strengthening server IP and origin identity protection with policy-driven trusted proxy validation, direct IP Host blocking, canonical host enforcement, response fingerprint reduction, origin leak detection, firewall rule guidance, production exposure scanning, origin log redaction, audit events, CLI diagnostics, and vulnerability matrix coverage for origin IP exposure, host header poisoning, forwarded header spoofing, and server fingerprint leakage risks.

### Upgrade 34 — Async Request, Response Queue, and Background Job Orchestration Engine

MNB Secure Core v1.0.1 adds the Async Request, Response Queue, and Background Job Orchestration Engine, introducing secure job dispatch, request-to-background deferral, response acknowledgement patterns, retry and dead-letter handling, idempotency protection, worker supervision, queue pressure controls, job audit trails, CLI worker diagnostics, and vulnerability matrix coverage for retry storms, duplicate execution, lost jobs, queue overload, and unsafe background processing risks.

Validation summary for this patch: PHP lint passed, tests passed, demos passed, config validation passed, queue CLI commands passed, and vulnerability report remained Grade A+.

### Upgrade 35 — Token Revocation and Session Control Engine

MNB Secure Core v1.0.1 adds the Token Revocation and Session Control Engine, introducing token lifecycle governance, refresh token rotation, revocation lists, session registry, device session tracking, forced logout, replay detection, idle and absolute session timeouts, remember-me token safety, token audit trails, CLI diagnostics, and vulnerability matrix coverage for stolen token reuse, session hijacking, session fixation, refresh token replay, and unrevoked session risks.

New CLI commands include `token:policy`, `token:revoke`, `token:introspect`, `token:cleanup`, `token:family`, `token:revoke-family`, `session:policy`, `session:list`, `session:revoke`, `session:revoke-user`, `session:cleanup`, `session:check`, and `session:devices`.

## Upgrade 36 — Final Production Readiness, XSS Enforcement, and Release Consolidation Patch

This patch adds final production readiness and release consolidation controls under the same v1.0.1 release line. It adds policy-driven output encoding helpers, safe template rendering, unsafe output scanning, production environment checklist generation, required secret/webhook readiness gates, final release-gate evaluation, clean archive planning, and consolidated upgrade manifest reporting.

New CLI commands:

```bash
php bin/mnb-secure xss:policy
php bin/mnb-secure xss:scan
php bin/mnb-secure xss:escape-sample
php bin/mnb-secure production:readiness
php bin/mnb-secure production:env-checklist
php bin/mnb-secure production:release-plan
php bin/mnb-secure release:manifest
php bin/mnb-secure release:build-plan
php bin/mnb-secure final:gate
```
