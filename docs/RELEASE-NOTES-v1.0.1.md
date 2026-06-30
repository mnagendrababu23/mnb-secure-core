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

