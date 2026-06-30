# MNB Secure Core

**Package:** `mnb/mnb-secure-core`  
**Version:** `v1.0.1`  
**Type:** reusable no-framework PHP security library  
**PHP:** 8.1+  
**License:** MIT  
**Author:** Nagendra babu Macharla

MNB Secure Core is a reusable PHP security foundation for custom applications that do not depend on a framework. It is designed for admin panels, APIs, school/ERP systems, CRM tools, billing platforms, file tools, reporting dashboards, and other PHP applications that need production-grade security building blocks without adopting Laravel/Symfony/Slim as a hard dependency.

The current `v1.0.1` release line includes request security, authentication, authorization, data protection, file safety, database governance, runtime command safety, outbound network/SSRF protection, security verification, safe errors, memory safety, throughput/capacity governance, origin protection, async queues, token/session control, XSS enforcement, and final production readiness tooling.

---

## Why use MNB Secure Core

MNB Secure Core helps PHP teams add serious application security without rebuilding the same controls again and again for every project. The library is especially useful for no-framework apps, shared-hosting projects, custom admin panels, API backends, ERP/CRM systems, education platforms, file tools, and internal business applications.

Key advantages:

| Advantage | Benefit |
| --- | --- |
| No-framework design | Works with plain PHP projects and can also be integrated into existing frameworks. |
| Central security kernel | Gives one consistent entry point for request, auth, database, files, logs, queues, sessions, and production checks. |
| Security-by-policy approach | High-risk actions such as SQL, schema changes, command execution, outbound HTTP, queues, and sessions are controlled by explicit policies. |
| Faster secure development | Reduces the need to manually build CSRF, rate limits, data masking, upload validation, audit logs, safe errors, token revocation, and production checks. |
| Safer production defaults | Encourages deny-by-default behavior, allow-lists, secret redaction, private storage, safe headers, and release-gate checks. |
| Tenant and role awareness | Helps protect multi-tenant systems by connecting trust zones, authorization, database policies, cache keys, files, sessions, and audit events. |
| Full lifecycle protection | Covers incoming requests, business operations, background jobs, outbound integrations, runtime execution, monitoring, verification, and release readiness. |
| Built-in diagnostics | Provides CLI checks, demos, vulnerability reports, readiness checks, coverage reports, and release build planning. |
| Safer logs and evidence | Keeps frontend responses clean while preserving redacted technical logs, audit records, pentest evidence, and incident response context. |
| Composer installation | Installs cleanly from Packagist with `composer require mnb/mnb-secure-core`. |

> For more detailed feature documentation and code examples, refer to the `docs/` directory. For runnable usage samples, refer to the `examples/` and `demos/` directories.

---

## Current release status

Latest local validation from the current `v1.0.1` upgrade line:

| Check | Result |
| --- | ---: |
| PHP lint | Passed |
| Test suite | 398 passed, 0 failed |
| Demo suite | Passed |
| Config validation | Passed |
| Vulnerability score | 99.05 |
| Vulnerability grade | A+ |

> Production `doctor`/readiness results still depend on your real `.env`, secrets, HTTPS, CDN/proxy, storage paths, database user, and deployment firewall settings.

---

## What this package protects

MNB Secure Core is organized as security engines. Each engine can be used independently, or through `Mnb\SecurityCore\Core\SecurityKernel`.

| Area | Main protection |
| --- | --- |
| Trust zones | Request, tenant, user, role, data-class, and resource boundary checks |
| Request receiving | Trusted hosts/proxies, HTTPS, request size, method/content checks, JSON parsing, suspicious request detection |
| Authentication | Bearer/API/session/webhook/internal authentication strategies |
| Authorization | Permissions, scopes, roles, ownership, tenant isolation, field-level filtering |
| Data protection | Encryption, masking, search hashes, redaction, export protection |
| Web security | Escaping, HTML sanitization, CSP/security headers, safe redirects, signed URLs, secure cookies |
| API/rate limiting | Token scopes, rate policies, abuse throttling |
| File security | Upload validation, private storage, malware scanner hooks, protected downloads, retention cleanup |
| Cache strategy | Tenant-aware keys, TTLs, encryption for sensitive cache policies, invalidation, stampede guard |
| Secrets | `.env` loading, secret inventory, redaction, scanning, rotation reports |
| Logging/audit/monitoring | JSONL logs, tamper-evident audit, metrics, alerts, retention |
| Backup/recovery/incident | Encrypted/signed backups, restore dry-runs, playbooks, evidence collection |
| Vulnerability matrix | OWASP/CWE-style vulnerability coverage mapping, gaps, recommendations |
| Database governance | Policy-based CRUD/search/alter, tenant scoping, query limits, schema plans, result masking |
| Runtime/network | Safe process runner, command allow-listing, outbound HTTP guard, SSRF/DNS/redirect protections |
| Verification/remediation | Pentest checklist, evidence bundles, SLA plans, retest gates, release gates |
| Safe errors | Safe public responses, hidden technical logs, problem+JSON, log redaction, error fingerprinting |
| Memory/resource safety | Operation memory profiles, stream guards, bounded buffers, temp file budgets, worker leak checks |
| Throughput/capacity | Latency budgets, concurrency limiting, adaptive throttling, queue pressure, SLO and capacity gates |
| Origin protection | Direct IP Host blocking, trusted proxy validation, fingerprint stripping, leak scanning, firewall guidance |
| Queue/background jobs | Async dispatch, 202 responses, idempotency, retries, dead-letter queue, worker supervision |
| Token/session control | Token revocation, refresh rotation, session registry, forced logout, remember-me safety |
| Final readiness/XSS | Safe template rendering, unsafe output scan, production checklist, release build planning |

---

## Requirements

Required:

- PHP 8.1 or higher
- `openssl`
- `fileinfo`
- `json`
- `pdo`
- Writable private storage outside the public web root

Recommended/optional:

- `zip` for ZIP backup/archive workflows
- `redis` for distributed cache, rate limiting, tokens, and queues
- ClamAV for production malware scanning
- HTTPS in production
- CDN/reverse proxy + firewall when origin IP hiding is required

Check your PHP environment:

```bash
php -v
php -m | grep -E "openssl|fileinfo|json|pdo|zip|redis"
```

---

## Installation

### Option A: direct library placement

Recommended for no-framework apps and shared hosting:

```text
my-php-app/
├── public/
│   └── index.php
├── app/
├── config/
│   └── security.php
├── storage/
│   ├── private/
│   ├── quarantine/
│   ├── cache/
│   ├── logs/
│   ├── audit/
│   ├── backups/
│   ├── queue/
│   └── tokens/
└── libraries/
    └── mnb-secure-core/
```

Bootstrap:

```php
<?php

require __DIR__ . '/../libraries/mnb-secure-core/autoload.php';

use Mnb\SecurityCore\Env\EnvLoader;
use Mnb\SecurityCore\Core\SecurityKernel;

EnvLoader::load(__DIR__ . '/../.env');
$config = require __DIR__ . '/../config/security.php';
$kernel = new SecurityKernel($config);
```

### Option B: Composer / Packagist

Install from Packagist:

```bash
composer require mnb/mnb-secure-core
```

Composer bootstrap:

```php
<?php

require __DIR__ . '/../vendor/autoload.php';

use Mnb\SecurityCore\Env\EnvLoader;
use Mnb\SecurityCore\Core\SecurityKernel;

EnvLoader::load(__DIR__ . '/../.env');
$config = require __DIR__ . '/../config/security.php';
$kernel = new SecurityKernel($config);
```

For local path development only:

```json
{
  "repositories": [
    {
      "type": "path",
      "url": "libraries/mnb-secure-core"
    }
  ],
  "require": {
    "mnb/mnb-secure-core": "^1.0"
  }
}
```

---

## First setup

Copy config and environment files. For Composer installs, the package lives under `vendor/mnb/mnb-secure-core`:

```bash
cp vendor/mnb/mnb-secure-core/config/security.php config/security.php
cp vendor/mnb/mnb-secure-core/.env.production.example .env
```

For direct library placement, use:

```bash
cp libraries/mnb-secure-core/config/security.php config/security.php
cp libraries/mnb-secure-core/.env.production.example .env
```

Create private storage:

```bash
mkdir -p storage/private storage/quarantine storage/cache storage/logs storage/audit storage/backups storage/queue storage/tokens
```

Generate keys and validate:

```bash
php vendor/mnb/mnb-secure-core/bin/mnb-secure key:generate
php vendor/mnb/mnb-secure-core/bin/mnb-secure config:validate
php vendor/mnb/mnb-secure-core/bin/mnb-secure doctor
```

For direct library placement, replace `vendor/mnb/mnb-secure-core` with `libraries/mnb-secure-core`.

Recommended production `.env` values:

```env
APP_ENV=production
APP_DEBUG=false
APP_URL=https://example.com
APP_KEY=replace_with_32_plus_char_secret
FORCE_HTTPS=true
TRUSTED_HOSTS=example.com,www.example.com
TRUSTED_PROXIES=

DATA_ENCRYPTION_KEY=replace_with_32_plus_char_secret
DATA_SEARCH_HASH_KEY=replace_with_32_plus_char_secret
SIGNED_URL_KEY=replace_with_32_plus_char_secret
REQUEST_WEBHOOK_SECRET=replace_with_32_plus_char_secret

SESSION_SECURE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=Lax

ORIGIN_PROTECTION_ENABLED=true
BLOCK_DIRECT_IP_HOST=true
CDN_OR_PROXY_ENABLED=true
REQUIRE_CDN_OR_PROXY_IN_PRODUCTION=true

STORAGE_PRIVATE_PATH=../storage/private
STORAGE_QUARANTINE_PATH=../storage/quarantine
CACHE_PATH=../storage/cache
LOG_PATH=../storage/logs
AUDIT_PATH=../storage/audit
BACKUP_PATH=../storage/backups
```

Never commit real `.env` secrets.

---

## Recommended middleware order

Use this general order for web/API entrypoints:

```php
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

$request = Request::fromGlobals($config['app']['trusted_proxies'] ?? []);

$pipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->serverIdentityProtectionMiddleware(),
    $kernel->trustedHostMiddleware(),
    $kernel->httpsMiddleware(),
    $kernel->corsMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->inputValidationMiddleware(),
    $kernel->rateLimitMiddleware('api', 'api.profile'),
    $kernel->authenticationMiddleware('api_bearer'),
    $kernel->authorizationMiddleware('students.read'),
    $kernel->autoAuditMiddleware(),
]);

$response = $pipeline->handle($request, function (Request $request): Response {
    return Response::json(['status' => true]);
});

$response->send();
```

For easier setup, use the Secure Request Receiving profiles:

```php
$response = $kernel->secureRequestReceiver('api_authenticated')->handle(
    $request,
    fn (Request $request) => Response::json([
        'status' => true,
        'request_id' => $request->attribute('request_id'),
    ])
);
```

Common profiles include:

```text
public_read
public_form
api_public
api_authenticated
admin
upload_image
webhook
internal_system
```

---

## Common usage patterns

### API token and rate limit

```php
use Mnb\SecurityCore\Auth\OpaqueTokenService;

$tokens = new OpaqueTokenService($kernel->tokenStore());
$issued = $tokens->issue('user-1001', ['api:read'], ttlSeconds: 3600);

$plainToken = $request->bearerToken();
$record = $plainToken
    ? $tokens->validate($plainToken, $request->ip(), (string)$request->header('user-agent', ''))
    : null;

if (!$record || !in_array('api:read', $record['scopes'] ?? [], true)) {
    return Response::json(['status' => false, 'message' => 'Unauthorized'], 401);
}

$result = $kernel->rateLimiter()->attempt('api:' . $request->ip(), 120, 60);

if (!$result->allowed) {
    return Response::json(['status' => false, 'message' => 'Too many requests'], 429, [
        'Retry-After' => (string)$result->retryAfter,
    ]);
}
```

### CSRF for browser forms

```php
use Mnb\SecurityCore\Auth\Csrf;

$csrf = new Csrf('_csrf_token');
$token = $csrf->token();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$csrf->verify($_POST['_csrf'] ?? '')) {
    return Response::text('Invalid CSRF token', 419);
}
```

### Authorization and tenant safety

```php
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Authz\PermissionGuard;

$context = new TenantContext(
    tenantId: 'school-1',
    userId: 'user-1001',
    roles: ['admin'],
    permissions: ['student.view', 'student.update']
);

(new PermissionGuard())->require($context, 'student.update');
```

### Data protection

```php
$protected = $kernel->dataProtectionRegistry()->protectForStorage('students', [
    'name' => 'Ravi',
    'email' => 'ravi@example.com',
    'parent_phone' => '9876543210',
]);

$safeResponse = $kernel->dataProtectionRegistry()->protectForResponse('students', $protected, $request);
$logSafe = $kernel->dataProtectionRegistry()->protectForLog('students', $protected);
```

### Secure database search

```php
use Mnb\SecurityCore\Database\TableSecurityPolicy;

$policy = new TableSecurityPolicy(
    table: 'students',
    resourceType: 'student',
    selectableColumns: ['id', 'school_id', 'name', 'class_id', 'status'],
    insertableColumns: ['name', 'class_id', 'status'],
    updatableColumns: ['name', 'class_id', 'status'],
    searchableColumns: ['name'],
    orderableColumns: ['id', 'name', 'created_at']
);

$rows = $kernel->secureDatabase()->search($context, $policy, 'Ravi', [
    'status' => ['eq' => 'active'],
    'class_id' => ['in' => [1, 2, 3]],
    'created_at' => ['between' => ['2026-01-01', '2026-06-30']],
], 'created_at', 'DESC', 50, 0);
```

### File upload and protected download

```php
$record = $kernel->secureFileManager(profile: 'documents')->storeFromPath(
    $_FILES['document']['tmp_name'],
    $_FILES['document']['name'],
    'student-documents',
    ['user_id' => 501],
    ['school_id' => 10, 'data_class' => 'sensitive']
);

$response = $kernel->protectedDownloadManager()->download(
    $request,
    $record,
    'student_document.download'
);
```

### Runtime command safety and outbound SSRF protection

```php
$result = $kernel->safeProcessRunner()->run('clamav_scan', [$uploadedFilePath]);
$response = $kernel->outboundHttpClient()->postJson($webhookUrl, ['event' => 'security.alert']);
```

### Safe errors

```php
$handler = $kernel->safeErrorHandler();
$handler->register();
```

Public responses stay clean while technical details go to hidden, redacted logs with request IDs.

### XSS-safe rendering

```php
$safeData = $kernel->safeViewData([
    'name' => $request->input('name'),
]);

echo $kernel->safeTemplateRenderer()->render('Hello {{ name }}', $safeData);
```

Use `TemplateSafeValue` only for content that was explicitly sanitized or generated by trusted code.

### Async queue dispatch

```php
$job = $kernel->jobDispatcher()->dispatch(
    name: 'file_scan',
    payload: ['file_id' => $fileId],
    queue: 'files',
    idempotencyKey: 'file_scan:' . $fileId
);

return $kernel->asyncResponseFactory()->accepted($job);
```

### Token revocation and session control

```php
$kernel->tokenRevocationService()->revoke('token-jti', 'logout');
$kernel->forcedLogoutService()->logoutUser('user-1001', 'password_changed');
```

---

## CLI reference

Run commands from the package root, or prefix with the library path from your app.

### Core

```bash
php bin/mnb-secure key:generate
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure matrix:export
```

### Vulnerability matrix

```bash
php bin/mnb-secure vulnerabilities:matrix
php bin/mnb-secure vulnerabilities:report
php bin/mnb-secure vulnerabilities:check sql_injection
php bin/mnb-secure vulnerabilities:check ssrf
php bin/mnb-secure vulnerabilities:check refresh_token_replay
php bin/mnb-secure vulnerabilities:owasp
php bin/mnb-secure vulnerabilities:export
```

### Database

```bash
php bin/mnb-secure db:health
php bin/mnb-secure db:check-connection
php bin/mnb-secure db:policy
php bin/mnb-secure db:query-limits
php bin/mnb-secure db:schema-plan add_column students admission_number 'VARCHAR(100)'
php bin/mnb-secure db:privileges
```

### Runtime and outbound network

```bash
php bin/mnb-secure runtime:list-commands
php bin/mnb-secure runtime:check-command clamav_scan /tmp/example.txt
php bin/mnb-secure outbound:policy
php bin/mnb-secure outbound:check-url https://example.com
```

### Verification and release gates

```bash
php bin/mnb-secure pentest:run-checklist production_release
php bin/mnb-secure pentest:verify PT-INJ-001
php bin/mnb-secure pentest:evidence
php bin/mnb-secure pentest:coverage production_release
php bin/mnb-secure pentest:remediation-plan
php bin/mnb-secure pentest:retest
php bin/mnb-secure security:release-gate production_release
```

### Errors

```bash
php bin/mnb-secure errors:policy
php bin/mnb-secure errors:catalog
php bin/mnb-secure errors:simulate internal
php bin/mnb-secure errors:simulate validation
php bin/mnb-secure errors:simulate security
php bin/mnb-secure errors:fingerprint
php bin/mnb-secure errors:check-production
```

### Memory/resources

```bash
php bin/mnb-secure memory:policy
php bin/mnb-secure memory:profile database_export
php bin/mnb-secure memory:simulate-allocation 10485760 request
php bin/mnb-secure memory:stream-plan 52428800 read
php bin/mnb-secure memory:payload-check
php bin/mnb-secure memory:worker-check
php bin/mnb-secure resources:check
php bin/mnb-secure resources:cleanup-plan
```

### Throughput/capacity

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

### Origin protection

```bash
php bin/mnb-secure origin:policy
php bin/mnb-secure origin:check
php bin/mnb-secure origin:exposure-report
php bin/mnb-secure origin:fingerprint
php bin/mnb-secure origin:firewall-plan
php bin/mnb-secure origin:proxy-profile cloudflare
php bin/mnb-secure origin:proxy-allowlist
php bin/mnb-secure origin:leak-scan
php bin/mnb-secure origin:production-gate
```

### Queue/background jobs

```bash
php bin/mnb-secure queue:policy
php bin/mnb-secure queue:dispatch test_job
php bin/mnb-secure queue:work default --once
php bin/mnb-secure queue:work files --max-jobs=10
php bin/mnb-secure queue:status job_abc123
php bin/mnb-secure queue:failed
php bin/mnb-secure queue:retry job_abc123
php bin/mnb-secure queue:dead-letter
php bin/mnb-secure queue:metrics
php bin/mnb-secure queue:pressure
php bin/mnb-secure queue:handlers
php bin/mnb-secure queue:release-gate
```

### Token/session

```bash
php bin/mnb-secure token:policy
php bin/mnb-secure token:revoke <jti>
php bin/mnb-secure token:introspect <jti>
php bin/mnb-secure token:cleanup
php bin/mnb-secure token:family <family_id>
php bin/mnb-secure token:revoke-family <family_id>

php bin/mnb-secure session:policy
php bin/mnb-secure session:list
php bin/mnb-secure session:revoke <session_id>
php bin/mnb-secure session:revoke-user <user_id>
php bin/mnb-secure session:cleanup
php bin/mnb-secure session:check <session_id>
php bin/mnb-secure session:devices <user_id>
```

### Final readiness and XSS

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

---

## Demos

Run all demos:

```bash
php demos/run-all-demos.php
```

Run the browser demo:

```bash
php -S 127.0.0.1:8090 -t demos/web/public
```

Open:

```text
http://127.0.0.1:8090
```

Important demo files:

| Demo | File |
| --- | --- |
| Vulnerability Matrix | `demos/13-vulnerability-blocking-matrix.php` |
| Secure Database | `demos/14-secure-database-connect-retrieval-update-delete-search-alter.php` |
| Pentest / Verification | `demos/15-penetration-testing-security-verification.php` |
| Safe Errors | `demos/16-error-handling-custom-errors-logs-hidden-frontend.php` |
| Memory Safety | `demos/17-memory-management-resource-safety.php` |
| Throughput Capacity | `demos/18-throughput-performance-capacity-management.php` |
| Secure Request Strategy | `demos/20-secure-request-receiving-strategy.php` |
| Runtime / Outbound Network | `demos/31-runtime-execution-outbound-network-security-engine.php` |
| Database Governance | `demos/32-secure-database-governance-query-lifecycle-engine.php` |
| Verification / Remediation | `demos/33-security-verification-remediation-evidence-automation-engine.php` |
| Safe Error / Technical Logs | `demos/34-safe-error-response-technical-log-isolation-engine.php` |
| Memory Governance | `demos/35-memory-governance-resource-safety-engine.php` |
| Throughput Governance | `demos/36-throughput-governance-performance-capacity-engine.php` |
| Origin Protection | `demos/37-origin-identity-protection-exposure-hardening-engine.php` |
| Queue / Background Jobs | `demos/38-async-request-response-queue-background-job-engine.php` |
| Token / Session Control | `demos/39-token-revocation-session-control-engine.php` |
| Final Readiness / XSS / Release | `demos/40-final-production-readiness-xss-release-consolidation-patch.php` |

---

## v1.0.1 upgrade consolidation

This release line keeps all upgrades under `v1.0.1`.

| Upgrade | Engine |
| ---: | --- |
| 27 | Runtime Execution and Outbound Network Security Engine |
| 28 | Secure Database Governance and Query Lifecycle Engine |
| 29 | Security Verification, Remediation, and Evidence Automation Engine |
| 30 | Safe Error Response and Technical Log Isolation Engine |
| 31 | Memory Governance and Resource Safety Engine |
| 32 | Throughput Governance and Performance Capacity Engine |
| 33 | Origin Identity Protection and Exposure Hardening Engine |
| 34 | Async Request, Response Queue, and Background Job Orchestration Engine |
| 35 | Token Revocation and Session Control Engine |
| 36 | Final Production Readiness, XSS Enforcement, and Release Consolidation Patch |

Patch ZIPs from upgrades 29–36 are intended to be applied in order. For public distribution, create one clean merged release archive instead of shipping many patch ZIPs.

---

## Production checklist

Before deployment, confirm:

- `APP_ENV=production`
- `APP_DEBUG=false`
- HTTPS enabled
- HSTS enabled only after HTTPS is stable
- Trusted hosts configured
- Trusted proxies configured when behind a proxy/CDN
- Direct IP Host requests blocked
- CDN/reverse proxy enabled when origin hiding is required
- Firewall allows HTTP/HTTPS only from trusted proxy/CDN ranges
- Real app, encryption, search hash, signed URL, JWT/token, and webhook secrets configured
- Production `.env` is not committed
- Private storage outside public root
- Logs, audit files, backups, queue files, and token/session stores outside public root
- Upload execution disabled
- Database user has least privilege
- Public errors hide technical details
- Logs redact secrets, tokens, cookies, and private paths
- XSS output escaping is used in templates
- CSP/security headers configured
- Rate limits enabled
- Audit logging enabled
- Backup and restore tested
- Queue workers supervised
- Token/session revocation hooks connected to password/role/permission/account status changes
- Security verification/retest completed
- `php bin/mnb-secure final:gate` passes

---

## What PHP code cannot solve alone

Some controls require deployment configuration:

- Full origin IP hiding requires CDN/reverse proxy plus firewall rules.
- HSTS requires working HTTPS.
- Webhook spoofing prevention requires a real shared webhook secret.
- Session/token revocation after role/password changes requires the host app to call the revocation hooks.
- XSS protection requires all templates/views to escape output or use safe renderers.
- Queue durability at scale requires a production-grade queue backend such as Redis/SQS/RabbitMQ or a properly migrated database queue.

---

## Release archive hygiene

Do not ship development/runtime data in public releases.

Exclude:

```text
.git/
vendor/
.env
storage/cache/*
storage/logs/*
storage/audit/*
storage/backups/*
storage/private/*
storage/quarantine/*
storage/queue/*
storage/tokens/*
```

Keep placeholder `.gitkeep` files where needed.

A clean release can be created with Git:

```bash
git archive --format=zip --output=mnb-secure-core-v1.0.1.zip HEAD
```

Or use the release planning commands:

```bash
php bin/mnb-secure release:manifest
php bin/mnb-secure release:build-plan
php bin/mnb-secure production:release-plan
```

---

## Public package safety note

MNB Secure Core provides reusable security building blocks. It does not automatically make an application secure unless the application integrates the controls correctly, configures production settings safely, and tests the final deployment.

Use the included demos, CLI diagnostics, release gates, and vulnerability matrix as proof-oriented safety tools, not as a substitute for secure application design, code review, and authorized penetration testing.

---

## Security reporting

Report vulnerabilities privately using `SECURITY.md`. Do not disclose exploitable details in public GitHub issues.

