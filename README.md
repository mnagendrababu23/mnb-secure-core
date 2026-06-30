# mnb-secure-core v1.0.1

**Package / library name:** `mnb-secure-core`  
**Composer package:** `mnb/mnb-secure-core`  
**Version:** `1.0.1`  
**Author:** Nagendra babu Macharla  
**Type:** reusable no-framework PHP security library  
**License:** MIT

`mnb-secure-core` is a reusable PHP security core for custom applications that do not use a framework. It gives a project-ready security foundation for school ERP, CRM, billing, admin panels, APIs, file tools, reporting dashboards, and other PHP applications.

This README is the primary setup and reference document for the package. Supporting files such as `LICENSE`, `CHANGELOG.md`, and `SECURITY.md` are included for public GitHub/package use.

---

## 1. Security concepts covered

1. Trust Zones and Data Boundaries
2. Secure Request Receiving Strategy
3. Authentication Strategy
4. Authorization Strategy
5. Data Protection Strategy
6. Web Application Security Controls
7. API Security and Rate Limiting
8. File Upload, Download, and Document Security
9. Caching Strategy
10. Environment and Secret Management
11. Logging, Audit, and Monitoring
12. Backup, Recovery, and Incident Response
13. Vulnerability Blocking Matrix
14. Secure Database Connect, Retrieval, Update, Delete, Search, and Alter
15. Penetration Testing, Security Verification, and Remediation
16. Error Handling, Safe Error Responses, and Hidden Technical Logs
17. Memory Management and Resource Safety
18. Throughput and Performance Capacity Management
19. Hide Server IP and Origin Identity Protection

---

## 2. Requirements

- PHP 8.1 or higher
- `openssl` PHP extension
- `fileinfo` PHP extension
- `json` PHP extension
- `pdo` PHP extension
- `zip` PHP extension recommended for ZIP backups
- `redis` PHP extension optional for Redis-backed cache, rate limiting, and token storage
- ClamAV optional for production malware scanning
- Writable private storage directory outside public web access
- HTTPS in production
- Composer optional; the package also includes a simple standalone autoloader

Check PHP locally:

```bash
php -v
php -m | grep -E "openssl|fileinfo|zip"
```

---

## 3. Recommended folder placement

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
│   └── backups/
└── libraries/
    └── mnb-secure-core/
```

Copy this package into:

```text
my-php-app/libraries/mnb-secure-core
```

Then include the library autoloader in your application bootstrap:

```php
require __DIR__ . '/../libraries/mnb-secure-core/autoload.php';
```

Composer users can install the public package after it is tagged/published:

```bash
composer require mnb/mnb-secure-core:^1.0
```

If you are installing directly from GitHub before Packagist publication, use a VCS repository entry:

```json
{
  "repositories": [
    {
      "type": "vcs",
      "url": "https://github.com/<your-user>/mnb-secure-core"
    }
  ],
  "require": {
    "mnb/mnb-secure-core": "^1.0"
  }
}
```

For local development, the path repository approach still works:

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

## 4. Copy config and environment file

Copy:

```text
mnb-secure-core/config/security.php  -> my-php-app/config/security.php
mnb-secure-core/.env.example         -> my-php-app/.env
```

Example `.env`:

```env
APP_ENV=local
APP_DEBUG=true
APP_URL=http://localhost
APP_KEY=CHANGE_ME_WITH_bin_mnb-secure_key_generate
FORCE_HTTPS=false
TRUSTED_HOSTS=localhost,127.0.0.1
TRUSTED_PROXIES=

# Origin/server identity protection
# PHP can help block direct IP Host requests and remove app-level fingerprint headers.
# For real origin IP hiding, put the site behind a CDN/reverse proxy and firewall the origin.
ORIGIN_PROTECTION_ENABLED=true
BLOCK_DIRECT_IP_HOST=true
CDN_OR_PROXY_ENABLED=false
REQUIRE_CDN_OR_PROXY_IN_PRODUCTION=true

SESSION_SECURE=false
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=Lax

STORAGE_PRIVATE_PATH=../storage/private
STORAGE_QUARANTINE_PATH=../storage/quarantine
CACHE_PATH=../storage/cache
LOG_PATH=../storage/logs
AUDIT_PATH=../storage/audit
BACKUP_PATH=../storage/backups
```

Generate a secure app key:

```bash
php libraries/mnb-secure-core/bin/mnb-secure key:generate
```

Create protected storage folders:

```bash
mkdir -p storage/private storage/quarantine storage/cache storage/logs storage/audit storage/backups
```

Keep `storage/private`, `storage/audit`, and `storage/backups` outside `public/`.

---

## 5. Basic bootstrap pattern

```php
<?php
require __DIR__ . '/../libraries/mnb-secure-core/autoload.php';

use Mnb\SecurityCore\Env\EnvLoader;
use Mnb\SecurityCore\Core\SecurityKernel;

EnvLoader::load(__DIR__ . '/../.env');
$config = require __DIR__ . '/../config/security.php';
$security = new SecurityKernel($config);
```

---

## 6. Web request protection pattern

```php
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Middleware\TrustedHostMiddleware;
use Mnb\SecurityCore\Http\Middleware\HttpsMiddleware;
use Mnb\SecurityCore\Http\Middleware\RequestSizeMiddleware;
use Mnb\SecurityCore\Http\Middleware\SecurityHeadersMiddleware;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

$request = Request::fromGlobals($config['app']['trusted_proxies'] ?? []);

$pipeline = new MiddlewarePipeline([
    new TrustedHostMiddleware($config['app']['trusted_hosts'] ?? []),
    new HttpsMiddleware((bool)($config['app']['force_https'] ?? false)),
    new RequestSizeMiddleware((int)($config['limits']['request_max_bytes'] ?? 2097152)),
    new SecurityHeadersMiddleware($config['security_headers'] ?? []),
]);

$response = $pipeline->handle($request, function (Request $request): Response {
    return Response::text('Secure page');
});

$response->send();
```

`X-Forwarded-Proto` is trusted only when the request comes from `TRUSTED_PROXIES`. This prevents direct clients from spoofing HTTPS through a forged proxy header.

---

## 7. API token and rate-limit pattern

```php
use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Http\Request;

$security = new SecurityKernel($config);
$tokens = new OpaqueTokenService($security->tokenStore());

$issued = $tokens->issue('user-1001', ['api:read'], ttlSeconds: 3600);

$request = Request::fromGlobals();
$plainToken = $request->bearerToken();
$record = $plainToken ? $tokens->validate($plainToken, $request->ip(), (string)$request->header('user-agent', '')) : null;

if (!$record || !in_array('api:read', $record['scopes'] ?? [], true)) {
    http_response_code(401);
    exit('Unauthorized');
}

$limiter = $security->rateLimiter();
$result = $limiter->attempt('api:' . $request->ip(), 120, 60);

if (!$result->allowed) {
    http_response_code(429);
    header('Retry-After: ' . $result->retryAfter);
    exit('Too many requests');
}
```

---

## 8. CSRF pattern

```php
use Mnb\SecurityCore\Auth\Csrf;

$csrf = new Csrf('_csrf_token');
$token = $csrf->token();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedToken = $_POST['_csrf'] ?? '';
    if (!$csrf->verify($postedToken)) {
        http_response_code(419);
        exit('Invalid CSRF token');
    }
}
```

Use CSRF protection for browser form submissions. Use bearer tokens or signed API credentials for API clients instead of CSRF tokens.

---

## 9. Authorization and ownership pattern

```php
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Authz\PermissionGuard;
use Mnb\SecurityCore\Authz\PolicyRegistry;

$context = new TenantContext(
    tenantId: 'school-1',
    userId: 'user-1001',
    roles: ['admin'],
    permissions: ['student.view', 'student.update']
);

$permissions = new PermissionGuard();
$permissions->require($context, 'student.update');
```

Recommended rules:

- Authorize before reading, creating, updating, deleting, exporting, or altering data.
- Always validate tenant, owner, school, branch, or organization boundaries.
- Deny by default when a permission or ownership rule is missing.
- Audit denied high-risk operations.

---

## 10. Data protection pattern

```php
use Mnb\SecurityCore\Data\Encryption;
use Mnb\SecurityCore\Data\DataMasker;

$crypto = new Encryption($_ENV['APP_KEY']);
$cipherText = $crypto->encrypt('Sensitive value');
$plainText = $crypto->decrypt($cipherText);

$maskedEmail = (new DataMasker())->email('student@example.com');
```

Protect secrets and sensitive data using encryption, masking, and field-level filtering. Never log raw passwords, tokens, session IDs, API keys, cookies, private file paths, or full database error traces.

---

## 11. Secure database pattern

The database security layer is built around these controls:

- PDO with safe connection options
- Identifier allow-lists for table and column names
- Parameterized values for user data
- Tenant and permission checks before CRUD
- Guarded search builder
- Guarded schema changes
- Audit logs for sensitive operations

Example:

```php
use Mnb\SecurityCore\Database\DatabaseConfig;
use Mnb\SecurityCore\Database\PdoConnectionFactory;
use Mnb\SecurityCore\Database\SecureDatabase;
use Mnb\SecurityCore\Database\TableSecurityPolicy;

$dbConfig = DatabaseConfig::fromArray([
    'driver' => 'mysql',
    'host' => '127.0.0.1',
    'database' => 'app_db',
    'username' => 'app_user',
    'password' => 'secret',
]);

$connection = (new PdoConnectionFactory())->create($dbConfig);

$policy = new TableSecurityPolicy(
    table: 'students',
    resourceType: 'student',
    selectableColumns: ['id', 'school_id', 'name', 'class_id', 'status'],
    insertableColumns: ['name', 'class_id', 'status'],
    updatableColumns: ['name', 'class_id', 'status'],
    searchableColumns: ['name'],
    orderableColumns: ['id', 'name']
);

// Pair SecureDatabase with a PolicyRegistry and AuditLogger as shown in examples/secure-database.php.
$rows = $connection->fetchAll('SELECT id, name FROM students WHERE school_id = ? LIMIT 50', [$context->schoolId]);
```

Database operation rules:

| Operation | Security rule |
| --- | --- |
| Connect | Use least-privilege DB user and safe PDO options |
| Retrieve | Enforce allowed columns, tenant scope, permission checks |
| Create | Validate fields and deny unknown columns |
| Update | Require object-level authorization and allowed fields |
| Delete | Prefer soft delete; hard delete requires separate permission |
| Search | Allow-list searchable columns and cap limits |
| Alter | Use schema guard with explicit permission and allow-list |


---

## 12. Redis and database-backed storage options

File-based cache, rate limits, and token storage are simple and good for one server. For high traffic or multiple web servers, use Redis or a database-backed store.

```php
use Mnb\SecurityCore\Core\SecurityKernel;

$security = new SecurityKernel($config);

$cache = $security->cache();        // file, redis, or database based on config/security.php
$limiter = $security->rateLimiter();
$tokenStore = $security->tokenStore();
```

Relevant config keys:

```php
$config['cache']['driver'];        // file, redis, database
$config['rate_limiter']['driver']; // file, redis, database
$config['token_store']['driver'];  // file, redis, database
$config['redis'];                  // host, port, password, database, timeout
```

Database-backed stores create their lightweight tables automatically when first used. Redis stores need the PHP `ext-redis` extension and a reachable Redis server.

## 13. File upload, download, and private document pattern

```php
use Mnb\SecurityCore\Files\FileUploadPolicy;
use Mnb\SecurityCore\Files\SecureFileManager;
use Mnb\SecurityCore\Files\LocalPrivateStorage;
use Mnb\SecurityCore\Files\CompositeMalwareScanner;
use Mnb\SecurityCore\Files\HeuristicMalwareScanner;
use Mnb\SecurityCore\Files\ClamAvMalwareScanner;

$policy = new FileUploadPolicy(
    allowedExtensions: ['pdf', 'png', 'jpg', 'jpeg'],
    allowedMimePrefixes: ['application/pdf', 'image/png', 'image/jpeg'],
    maxBytes: 5 * 1024 * 1024,
);

$scanner = new CompositeMalwareScanner([
    new HeuristicMalwareScanner(),
    new ClamAvMalwareScanner(failClosedWhenUnavailable: false),
]);

$manager = new SecureFileManager(
    new LocalPrivateStorage(__DIR__ . '/../storage/private'),
    $policy,
    __DIR__ . '/../storage/quarantine',
    $scanner
);

$result = $manager->storeFromPath(
    $_FILES['document']['tmp_name'],
    $_FILES['document']['name'],
    'documents'
);
```

File security checklist:

- Validate extension and MIME type.
- Rename uploaded files to safe random names.
- Store private files outside `public/`.
- Scan files before use where malware scanning is available.
- Never execute uploaded files.
- Download private files through an authorization controller.
- Add `Content-Disposition: attachment` for risky file types.

---

## 14. Security headers

Recommended production headers:

- `Content-Security-Policy`
- `X-Frame-Options` or CSP `frame-ancestors`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`
- `Permissions-Policy`
- `Strict-Transport-Security` when HTTPS is stable

Use `SecurityHeaders` or `SecurityHeadersMiddleware` to attach headers at the response boundary.

---

## 15. Hide server IP and origin identity protection

A PHP library cannot fully hide a public server IP by itself. If DNS points directly to the server, attackers may still find the origin. Real origin IP protection needs deployment controls:

- Put the site behind a CDN, reverse proxy, or load balancer.
- Proxy the DNS record where your DNS provider supports it.
- Firewall the origin server so only trusted CDN/proxy IP ranges can reach HTTP/HTTPS ports.
- Remove or minimize `Server`, `X-Powered-By`, framework, generator, and version headers.
- Block requests where the `Host` header is a direct IP address.
- Keep `APP_DEBUG=false` and use safe public error responses in production.

`mnb-secure-core` now includes `ServerIdentityHider` and `ServerIdentityProtectionMiddleware` to help with the application-level part: block direct IP Host requests and strip fingerprint headers from application responses.

```php
use Mnb\SecurityCore\Http\Middleware\ServerIdentityProtectionMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;

$pipeline = new MiddlewarePipeline([
    new ServerIdentityProtectionMiddleware($config['origin_protection'] ?? []),
    // other middleware...
]);
```

Recommended production config:

```php
'origin_protection' => [
    'enabled' => true,
    'block_direct_ip_host' => true,
    'cdn_or_proxy_enabled' => true,
    'require_cdn_or_proxy_in_production' => true,
    'strip_headers' => ['Server', 'X-Powered-By', 'X-Generator', 'X-Runtime', 'X-Version'],
],
```

Important server-level settings:

```apache
# Apache
ServerTokens Prod
ServerSignature Off
Header unset X-Powered-By
```

```nginx
# Nginx
server_tokens off;
proxy_hide_header X-Powered-By;
```

```ini
; php.ini
expose_php = Off
display_errors = Off
```

Use the production checker to warn when direct IP host access is allowed or origin protection is disabled.

---

## 16. Cache strategy

The cache layer is intended for safe, bounded, non-sensitive data.

Rules:

- Do not cache passwords, raw tokens, OTPs, private documents, or full PII records.
- Prefix cache keys by app/module/tenant where needed.
- Use TTLs for all temporary cache entries.
- Use cache for rate-limit counters, low-risk lookups, and computed summaries.
- Clear affected cache after updates or deletes.

---

## 17. Environment and secret management

Use `.env` only for local configuration and server-specific secrets. Never commit real secrets.

Recommended secret rules:

- Rotate application keys when exposure is suspected.
- Use different keys per environment.
- Keep production `.env` outside public web roots.
- Do not print environment values in error pages.
- Use `SecretScanner` before packaging or deployment.

---

## 18. Logging, audit, and monitoring

Use two different logging styles:

1. **Safe application logs** for operational debugging.
2. **Tamper-evident audit logs** for security-sensitive actions.

Audit these events:

- Login success/failure
- Password changes
- Permission denied events
- Sensitive record view/update/delete
- File upload/download
- Export actions
- API token creation/revocation
- Schema migration or guarded ALTER operations
- Backup creation/restoration

Never log raw passwords, tokens, cookies, API keys, encryption keys, or private document contents.

---

## 19. Error handling strategy

The error handling layer separates public messages from internal diagnostic details.

Public response rules:

- Show clean messages to users.
- Do not expose file paths, stack traces, SQL, route names, `.env` values, token values, or server internals.
- Use consistent status codes.
- Log technical details server-side only.

Example:

```php
use Mnb\SecurityCore\Errors\SafeErrorHandler;
use Mnb\SecurityCore\Errors\ErrorResponseFactory;
use Mnb\SecurityCore\Logging\FileLogger;

$logger = new FileLogger(__DIR__ . '/../storage/logs/app.log');
$factory = new ErrorResponseFactory(debug: false);
$handler = new SafeErrorHandler($factory, $logger);

$handler->register();
```

Recommended public statuses:

| Exception type | Public HTTP status |
| --- | --- |
| ValidationException | 422 |
| AuthorizationException | 403 |
| NotFoundException | 404 |
| BusinessRuleException | 409 |
| SecurityException | 400 or 403 |
| Unknown Throwable | 500 |

---

## 20. Backup, recovery, and incident response

Backup rules:

- Store backups outside `public/`.
- Encrypt backups when possible.
- Keep retention limits.
- Test restoration, not only backup creation.
- Audit backup create/download/delete actions.

Incident response basics:

1. Detect suspicious activity.
2. Preserve logs and evidence.
3. Contain exposed accounts, tokens, or files.
4. Patch the root cause.
5. Rotate secrets.
6. Restore clean data if needed.
7. Retest and document remediation.

---

## 21. Memory management and resource safety

Use memory guards for large files, exports, imports, conversions, and batch operations.

Rules:

- Cap upload size and request size.
- Process large rows/files in chunks.
- Avoid loading entire large files into memory when streaming is possible.
- Track memory before and after heavy operations.
- Reject unsafe workloads before processing.

Risk examples:

| Risk | Control |
| --- | --- |
| Large CSV import | Chunk processor and row limits |
| Large PDF/document conversion | Upload size cap and worker process |
| Large export | Streamed output and query pagination |
| Repeated API bursts | Rate limiter and throughput monitor |

---

## 22. Throughput and performance capacity management

Throughput controls help prevent accidental overload and abuse.

Use them to plan:

- Expected requests per second
- Average response time
- Concurrent users
- Worker capacity
- Queue pressure
- Upload and conversion limits
- API burst limits

Example CLI commands:

```bash
php bin/mnb-secure throughput:check
php bin/mnb-secure throughput:plan 80 150 25 500 900
```

---

## 23. Vulnerability blocking matrix

| Vulnerability | Main controls |
| --- | --- |
| SQL injection | Parameterized queries, identifier allow-lists, SecureQueryBuilder |
| XSS | Input validation, output escaping, CSP, safe response builders |
| CSRF | CSRF tokens on browser form requests |
| Broken access control / IDOR | PermissionGuard, TenantGuard, PolicyRegistry, ownership checks |
| API abuse | Bearer tokens, scopes, rate limiter, audit logs |
| File upload execution | MIME/extension validation, random names, private storage, no execute permissions |
| Path traversal | Storage abstraction and normalized safe paths |
| Secret leakage | Env separation, SecretScanner, safe error logger |
| Sensitive log leakage | Log redaction and public/internal error separation |
| Cache poisoning | Key namespacing, TTLs, no sensitive cache entries |
| Backup exposure | Private backup storage, audit logs, retention controls |
| Memory exhaustion | Request limits, upload limits, MemoryGuard, chunk processing |
| Throughput overload | Rate limits, throughput monitor, capacity planner |
| Unauthorized schema alter | Migration/schema guard with explicit allow-list and permission |
| Origin IP / server fingerprint exposure | ServerIdentityProtectionMiddleware, trusted hosts, CDN/proxy/firewall checklist |

---

## 24. Concept to file map

| Concept | Main files/classes |
| --- | --- |
| Trust Zones and Data Boundaries | `src/Trust/*`, `src/Data/DataClassifier.php` |
| Secure Request Receiving | `src/Http/Request.php`, `src/Http/Middleware/*` |
| Authentication | `src/Auth/*` |
| Authorization | `src/Authz/*`, `src/Authz/Policies/*` |
| Data Protection | `src/Data/*`, `src/Env/SecretScanner.php` |
| Web Security Controls | `src/Security/WebSecurityControls.php`, `src/Http/Middleware/SecurityHeadersMiddleware.php` |
| API Security and Rate Limiting | `src/Api/*`, `src/RateLimit/*` |
| Upload/Download Security | `src/Files/*` |
| Caching | `src/Cache/*`, `src/Contracts/CacheInterface.php` |
| Environment and Secrets | `src/Env/*`, `.env.example`, `config/security.php` |
| Logging and Audit | `src/Logging/*` |
| Backup and Recovery | `src/Recovery/*` |
| Vulnerability Matrix | `src/Security/VulnerabilityMatrix.php` |
| Secure Database | `src/Database/*` |
| Penetration Testing | `src/Pentest/*` |
| Safe Error Handling | `src/Errors/*`, `src/Exceptions/*` |
| Memory Management | `src/Memory/*` |
| Throughput Management | `src/Throughput/*` |
| Hide Server IP / Origin Identity | `src/Security/ServerIdentityHider.php`, `src/Http/Middleware/ServerIdentityProtectionMiddleware.php` |

---

## 25. Demos

Run all CLI demos:

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

Demo map:

| Concept | Demo file |
| --- | --- |
| Trust Zones and Data Boundaries | `demos/01-trust-zones-data-boundaries.php` |
| Secure Request Receiving | `demos/02-secure-request-receiving.php` |
| Authentication | `demos/03-authentication.php` |
| Authorization | `demos/04-authorization.php` |
| Data Protection | `demos/05-data-protection.php` |
| Web Security Controls | `demos/06-web-application-security-controls.php` |
| API Security and Rate Limiting | `demos/07-api-security-rate-limiting.php` |
| File Upload/Download Security | `demos/08-file-upload-download-document-security.php` |
| Caching Strategy | `demos/09-caching-strategy.php` |
| Environment and Secrets | `demos/10-environment-secret-management.php` |
| Logging and Audit | `demos/11-logging-audit-monitoring.php` |
| Backup and Incident Response | `demos/12-backup-recovery-incident-response.php` |
| Vulnerability Matrix | `demos/13-vulnerability-blocking-matrix.php` |
| Secure Database | `demos/14-secure-database-connect-retrieval-update-delete-search-alter.php` |
| Pentest and Verification | `demos/15-penetration-testing-security-verification.php` |
| Error Handling | `demos/16-error-handling-custom-errors-logs-hidden-frontend.php` |
| Memory Management | `demos/17-memory-management-resource-safety.php` |
| Throughput Management | `demos/18-throughput-performance-capacity-management.php` |
| Hide Server IP / Origin Identity | `demos/19-hide-server-ip-origin-protection.php` |

---

## 26. CLI commands

From package root:

```bash
php tests/run-tests.php
php demos/run-all-demos.php
php bin/mnb-secure key:generate
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure bootstrap:first-token demo-admin admin:*,profile.read,uploads.write 86400 --write-demo-user
php bin/mnb-secure matrix:export
php bin/mnb-secure throughput:check
php bin/mnb-secure throughput:plan 80 150 25 500 900
```

---

## 27. Testing checklist

Before using this library in production, verify:

- Authentication accepts valid users and rejects invalid credentials.
- Session cookies are secure, HTTP-only, and SameSite protected.
- CSRF-protected forms reject missing or invalid tokens.
- Authorization blocks missing permissions.
- Tenant/ownership boundaries block cross-tenant access.
- SQL injection payloads do not alter query structure.
- XSS payloads are escaped or rejected.
- API endpoints require valid tokens and scopes.
- Rate limits return 429 when thresholds are exceeded.
- Uploads reject unsafe extensions and MIME types.
- Private downloads require authorization.
- Cache does not store sensitive data.
- Logs redact secrets.
- Public errors do not show stack traces, paths, SQL, or `.env` values.
- Backups are private and restoration is tested.
- Memory and throughput guards block unsafe large workloads.
- Production security checks pass before deployment.

---

## 28. Penetration testing workflow

Only test systems you own or are authorized to test.

Recommended workflow:

1. Define target scope.
2. List modules, roles, and sensitive objects.
3. Run authentication, authorization, CSRF, XSS, SQLi, upload, API, and rate-limit tests.
4. Record findings with severity and reproduction steps.
5. Patch the issue.
6. Retest the exact payload/request.
7. Mark finding as remediated only after proof.

Suggested finding format:

```text
Title:
Severity:
Affected module:
Affected role/user:
Steps to reproduce:
Expected result:
Actual result:
Technical impact:
Business impact:
Recommended fix:
Retest result:
```

---

## 29. Public package safety note

This library provides reusable security building blocks. It does not automatically make an application secure unless the application integrates the controls correctly, configures production settings safely, and tests the final deployment.

For reverse-proxy deployments, configure `TRUSTED_PROXIES`; otherwise forwarded HTTPS headers are intentionally ignored.

For database-backed cache, rate limiter, and token stores, the bundled SQL uses MySQL/MariaDB upsert syntax. Use the file/Redis drivers or add driver-specific SQL before relying on those stores with SQLite/PostgreSQL.

---

## 30. Production checklist

Before deployment:

- `APP_ENV=production`
- `APP_DEBUG=false`
- HTTPS enabled
- HSTS enabled only after HTTPS is stable
- Trusted hosts configured
- Direct IP Host requests blocked
- CDN/reverse proxy enabled when you want to hide the origin server IP
- Origin firewall allows only trusted proxy/CDN IP ranges
- Real `APP_KEY` generated and protected
- Production `.env` not committed
- Private storage outside public root
- Logs outside public root
- Backups outside public root
- Upload execution disabled
- Database user has least privilege
- Error pages hide technical details
- Security headers enabled
- Rate limits enabled
- Audit logging enabled
- Backup and restore tested
- Penetration testing completed and remediated

---

## 31. Starter integration template

Use `templates/no-framework-app/` as a copy/paste reference for integrating the security core into a custom PHP app.

Typical flow:

1. Copy the template into a new app.
2. Point the template autoloader to `libraries/mnb-secure-core/autoload.php`.
3. Copy `config/security.php`.
4. Create `.env` from `.env.example`.
5. Create storage folders.
6. Run tests and demos.
7. Add application-specific policies and controllers.

---


## 32. Framework integration examples

Additional copy/paste examples are available in `examples/framework-integration/`:

```text
examples/framework-integration/
├── README.md
├── plain-php-api.php
├── slim-app.php
└── doctor-workflow.php
```

They show how to wire the v1.0.1 controls into application code:

- middleware pipeline order: request trust → security headers → rate policies → API token auth
- `AuthContext` and `Auth\PermissionGuard` usage after bearer-token validation
- named rate-limit policies for route/user/IP-aware throttling
- upload security profiles such as `images`, `documents`, `videos`, `archives`, and `strict`
- structured audit events for token, upload, admin, and sensitive actions
- `SecurityDoctor` usage for local and CI readiness checks

Plain PHP front controller example:

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->rateLimitMiddleware('api', 'api.profile'),
    new ApiTokenMiddleware($tokens),
]);
```

Slim remains optional. The Slim example is a bridge pattern, not a required dependency.

---


## 33. Developer experience quickstart

Production onboarding helpers are available for v1.0.1:

```text
.env.production.example
config/security.production.php
docs/INSTALL-CHECKLIST.md
examples/quickstart/README.md
examples/quickstart/bootstrap-first-token.php
```

Recommended first setup flow:

```bash
cp .env.production.example .env
php bin/mnb-secure key:generate
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure bootstrap:first-token demo-admin admin:*,profile.read,uploads.write 86400 --write-demo-user
```

The bootstrap command issues a real opaque API token through the configured token store and audit trail. The plain token is shown once; store it securely and rotate it after creating real application users.

Use `docs/INSTALL-CHECKLIST.md` before pushing to production.

---

## 34. Package structure

```text
mnb-secure-core/
├── autoload.php
├── bin/mnb-secure
├── composer.json
├── config/security.php
├── config/security.production.php
├── .env.production.example
├── docs/INSTALL-CHECKLIST.md
├── database/
├── demos/
├── examples/
├── src/
├── storage/
├── tests/run-tests.php
├── LICENSE
├── CHANGELOG.md
├── SECURITY.md
└── README.md
```


## 34. Auto audit, CORS, and suggestions add-on

This v1.0.1 add-on includes three extra developer-facing helpers.

### Auto audit logger

Enable request-outcome audit logging from config:

```php
'audit' => [
    'enabled' => true,
    'auto' => [
        'enabled' => true,
        'log_reads' => false,
        'excluded_paths' => ['health', 'metrics'],
    ],
],
```

Use it in the middleware pipeline after request trust and before application handlers:

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->corsMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->autoAuditMiddleware(),
]);
```

The middleware safely infers actions such as `auth.login`, `auth.register`, `auth.password_verification`, `submission.created`, `email.sent`, `record.add`, `record.edit`, `record.update`, and `record.delete` from method/path/route/status. It does not store raw request bodies or passwords. For explicit app events, use:

```php
$autoAudit = $kernel->autoAuditLogger();
$autoAudit->emailSent(['user_id' => 10], ['to_fingerprint' => SecurityAuditEvent::fingerprint('user@example.com')]);
$autoAudit->passwordVerificationFailed(['email_fingerprint' => SecurityAuditEvent::fingerprint('user@example.com')]);
```

### CORS / cross-origin middleware

Use the improved CORS middleware for API cross-origin fixes:

```php
$cors = $kernel->corsMiddleware();
```

Supported config includes explicit origins, wildcard subdomain patterns, credential-safe origin reflection, preflight method/header checks, exposed headers, `Access-Control-Max-Age`, and optional Private Network Access support. Avoid `allowed_origins => ['*']` when `allow_credentials` is enabled.

### Auto suggestions

Use suggestions to guide developers or app users based on typed words or pasted code:

```php
$suggestions = $kernel->suggestionEngine()->suggest('cors audit login upload doctor');
$codeHints = $kernel->suggestionEngine()->suggestFromCode($phpCode);
```

The engine suggests relevant v1.0.1 helpers such as auto audit, CORS policy, request trust, security headers, rate policies, auth context, upload profiles, and doctor checks.


## 35. Request input validation and sanitization

Use request validation before controller/business logic to normalize safe text, reject invalid submissions, and drop unexpected fields.

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->corsMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->inputValidationMiddleware([
        'register' => [
            'methods' => ['POST'],
            'path' => '/register',
            'body' => [
                'allowed_fields' => ['name', 'email', 'password'],
                'strict' => true,
                'sanitize_rules' => [
                    'name' => 'trim|strip_tags|collapse_spaces|max_length:120',
                    'email' => 'trim|email',
                ],
                'rules' => [
                    'name' => 'required|string|min:2|max:120',
                    'email' => 'required|email|max:190',
                    'password' => 'required|string|min:8|max:128',
                ],
            ],
        ],
    ]),
    $kernel->autoAuditMiddleware(),
]);
```

After validation, controllers can use sanitized input normally:

```php
$name = $request->input('name');
$email = $request->validated('email');
```

Available validator rules include `required`, `nullable`, `sometimes`, `email`, `integer`, `numeric`, `boolean`, `string`, `array`, `min`, `max`, `between`, `size`, `in`, `not_in`, `regex`, `alpha`, `alpha_num`, `slug`, `url`, `ip`, `uuid`, `date`, `json`, `confirmed`, `same`, `different`, `required_if`, and `required_without`.

Available sanitizer rules include `trim`, `strip_tags`, `strip_control_chars`, `collapse_spaces`, `lower`, `upper`, `email`, `url`, `int`, `float`, `bool`, `only_digits`, `slug`, `filename`, `null_if_empty`, and `max_length:N`.

This layer is for request normalization and validation. It does not replace output escaping, prepared SQL, CSP, CSRF, upload scanning, or business-rule authorization.

---

## Release readiness and public support

For public GitHub releases, use the included release readiness docs and templates:

- `docs/PRE-MERGE-CHECKLIST.md` — final checks before merging the v1.0.1 branch into `main`.
- `docs/RELEASE-NOTES-v1.0.1.md` — release notes for the public v1.0.1 hardening release.
- `docs/PUBLIC-USAGE-EXAMPLES.md` — copy-friendly examples for common integration flows.
- `.github/PULL_REQUEST_TEMPLATE.md` — PR review checklist for compatibility and security.
- `.github/ISSUE_TEMPLATE/` — bug, feature, and configuration question templates.

Security vulnerabilities should be reported privately using `SECURITY.md`, not through public GitHub issues.


## Trust Zone Boundary Engine

The v1.0.1 trust boundary engine connects request trust, authentication context, tenant context, data classification, permissions, and audit logging into named resource policies.

```php
$decision = $kernel->trustBoundaryRegistry()->decide(
    policyName: 'students.read',
    request: $request,
    resource: ['id' => 44, 'school_id' => 10],
    action: 'read',
    dataClass: 'sensitive',
    resourceName: 'students'
);

if ($decision->denied()) {
    return Response::json(['status' => false, 'message' => 'Access denied'], 403);
}
```

Middleware usage:

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->corsMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->inputValidationMiddleware(),
    $kernel->rateLimitMiddleware('api', 'students.read'),
    $kernel->trustBoundaryMiddleware('students.read'),
]);
```

Output filtering:

```php
$safe = $kernel->trustBoundaryRegistry()->filterForZone('students', $student, 'school_admin');
```

See `demos/19-trust-zone-boundary-engine.php` and `docs/PUBLIC-USAGE-EXAMPLES.md`.
