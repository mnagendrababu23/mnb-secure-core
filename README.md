# mnb-secure-core v1.0

**Package / library name:** `mnb-secure-core`  
**Composer package:** `mnb/mnb-secure-core`  
**Version:** `1.0`  
**Author:** Nagendra babu Macharla  
**Type:** reusable no-framework PHP security library

`mnb-secure-core` is a reusable PHP security core for custom applications that do not use a framework. It gives a project-ready security foundation for school ERP, CRM, billing, admin panels, APIs, file tools, reporting dashboards, and other PHP applications.

This single README is the complete setup and reference document for the package. The earlier multi-file documentation has been merged here so the ZIP stays clean and easy to read.

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

---

## 2. Requirements

- PHP 8.1 or higher
- `openssl` PHP extension
- `fileinfo` PHP extension
- `zip` PHP extension recommended for ZIP backups
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

Composer users can load it through Composer after placing it in their project as a path repository or private package:

```json
{
  "repositories": [
    {
      "type": "path",
      "url": "libraries/mnb-secure-core"
    }
  ],
  "require": {
    "mnb/mnb-secure-core": "1.0.0"
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

$request = Request::fromGlobals();

$pipeline = new MiddlewarePipeline([
    new TrustedHostMiddleware($config['trusted_hosts'] ?? []),
    new HttpsMiddleware((bool)($config['force_https'] ?? false)),
    new RequestSizeMiddleware((int)($config['max_request_bytes'] ?? 2097152)),
    new SecurityHeadersMiddleware($config['headers'] ?? []),
]);

$response = $pipeline->handle($request, function (Request $request): Response {
    return new Response('Secure page');
});

$response->send();
```

---

## 7. API token and rate-limit pattern

```php
use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Auth\Stores\FileTokenStore;
use Mnb\SecurityCore\RateLimit\FileRateLimiter;
use Mnb\SecurityCore\Http\Request;

$store = new FileTokenStore(__DIR__ . '/../storage/tokens');
$tokens = new OpaqueTokenService($store);

$issued = $tokens->issue('user-1001', ['api:read'], 3600);

$request = Request::fromGlobals();
$plainToken = $request->bearerToken();

if (!$plainToken || !$tokens->verify($plainToken, 'api:read')) {
    http_response_code(401);
    exit('Unauthorized');
}

$limiter = new FileRateLimiter(__DIR__ . '/../storage/cache/rate-limits');
$result = $limiter->hit('api:' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'), 60, 120);

if (!$result->allowed) {
    http_response_code(429);
    exit('Too many requests');
}
```

---

## 8. CSRF pattern

```php
use Mnb\SecurityCore\Auth\Csrf;

$csrf = new Csrf($_SESSION);
$token = $csrf->token();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedToken = $_POST['_csrf'] ?? '';
    $csrf->validate($postedToken);
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

$maskedEmail = DataMasker::email('student@example.com');
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

$dbConfig = new DatabaseConfig(
    driver: 'mysql',
    host: '127.0.0.1',
    database: 'app_db',
    username: 'app_user',
    password: 'secret',
);

$connection = PdoConnectionFactory::make($dbConfig);

$policy = new TableSecurityPolicy(
    table: 'students',
    allowedColumns: ['id', 'school_id', 'name', 'class', 'status'],
    tenantColumn: 'school_id',
    requiredPermissions: [
        'view' => 'student.view',
        'create' => 'student.create',
        'update' => 'student.update',
        'delete' => 'student.delete',
    ]
);

$secureDb = new SecureDatabase($connection);
$rows = $secureDb->search($context, $policy, ['status' => 'active'], limit: 50);
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

## 12. File upload, download, and private document pattern

```php
use Mnb\SecurityCore\Files\FileUploadPolicy;
use Mnb\SecurityCore\Files\SecureFileManager;
use Mnb\SecurityCore\Files\LocalPrivateStorage;
use Mnb\SecurityCore\Files\NullMalwareScanner;

$policy = new FileUploadPolicy(
    maxBytes: 5 * 1024 * 1024,
    allowedMimeTypes: ['application/pdf', 'image/png', 'image/jpeg'],
    allowedExtensions: ['pdf', 'png', 'jpg', 'jpeg']
);

$manager = new SecureFileManager(
    $policy,
    new LocalPrivateStorage(__DIR__ . '/../storage/private'),
    new NullMalwareScanner()
);

$result = $manager->store($_FILES['document']);
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

## 13. Security headers

Recommended production headers:

- `Content-Security-Policy`
- `X-Frame-Options` or CSP `frame-ancestors`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`
- `Permissions-Policy`
- `Strict-Transport-Security` when HTTPS is stable

Use `SecurityHeaders` or `SecurityHeadersMiddleware` to attach headers at the response boundary.

---

## 14. Cache strategy

The cache layer is intended for safe, bounded, non-sensitive data.

Rules:

- Do not cache passwords, raw tokens, OTPs, private documents, or full PII records.
- Prefix cache keys by app/module/tenant where needed.
- Use TTLs for all temporary cache entries.
- Use cache for rate-limit counters, low-risk lookups, and computed summaries.
- Clear affected cache after updates or deletes.

---

## 15. Environment and secret management

Use `.env` only for local configuration and server-specific secrets. Never commit real secrets.

Recommended secret rules:

- Rotate application keys when exposure is suspected.
- Use different keys per environment.
- Keep production `.env` outside public web roots.
- Do not print environment values in error pages.
- Use `SecretScanner` before packaging or deployment.

---

## 16. Logging, audit, and monitoring

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

## 17. Error handling strategy

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

## 18. Backup, recovery, and incident response

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

## 19. Memory management and resource safety

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

## 20. Throughput and performance capacity management

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

## 21. Vulnerability blocking matrix

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

---

## 22. Concept to file map

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

---

## 23. Demos

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

---

## 24. CLI commands

From package root:

```bash
php tests/run-tests.php
php demos/run-all-demos.php
php bin/mnb-secure key:generate
php bin/mnb-secure matrix:export
php bin/mnb-secure throughput:check
php bin/mnb-secure throughput:plan 80 150 25 500 900
```

---

## 25. Testing checklist

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

## 26. Penetration testing workflow

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

## 27. Production checklist

Before deployment:

- `APP_ENV=production`
- `APP_DEBUG=false`
- HTTPS enabled
- HSTS enabled only after HTTPS is stable
- Trusted hosts configured
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

## 28. Starter integration template

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

## 29. Package structure

```text
mnb-secure-core/
├── autoload.php
├── bin/mnb-secure
├── composer.json
├── config/security.php
├── demos/
├── examples/
├── src/
├── storage/
├── templates/no-framework-app/
├── tests/run-tests.php
└── README.md
```

---

## 30. Notes for version 1.0

- This ZIP is labeled and packaged as `mnb-secure-core` version `1.0`.
- Author metadata is set to `Nagendra babu Macharla`.
- Composer package metadata uses the valid Composer format `mnb/mnb-secure-core` while the library display name remains `mnb-secure-core`.
- Documentation has been consolidated into this single README to avoid many separate Markdown files.
