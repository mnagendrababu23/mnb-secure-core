# Secure Request Receiving Strategy

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Document type:** Detailed feature documentation and code usage  
**Feature area:** Request intake, method/content-type control, request size limits, JSON parsing, request trust, suspicious request detection, webhook signatures, request IDs, rate limiting, authentication handoff, authorization handoff, audit trail

---

## 1. Overview

The **Secure Request Receiving Strategy** protects the first point where outside traffic enters your application.

It answers questions like:

```text
Is this HTTP method allowed?
Is the request body too large?
Is the Content-Type expected for this endpoint?
Is this request coming through a trusted proxy?
Should forwarded headers be trusted?
Is this a webhook and is the signature valid?
Is the request suspicious before it reaches application code?
Should this request require CSRF, bearer token auth, or signature auth?
Should rate limiting apply?
Should a request ID be attached for tracing and audit logs?
Which request receiving profile should be used for this route?
```

The goal is simple: **reject unsafe requests early, normalize safe requests, and pass only trusted request data into application code.**

This engine sits before most other application features. It is usually the first middleware group in the request lifecycle.

---

## 2. Why Request Receiving Matters

Many attacks reach an application before authentication or business logic runs.

Examples:

```text
Oversized JSON body
Unsupported HTTP methods
TRACE / CONNECT abuse
Content-Type confusion
Webhook spoofing
Forwarded-header spoofing
Host header poisoning
Too many query parameters
Path traversal attempts
Suspicious SQL/XSS/path payloads
Untrusted request body on GET
Missing request correlation ID
Invalid JSON body
```

A secure request receiving layer reduces risk by applying a predictable gate before route handlers execute.

Recommended flow:

```text
Raw HTTP request
    ↓
Request ID / correlation ID
    ↓
Trusted proxy and origin checks
    ↓
HTTPS / trusted host / CORS checks
    ↓
Method, size, and content-type checks
    ↓
JSON body parsing and request normalization
    ↓
Suspicious request detection
    ↓
Security headers
    ↓
Input validation
    ↓
Rate limit
    ↓
Authentication / CSRF / webhook signature
    ↓
Authorization / trust boundary
    ↓
Route handler
```

---

## 3. Main Classes

The request receiving strategy is mainly built around these classes:

```text
Mnb\SecurityCore\Http\Request
Mnb\SecurityCore\Http\Response
Mnb\SecurityCore\Http\MiddlewarePipeline
Mnb\SecurityCore\Http\SecureRequestReceiver
Mnb\SecurityCore\Http\RequestReceivingProfile
Mnb\SecurityCore\Http\RequestReceivingRegistry
Mnb\SecurityCore\Http\RequestTrust
Mnb\SecurityCore\Http\WebhookSignatureVerifier

Mnb\SecurityCore\Http\Middleware\RequestIdMiddleware
Mnb\SecurityCore\Http\Middleware\RequestTrustMiddleware
Mnb\SecurityCore\Http\Middleware\ServerIdentityProtectionMiddleware
Mnb\SecurityCore\Http\Middleware\HttpsMiddleware
Mnb\SecurityCore\Http\Middleware\TrustedHostMiddleware
Mnb\SecurityCore\Http\Middleware\CorsMiddleware
Mnb\SecurityCore\Http\Middleware\RequestMethodMiddleware
Mnb\SecurityCore\Http\Middleware\RequestSizeMiddleware
Mnb\SecurityCore\Http\Middleware\ContentTypeMiddleware
Mnb\SecurityCore\Http\Middleware\JsonBodyParserMiddleware
Mnb\SecurityCore\Http\Middleware\SuspiciousRequestMiddleware
Mnb\SecurityCore\Http\Middleware\SecurityHeadersMiddleware
Mnb\SecurityCore\Http\Middleware\InputValidationMiddleware
Mnb\SecurityCore\Http\Middleware\RateLimitMiddleware
Mnb\SecurityCore\Http\Middleware\AutoAuditMiddleware
Mnb\SecurityCore\Http\Middleware\CsrfMiddleware
Mnb\SecurityCore\Http\Middleware\ApiTokenMiddleware
Mnb\SecurityCore\Http\Middleware\WebhookSignatureMiddleware
Mnb\SecurityCore\Http\Middleware\AuthorizationMiddleware
Mnb\SecurityCore\Http\Middleware\TrustBoundaryMiddleware
```

The central access points are:

```php
$kernel->requestReceivingRegistry();
$kernel->requestReceivingProfile('api_authenticated');
$kernel->secureRequestReceiver('api_authenticated');
$kernel->requestReceivingPipeline('api_authenticated');
$kernel->webhookSignatureVerifier();
$kernel->webhookSignatureMiddleware();
```

---

## 4. Installation

Install from Packagist:

```bash
composer require mnb/mnb-secure-core
```

Basic bootstrap:

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Env\EnvLoader;

EnvLoader::load(__DIR__ . '/.env');

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

---

## 5. Core Request Object

`Request` is a small framework-neutral request wrapper.

Create a request from PHP globals:

```php
use Mnb\SecurityCore\Http\Request;

$request = Request::fromGlobals();
```

Create manually for tests or custom framework adapters:

```php
use Mnb\SecurityCore\Http\Request;

$request = new Request(
    method: 'POST',
    path: '/api/students',
    query: [],
    body: [],
    headers: [
        'Content-Type' => 'application/json',
        'Authorization' => 'Bearer token_value',
    ],
    server: [
        'CONTENT_LENGTH' => 128,
        'REMOTE_ADDR' => '203.0.113.10',
        'HTTP_HOST' => 'api.example.com',
        'HTTPS' => 'on',
    ]
);
```

Common request accessors:

```php
$request->method();              // GET, POST, PUT, PATCH, DELETE
$request->path();                // /api/students
$request->query('page', 1);      // query value
$request->input('name');         // body value
$request->body();                // parsed body array
$request->queryParams();         // query array
$request->all();                 // query + body
$request->header('content-type');
$request->bearerToken();
$request->contentLength();
$request->clientIp();
$request->host();
$request->effectiveHost();
$request->isSecure();
```

Attach request attributes:

```php
$request = $request->withAttribute('route_name', 'students.create');

$routeName = $request->attribute('route_name');
```

---

## 6. Core Response Object

`Response` is a small framework-neutral response wrapper.

Return JSON:

```php
use Mnb\SecurityCore\Http\Response;

return Response::json([
    'status' => true,
    'message' => 'Created successfully.',
], 201);
```

Return text:

```php
return Response::text('OK', 200);
```

Add headers:

```php
$response = Response::json(['status' => true])
    ->withHeader('X-App-Version', '1.0.1');
```

Send response in a plain PHP front controller:

```php
$response->send();
```

---

## 7. Request Receiving Profiles

A **request receiving profile** is a named policy for a route group.

Examples:

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

Each profile can define:

```text
allowed methods
max request bytes
allowed content types
rate limit policy
auth mode
CSRF requirement
request ID handling
request trust handling
origin protection
HTTPS enforcement
trusted host check
CORS
security headers
JSON body parsing
suspicious request detection
input validation
auto audit
authorization policy
trust boundary policy
upload profile
```

---

## 8. Recommended Configuration

Add or review the `request_receiving` block in `config/security.php`:

```php
'request_receiving' => [
    'enabled' => filter_var($_ENV['REQUEST_RECEIVING_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
    'reject_body_on_get' => true,
    'blocked_methods' => ['TRACE', 'CONNECT'],

    'json_depth' => (int)($_ENV['REQUEST_JSON_DEPTH'] ?? 64),
    'json_max_bytes' => (int)($_ENV['REQUEST_JSON_MAX_BYTES'] ?? 1048576),
    'json_require_object' => true,

    'request_id' => [
        'header' => $_ENV['REQUEST_ID_HEADER'] ?? 'X-Request-ID',
        'accept_incoming' => filter_var($_ENV['REQUEST_ID_ACCEPT_INCOMING'] ?? true, FILTER_VALIDATE_BOOL),
        'max_length' => (int)($_ENV['REQUEST_ID_MAX_LENGTH'] ?? 80),
    ],

    'suspicious' => [
        'mode' => $_ENV['SUSPICIOUS_REQUEST_MODE'] ?? 'block', // block or audit
        'max_path_length' => (int)($_ENV['REQUEST_MAX_PATH_LENGTH'] ?? 2048),
        'max_parameters' => (int)($_ENV['REQUEST_MAX_PARAMETERS'] ?? 200),
    ],

    'webhook' => [
        'signature_header' => $_ENV['WEBHOOK_SIGNATURE_HEADER'] ?? 'X-Signature',
        'timestamp_header' => $_ENV['WEBHOOK_TIMESTAMP_HEADER'] ?? 'X-Timestamp',
        'algorithm' => $_ENV['WEBHOOK_SIGNATURE_ALGORITHM'] ?? 'sha256',
        'secret' => $_ENV['WEBHOOK_SECRET'] ?? '',
        'tolerance_seconds' => (int)($_ENV['WEBHOOK_TIMESTAMP_TOLERANCE'] ?? 300),
    ],

    'defaults' => [
        'request_id' => true,
        'request_trust' => true,
        'origin_protection' => true,
        'https' => true,
        'trusted_host' => true,
        'cors' => true,
        'security_headers' => true,
        'json_body' => true,
        'suspicious_detection' => true,
        'input_validation' => true,
        'auto_audit' => true,
    ],

    'profiles' => [
        'public_read' => [
            'methods' => ['GET', 'HEAD'],
            'max_bytes' => 65536,
            'content_types' => [],
            'rate_policy' => 'api',
            'auth' => null,
            'csrf' => false,
            'input_validation' => false,
            'auto_audit' => false,
        ],

        'api_authenticated' => [
            'methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
            'max_bytes' => 1048576,
            'content_types' => ['application/json'],
            'rate_policy' => 'api',
            'auth' => 'bearer',
            'csrf' => false,
            'input_validation' => true,
            'authorization' => null,
            'trust_boundary' => null,
        ],

        'webhook' => [
            'methods' => ['POST'],
            'max_bytes' => 1048576,
            'content_types' => ['application/json'],
            'rate_policy' => 'api',
            'auth' => 'signature',
            'csrf' => false,
            'input_validation' => true,
            'auto_audit' => true,
        ],
    ],
],
```

---

## 9. Environment Variables

Recommended `.env` values:

```env
REQUEST_RECEIVING_ENABLED=true
REQUEST_JSON_DEPTH=64
REQUEST_JSON_MAX_BYTES=1048576
REQUEST_ID_HEADER=X-Request-ID
REQUEST_ID_ACCEPT_INCOMING=true
REQUEST_ID_MAX_LENGTH=80
REQUEST_MAX_PATH_LENGTH=2048
REQUEST_MAX_PARAMETERS=200
SUSPICIOUS_REQUEST_MODE=block

WEBHOOK_SIGNATURE_HEADER=X-Signature
WEBHOOK_TIMESTAMP_HEADER=X-Timestamp
WEBHOOK_SIGNATURE_ALGORITHM=sha256
WEBHOOK_SECRET=replace_with_32_plus_character_secret
WEBHOOK_TIMESTAMP_TOLERANCE=300
```

For production, `WEBHOOK_SECRET` must be a real random secret. Do not leave it empty.

---

## 10. Getting a Profile

```php
$registry = $kernel->requestReceivingRegistry();

$profile = $registry->get('api_authenticated');

echo $profile->name();        // api_authenticated
print_r($profile->methods()); // GET, POST, PUT, PATCH, DELETE
echo $profile->maxBytes();    // 1048576
```

Check if a profile exists:

```php
if (!$registry->has('webhook')) {
    throw new RuntimeException('Webhook request profile is missing.');
}
```

---

## 11. Handling a Request with SecureRequestReceiver

For a plain PHP application:

```php
<?php

use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

$request = Request::fromGlobals($config['app']['trusted_proxies'] ?? []);

$response = $kernel
    ->secureRequestReceiver('api_authenticated')
    ->handle($request, function (Request $request): Response {
        return Response::json([
            'status' => true,
            'message' => 'Request accepted.',
            'request_id' => $request->attribute('request_id'),
        ]);
    });

$response->send();
```

For an endpoint group, choose a profile that matches the route behavior:

```php
$receiver = match ($routeGroup) {
    'public' => $kernel->secureRequestReceiver('public_read'),
    'api' => $kernel->secureRequestReceiver('api_authenticated'),
    'admin' => $kernel->secureRequestReceiver('admin'),
    'webhook' => $kernel->secureRequestReceiver('webhook'),
    default => $kernel->secureRequestReceiver('api_public'),
};
```

---

## 12. Request Receiving Pipeline Only

If you already have your own router and want only the middleware pipeline:

```php
$pipeline = $kernel->requestReceivingPipeline('api_authenticated');

$response = $pipeline->handle($request, function ($request) {
    return Response::json(['status' => true]);
});
```

---

## 13. Middleware Order Used by Profiles

`SecurityKernel::secureRequestReceiver()` builds middleware in a safe order.

Typical profile order:

| Step | Middleware | Purpose |
| ---: | --- | --- |
| 1 | `RequestIdMiddleware` | Attach correlation ID early. |
| 2 | `RequestTrustMiddleware` | Validate trusted proxy / forwarded header behavior. |
| 3 | `ServerIdentityProtectionMiddleware` | Block direct origin/IP exposure when configured. |
| 4 | `HttpsMiddleware` | Enforce HTTPS when configured. |
| 5 | `TrustedHostMiddleware` | Block unknown or poisoned Host headers. |
| 6 | `CorsMiddleware` | Apply CORS policy. |
| 7 | `RequestMethodMiddleware` | Allow only expected methods. |
| 8 | `RequestSizeMiddleware` | Block oversized requests. |
| 9 | `ContentTypeMiddleware` | Enforce expected content types. |
| 10 | `JsonBodyParserMiddleware` | Parse bounded JSON safely. |
| 11 | `SuspiciousRequestMiddleware` | Detect path traversal, injection patterns, control chars. |
| 12 | `SecurityHeadersMiddleware` | Attach secure response headers. |
| 13 | `InputValidationMiddleware` | Sanitize and validate query/body payloads. |
| 14 | `RateLimitMiddleware` | Apply endpoint rate limits. |
| 15 | `AutoAuditMiddleware` | Record request audit events. |
| 16 | CSRF / API token / signature middleware | Authenticate or verify request source. |
| 17 | `AuthorizationMiddleware` | Enforce permission/resource access. |
| 18 | `TrustBoundaryMiddleware` | Enforce trust-zone/data-boundary policy. |

This order is intentional: cheap request checks happen before expensive application logic.

---

## 14. Request ID and Correlation ID

`RequestIdMiddleware` attaches a safe request ID.

```php
$requestId = $request->attribute('request_id');
$correlationId = $request->attribute('correlation_id');
```

The response includes the request ID header:

```http
X-Request-ID: 0d1a2b3c4d5e6f...
```

Use this ID when connecting frontend errors to backend logs:

```php
return Response::json([
    'status' => false,
    'message' => 'Request failed.',
    'request_id' => $request->attribute('request_id'),
], 400);
```

Production recommendation:

```text
Accept incoming request IDs only from trusted gateways or sanitize them strictly.
Never allow CR/LF characters in request ID headers.
```

The built-in middleware already rejects unsafe request ID values.

---

## 15. HTTP Method Protection

Block dangerous methods globally:

```php
'blocked_methods' => ['TRACE', 'CONNECT'],
```

Define allowed methods per profile:

```php
'api_public' => [
    'methods' => ['GET', 'POST'],
],
```

Manual middleware usage:

```php
$middleware = $kernel->requestMethodMiddleware(['GET', 'POST']);
```

Blocked response example:

```json
{
  "status": false,
  "message": "HTTP method is not allowed"
}
```

---

## 16. Request Size Protection

Profile-level request size:

```php
'upload_image' => [
    'methods' => ['POST'],
    'max_bytes' => 5242880,
    'content_types' => ['multipart/form-data'],
],
```

Manual middleware usage:

```php
use Mnb\SecurityCore\Http\Middleware\RequestSizeMiddleware;

$middleware = new RequestSizeMiddleware(1024 * 1024); // 1 MB
```

Oversized request response:

```json
{
  "status": false,
  "message": "Request too large"
}
```

Production recommendation:

```text
Set request_max_bytes lower than web server upload/body limits.
Configure Nginx/Apache/PHP limits to match or exceed the app policy safely.
Use file upload profiles for large multipart endpoints.
```

---

## 17. Content-Type Protection

Allowed content types are profile-specific:

```php
'api_authenticated' => [
    'content_types' => ['application/json'],
],

'public_form' => [
    'content_types' => [
        'application/x-www-form-urlencoded',
        'multipart/form-data',
    ],
],
```

Manual usage:

```php
$middleware = $kernel->contentTypeMiddleware(['application/json']);
```

`ContentTypeMiddleware` can also reject request bodies on `GET` and `HEAD` when `reject_body_on_get` is enabled.

---

## 18. JSON Body Parsing

`JsonBodyParserMiddleware` safely parses JSON requests with:

```text
maximum byte limit
maximum decode depth
invalid JSON handling
object/array requirement
```

Configuration:

```php
'json_depth' => 64,
'json_max_bytes' => 1048576,
'json_require_object' => true,
```

After parsing, JSON body is available from:

```php
$name = $request->input('name');
$body = $request->body();
```

Invalid JSON response:

```json
{
  "status": false,
  "message": "Invalid JSON body"
}
```

Large JSON response:

```json
{
  "status": false,
  "message": "JSON body too large"
}
```

---

## 19. Suspicious Request Detection

`SuspiciousRequestMiddleware` detects early attack indicators before the request reaches the route handler.

Default detection includes:

```text
control characters in path
very long path
path traversal
excessive parameters
../ or encoded traversal
<script
union select
information_schema
<?php
cmd=
powershell
etc/passwd
```

Configuration:

```php
'suspicious' => [
    'mode' => 'block',
    'max_path_length' => 2048,
    'max_parameters' => 200,
],
```

Modes:

| Mode | Behavior |
| --- | --- |
| `block` | Reject suspicious request with safe response. |
| `audit` | Allow request but attach `suspicious_request_reasons` attribute and record audit event. |

Example audit-mode usage:

```php
$reasons = $request->attribute('suspicious_request_reasons', []);

if ($reasons !== []) {
    // increase risk score, require stronger verification, or log extra context
}
```

---

## 20. Input Validation Integration

`InputValidationMiddleware` can sanitize and validate query/body data by route policy.

Example config:

```php
'validation' => [
    'input' => [
        'enabled' => true,
        'sanitize' => true,
        'routes' => [
            'students.create' => [
                'methods' => ['POST'],
                'path' => '/api/students',
                'body' => [
                    'strict' => true,
                    'allowed_fields' => ['name', 'email', 'class_id'],
                    'rules' => [
                        'name' => ['required', 'string', 'max:100'],
                        'email' => ['required', 'email'],
                        'class_id' => ['required', 'integer'],
                    ],
                ],
            ],
        ],
    ],
],
```

Set route name before validation:

```php
$request = $request->withAttribute('route_name', 'students.create');
```

Read validated input:

```php
$name = $request->validated('name');
$email = $request->validated('email');
```

Strict validation can remove fields not in `allowed_fields`. This helps prevent mass assignment.

---

## 21. Webhook Signature Verification

For webhook endpoints, use the `webhook` profile:

```php
$response = $kernel
    ->secureRequestReceiver('webhook')
    ->handle($request, function ($request) {
        return Response::json(['status' => true, 'message' => 'Webhook accepted.']);
    });
```

Configure webhook signing:

```php
'webhook' => [
    'signature_header' => 'X-Signature',
    'timestamp_header' => 'X-Timestamp',
    'algorithm' => 'sha256',
    'secret' => $_ENV['WEBHOOK_SECRET'] ?? '',
    'tolerance_seconds' => 300,
],
```

Manual verifier usage:

```php
$verifier = $kernel->webhookSignatureVerifier();

$result = $verifier->verify($request, $request->attribute('raw_body', ''));

if (!$result['valid']) {
    return Response::json(['status' => false, 'message' => 'Invalid webhook signature'], 401);
}
```

A successful `WebhookSignatureMiddleware` attaches:

```php
$request->attribute('webhook_signature_verified'); // true
```

Production recommendations:

```text
Use a different secret per webhook provider where possible.
Keep timestamp tolerance small, usually 300 seconds or less.
Reject missing timestamps when provider supports timestamped signatures.
Do not log raw webhook secret or full signature values.
```

---

## 22. CSRF Form Request Profile

For browser form endpoints:

```php
'public_form' => [
    'methods' => ['POST'],
    'max_bytes' => 1048576,
    'content_types' => ['application/x-www-form-urlencoded', 'multipart/form-data'],
    'rate_policy' => 'api',
    'auth' => null,
    'csrf' => true,
    'input_validation' => true,
    'auto_audit' => true,
],
```

Use `public_form` for:

```text
contact forms
registration forms
login forms
password reset requests
newsletter forms
```

CSRF is usually not required for stateless JSON APIs using bearer tokens, but it is important for cookie/session-backed browser forms.

---

## 23. Bearer Token API Profile

For authenticated JSON APIs:

```php
'api_authenticated' => [
    'methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    'max_bytes' => 1048576,
    'content_types' => ['application/json'],
    'rate_policy' => 'api',
    'auth' => 'bearer',
    'csrf' => false,
    'input_validation' => true,
],
```

When `auth` is `bearer`, the profile adds `ApiTokenMiddleware`.

The request must include:

```http
Authorization: Bearer <token>
```

---

## 24. Admin Request Profile

Admin routes should usually combine:

```text
HTTPS
trusted host
request trust
request ID
authentication
authorization
input validation
rate limiting
auto audit
security headers
```

Example:

```php
'admin' => [
    'methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    'max_bytes' => 1048576,
    'content_types' => ['application/json', 'application/x-www-form-urlencoded'],
    'rate_policy' => 'api',
    'auth' => 'bearer',
    'required_roles' => ['admin', 'super_admin'],
    'authorization' => 'students.read',
    'input_validation' => true,
    'auto_audit' => true,
],
```

Route usage:

```php
$response = $kernel
    ->secureRequestReceiver('admin')
    ->handle($request, function ($request) {
        return Response::json(['status' => true, 'message' => 'Admin request accepted.']);
    });
```

---

## 25. Upload Request Profile

For upload endpoints, request receiving should only accept the correct method and content type. File-specific validation should be handled by the File Security Engine.

```php
'upload_image' => [
    'methods' => ['POST'],
    'max_bytes' => 5242880,
    'content_types' => ['multipart/form-data'],
    'rate_policy' => 'api',
    'auth' => 'bearer',
    'upload_profile' => 'images',
    'input_validation' => true,
    'auto_audit' => true,
],
```

Recommended flow:

```text
Request receiving profile checks method, size, content type, auth, rate limit
    ↓
File Upload Security Engine checks MIME, extension, size, malware, quarantine
    ↓
Database Governance Engine stores safe file metadata
```

---

## 26. Internal System Request Profile

Internal endpoints should not be treated as public API endpoints.

Example:

```php
'internal_system' => [
    'methods' => ['POST'],
    'max_bytes' => 1048576,
    'content_types' => ['application/json'],
    'rate_policy' => 'api',
    'auth' => 'bearer',
    'trust_boundary' => 'backup.run',
    'input_validation' => true,
    'auto_audit' => true,
],
```

Use internal profiles for:

```text
queue worker callbacks
backup triggers
incident-response hooks
maintenance actions
admin-only automation
```

---

## 27. Trusted Proxy and Forwarded Header Safety

Requests often pass through reverse proxies or CDNs. Forwarded headers are dangerous unless the immediate proxy is trusted.

Risky headers:

```text
Forwarded
X-Forwarded-For
X-Forwarded-Host
X-Forwarded-Proto
X-Real-IP
CF-Connecting-IP
```

Use trusted proxy config:

```php
'app' => [
    'trusted_proxies' => [
        '127.0.0.1',
        '10.0.0.0/8',
    ],
],
```

Create request with trusted proxies:

```php
$request = Request::fromGlobals($config['app']['trusted_proxies'] ?? []);
```

Important behavior:

```text
Forwarded host/proto/client IP are used only when the immediate REMOTE_ADDR is trusted.
Untrusted forwarded headers are ignored or blocked by origin/request trust middleware.
```

---

## 28. Origin and Trusted Host Protection

Secure request receiving integrates with Origin Identity Protection.

Recommended app config:

```php
'app' => [
    'force_https' => true,
    'trusted_hosts' => [
        'example.com',
        'api.example.com',
    ],
],
```

This protects against:

```text
Host header poisoning
Password reset poisoning
Cache poisoning
Direct origin/IP Host access
Forwarded host spoofing
```

---

## 29. Rate Limiting Integration

Each request receiving profile can specify a rate policy:

```php
'rate_policy' => 'api',
```

The profile adds `RateLimitMiddleware` automatically.

Use stricter rate policies for:

```text
login
password reset
OTP verification
public forms
webhook endpoints
admin endpoints
```

Example:

```php
'login' => [
    'methods' => ['POST'],
    'max_bytes' => 65536,
    'content_types' => ['application/json'],
    'rate_policy' => 'auth_login',
    'auth' => null,
    'csrf' => false,
    'input_validation' => true,
],
```

---

## 30. Auto Audit Integration

When `auto_audit` is enabled, request events are recorded by `AutoAuditMiddleware`.

Typical audit context:

```text
request method
path
client IP
request ID
user context when available
profile name
result status
```

Enable per profile:

```php
'auto_audit' => true,
```

Disable for low-risk public read endpoints if needed:

```php
'auto_audit' => false,
```

---

## 31. Safe Responses from Request Receiving

Request receiving middleware returns safe responses.

Examples:

| Condition | Status | Message |
| --- | ---: | --- |
| Method blocked | `405` | `HTTP method is not allowed` |
| Request too large | `413` | `Request too large` |
| Unsupported content type | `415` | `Unsupported content type` |
| Invalid JSON | `400` | `Invalid JSON body` |
| Suspicious request | `400` | `Suspicious request rejected` |
| Invalid webhook signature | `401` | `Invalid webhook signature` |
| Validation failed | `422` | `Validation failed` |

These responses should not expose stack traces, file paths, SQL errors, or secrets.

---

## 32. Code Example: Public JSON Endpoint

```php
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

$request = Request::fromGlobals($config['app']['trusted_proxies'] ?? []);

$response = $kernel
    ->secureRequestReceiver('api_public')
    ->handle($request, function (Request $request): Response {
        return Response::json([
            'status' => true,
            'data' => [
                'message' => 'Public API response',
            ],
        ]);
    });

$response->send();
```

---

## 33. Code Example: Authenticated API Endpoint

```php
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

$request = Request::fromGlobals($config['app']['trusted_proxies'] ?? []);
$request = $request->withAttribute('route_name', 'students.create');

$response = $kernel
    ->secureRequestReceiver('api_authenticated')
    ->handle($request, function (Request $request): Response {
        $name = $request->validated('name', $request->input('name'));

        return Response::json([
            'status' => true,
            'message' => 'Student request accepted.',
            'name' => $name,
            'request_id' => $request->attribute('request_id'),
        ]);
    });

$response->send();
```

---

## 34. Code Example: Webhook Endpoint

```php
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

$request = Request::fromGlobals($config['app']['trusted_proxies'] ?? []);

$response = $kernel
    ->secureRequestReceiver('webhook')
    ->handle($request, function (Request $request): Response {
        if ($request->attribute('webhook_signature_verified') !== true) {
            return Response::json(['status' => false, 'message' => 'Webhook not verified'], 401);
        }

        $payload = $request->body();

        return Response::json([
            'status' => true,
            'message' => 'Webhook accepted.',
        ]);
    });

$response->send();
```

---

## 35. Code Example: Custom Profile

Add a profile:

```php
'profiles' => [
    'report_export' => [
        'methods' => ['POST'],
        'max_bytes' => 65536,
        'content_types' => ['application/json'],
        'rate_policy' => 'api',
        'auth' => 'bearer',
        'csrf' => false,
        'input_validation' => true,
        'authorization' => 'reports.export',
        'trust_boundary' => 'reports.export',
        'auto_audit' => true,
    ],
],
```

Use it:

```php
$response = $kernel
    ->secureRequestReceiver('report_export')
    ->handle($request, function (Request $request): Response {
        $job = $kernel->jobDispatcher()->dispatch(
            name: 'database_export',
            payload: ['report' => 'students'],
            queue: 'exports',
            idempotencyKey: 'export:' . hash('sha256', json_encode($request->body()))
        );

        return $kernel->asyncResponseFactory()->accepted($job);
    });
```

This pattern keeps expensive work out of the synchronous request.

---

## 36. Framework Integration Pattern

For frameworks such as Slim, Laravel, or custom routers, convert the framework request into `Mnb\SecurityCore\Http\Request`, run the receiver, then convert the response back if needed.

Pseudo-adapter:

```php
function handleWithMnb(SecurityKernel $kernel, string $profile, Request $request, callable $route): Response
{
    return $kernel->secureRequestReceiver($profile)->handle($request, $route);
}
```

In a framework middleware:

```php
$receiver = $kernel->secureRequestReceiver('api_authenticated');

$response = $receiver->handle($mnbRequest, function ($safeRequest) use ($next) {
    return $next($safeRequest);
});
```

---

## 37. Testing Request Receiving Profiles

Use manual `Request` objects in tests.

### Test: method blocked

```php
$request = new Request(
    method: 'TRACE',
    path: '/api/test',
    headers: [],
    server: ['CONTENT_LENGTH' => 0]
);

$response = $kernel
    ->secureRequestReceiver('api_public')
    ->handle($request, fn() => Response::json(['status' => true]));

assert($response->status() === 405);
```

### Test: JSON body too large

```php
$request = (new Request(
    method: 'POST',
    path: '/api/test',
    headers: ['Content-Type' => 'application/json'],
    server: ['CONTENT_LENGTH' => 99999999]
))->withAttribute('raw_body', str_repeat('A', 99999999));

$response = $kernel
    ->secureRequestReceiver('api_public')
    ->handle($request, fn() => Response::json(['status' => true]));

assert(in_array($response->status(), [413, 415], true));
```

### Test: unsupported content type

```php
$request = new Request(
    method: 'POST',
    path: '/api/test',
    headers: ['Content-Type' => 'text/plain'],
    server: ['CONTENT_LENGTH' => 20]
);

$response = $kernel
    ->secureRequestReceiver('api_public')
    ->handle($request, fn() => Response::json(['status' => true]));

assert($response->status() === 415);
```

### Test: suspicious path blocked

```php
$request = new Request(
    method: 'GET',
    path: '/../etc/passwd',
    headers: [],
    server: ['CONTENT_LENGTH' => 0]
);

$response = $kernel
    ->secureRequestReceiver('public_read')
    ->handle($request, fn() => Response::json(['status' => true]));

assert($response->status() === 400);
```

---

## 38. CLI Commands

Useful project-level commands:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure production:readiness
php bin/mnb-secure final:gate
```

Related commands from other engines:

```bash
php bin/mnb-secure origin:check
php bin/mnb-secure origin:production-gate
php bin/mnb-secure token:policy
php bin/mnb-secure session:policy
php bin/mnb-secure throughput:policy
php bin/mnb-secure memory:policy
php bin/mnb-secure vulnerabilities:report
```

If you maintain project-specific command wrappers, add request receiving checks such as:

```text
list request receiving profiles
verify webhook secret is configured
verify JSON limits are sane
verify dangerous HTTP methods are blocked
verify public/admin/webhook profiles exist
```

---

## 39. Recommended Production Defaults

| Setting | Recommended value |
| --- | --- |
| `REQUEST_RECEIVING_ENABLED` | `true` |
| `SUSPICIOUS_REQUEST_MODE` | `block` |
| `REQUEST_JSON_MAX_BYTES` | `1048576` or lower for normal APIs |
| `REQUEST_JSON_DEPTH` | `32` or `64` |
| `REQUEST_MAX_PARAMETERS` | `100` to `200` |
| `blocked_methods` | `TRACE`, `CONNECT` |
| `reject_body_on_get` | `true` |
| `webhook.secret` | real 32+ character secret |
| `trusted_hosts` | exact production domains only |
| `trusted_proxies` | exact proxy/CDN ranges only |
| `force_https` | `true` in production |
| `auto_audit` | `true` for sensitive endpoints |

---

## 40. Recommended Profile Design

Use separate profiles instead of one global request policy.

Recommended:

```text
public_read       → GET/HEAD only, tiny max body, no auth
public_form       → POST form, CSRF, validation, rate limit
api_public        → JSON API, no auth, small body, rate limit
api_authenticated → JSON API, bearer auth, validation, rate limit
admin             → auth + authorization + audit + strict checks
upload_image      → multipart only + auth + file profile
webhook           → POST JSON + signature auth
internal_system   → auth + trust boundary + audit
```

Avoid:

```text
one profile that allows all methods
one profile that allows all content types
one profile that disables validation globally
one profile that accepts huge bodies for every route
one profile that treats webhooks like normal public API calls
```

---

## 41. Security Checklist

Before production:

```text
[ ] All public endpoints use a request receiving profile.
[ ] TRACE and CONNECT are blocked.
[ ] GET/HEAD request bodies are rejected unless explicitly needed.
[ ] JSON body size and depth limits are configured.
[ ] Upload endpoints use multipart-only profiles and file security profiles.
[ ] Webhook endpoints use signature profile and real WEBHOOK_SECRET.
[ ] Admin endpoints use auth, authorization, audit, HTTPS, trusted host.
[ ] Trusted proxy ranges are configured correctly.
[ ] Trusted host list contains only production domains.
[ ] Suspicious request mode is block in production.
[ ] Input validation is enabled on write endpoints.
[ ] Rate limits are attached to public, auth, webhook, and admin routes.
[ ] Request IDs are included in responses and logs.
[ ] Safe error handling wraps the request pipeline.
```

---

## 42. Common Mistakes

### Mistake: allowing all content types

Bad:

```php
'content_types' => ['*'],
```

Better:

```php
'content_types' => ['application/json'],
```

Use multipart only for real upload endpoints.

---

### Mistake: using a large request limit globally

Bad:

```php
'max_bytes' => 104857600,
```

Better:

```php
'api_authenticated' => ['max_bytes' => 1048576],
'upload_image' => ['max_bytes' => 5242880],
```

Large limits should be route-specific.

---

### Mistake: treating webhooks as public POST APIs

Bad:

```php
'auth' => null,
```

Better:

```php
'auth' => 'signature',
```

Webhook endpoints should verify signatures.

---

### Mistake: trusting forwarded headers from everyone

Bad:

```text
Use X-Forwarded-For without trusted proxy checks.
```

Better:

```text
Trust forwarded headers only when REMOTE_ADDR is a known proxy/CDN.
```

---

### Mistake: disabling suspicious request detection on admin routes

Bad:

```php
'suspicious_detection' => false,
```

Better:

```php
'suspicious_detection' => true,
```

---

## 43. How This Connects to Other Engines

| Engine | Connection |
| --- | --- |
| Trust Zones and Data Boundaries | Request profile can call trust boundary middleware. |
| Authentication Strategy | Request profile can require bearer, CSRF, signature, or auth strategy. |
| Authorization Strategy | Request profile can enforce permission checks. |
| Rate Limiting | Request profile can attach rate policy. |
| File Security | Upload profile receives only validated multipart request. |
| Origin Protection | Request receiving validates host, proxy, and origin exposure. |
| Safe Error Handling | Invalid requests return safe responses without technical leaks. |
| Logging/Audit | Auto audit records request behavior. |
| Token/Session Control | Bearer/session middleware can be combined with token/session policy. |
| Queue/Background Jobs | Long-running requests should return 202 and dispatch jobs. |
| Memory/Throughput | Request limits protect memory and capacity budgets. |

---

## 44. Recommended Final Flow for APIs

For secure JSON API routes:

```text
1. Use api_authenticated profile.
2. Attach route_name before input validation if route policies are used.
3. Validate and sanitize input.
4. Enforce auth/token/session policy.
5. Enforce authorization and trust boundary.
6. Use database governance for persistence.
7. Use safe responses and output encoding.
8. Dispatch expensive work to queue.
9. Record audit events.
```

Example route handler after request receiving:

```php
$response = $kernel
    ->secureRequestReceiver('api_authenticated')
    ->handle($request->withAttribute('route_name', 'students.create'), function ($request) use ($kernel) {
        $data = [
            'name' => $request->validated('name'),
            'email' => $request->validated('email'),
        ];

        // Continue with authorization/database governance here.
        return Response::json([
            'status' => true,
            'message' => 'Safe request reached application logic.',
            'request_id' => $request->attribute('request_id'),
        ]);
    });
```

---

## 45. Summary

The **Secure Request Receiving Strategy** is the front door of the security core.

It provides:

```text
request profile registry
safe middleware pipeline
request ID correlation
trusted proxy handling
origin/host/HTTPS checks
method restrictions
request size limits
content-type validation
safe JSON parsing
suspicious request detection
input validation handoff
rate limiting handoff
CSRF/API token/webhook signature auth handoff
authorization/trust-boundary handoff
audit-ready request intake
```

Use it on every route group. Keep profiles small, explicit, and purpose-specific. Unsafe traffic should be rejected before it reaches controllers, services, database queries, file handling, background jobs, or business logic.
