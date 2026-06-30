# API Security and Rate Limiting

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Document type:** Detailed feature documentation and code usage  
**Feature area:** API response safety, bearer-token protection, request throttling, per-route policies, rate-limit headers, CORS coordination, request receiving integration, token/session integration, queue/backpressure handoff, audit and production readiness

---

## 1. Overview

The **API Security and Rate Limiting** layer protects machine-facing routes such as REST APIs, mobile app APIs, admin APIs, webhook receivers, internal service endpoints, and integration endpoints.

It answers questions like:

```text
Is this API request allowed to enter the application?
Is the bearer token present and valid?
Is the client sending too many requests?
Should limits be based on IP, authenticated user, route, method, or token?
Should the response include rate-limit headers?
Should the API return a safe JSON error instead of a raw exception?
Should a heavy API operation be deferred to a queue?
Should CORS allow this frontend origin to call the API?
```

A good API security setup is not just one middleware. It is a sequence:

```text
Raw API request
    ↓
Request ID / trust / host / origin checks
    ↓
Request size, method, content-type, JSON parser
    ↓
Suspicious request detection
    ↓
CORS and security headers
    ↓
Rate limiting
    ↓
Authentication / bearer token validation
    ↓
Token/session revocation check
    ↓
Authorization / tenant boundary
    ↓
Input validation
    ↓
Controller / service
    ↓
Safe JSON response
```

`mnb-secure-core` provides the building blocks for this flow without forcing one framework. You can use it in plain PHP, Slim, Laravel-style middleware, custom routers, background API workers, or internal admin panels.

---

## 2. What This Feature Protects Against

API security and rate limiting help reduce risk from:

```text
Credential stuffing
Login brute force
OTP brute force
API token abuse
Scraping and enumeration
Password reset abuse
High-volume endpoint abuse
Webhook spam
Expensive export/report abuse
Denial-of-service by repeated requests
User-specific quota exhaustion
Route-specific hot spots
CORS misconfiguration
Unsafe JSON error responses
Token replay when combined with token/session controls
```

Rate limiting should not be treated as the only protection. It works with authentication, authorization, request validation, suspicious request detection, throughput governance, queue deferral, and safe errors.

---

## 3. Main Classes

The API and rate limiting layer is mainly built around these classes:

```text
Mnb\SecurityCore\Api\ApiResponder

Mnb\SecurityCore\RateLimit\RateLimitPolicy
Mnb\SecurityCore\RateLimit\RateLimitPolicyRegistry
Mnb\SecurityCore\RateLimit\RateLimitKeyBuilder
Mnb\SecurityCore\RateLimit\RateLimitResult
Mnb\SecurityCore\RateLimit\FileRateLimiter
Mnb\SecurityCore\RateLimit\DatabaseRateLimiter
Mnb\SecurityCore\RateLimit\RedisRateLimiter

Mnb\SecurityCore\Contracts\RateLimiterInterface

Mnb\SecurityCore\Http\Request
Mnb\SecurityCore\Http\Response
Mnb\SecurityCore\Http\MiddlewarePipeline

Mnb\SecurityCore\Http\Middleware\RateLimitMiddleware
Mnb\SecurityCore\Http\Middleware\RateLimitPolicyMiddleware
Mnb\SecurityCore\Http\Middleware\ApiTokenMiddleware
Mnb\SecurityCore\Http\Middleware\AuthenticationMiddleware
Mnb\SecurityCore\Http\Middleware\AuthorizationMiddleware
Mnb\SecurityCore\Http\Middleware\CorsMiddleware
Mnb\SecurityCore\Http\Middleware\JsonBodyParserMiddleware
Mnb\SecurityCore\Http\Middleware\RequestSizeMiddleware
Mnb\SecurityCore\Http\Middleware\SuspiciousRequestMiddleware
Mnb\SecurityCore\Http\Middleware\ErrorHandlingMiddleware
```

The central access points are available through `SecurityKernel`:

```php
$kernel->rateLimiter();
$kernel->fileRateLimiter();
$kernel->rateLimitPolicies();
$kernel->rateLimitPolicy('api');
$kernel->rateLimitMiddleware('api');
$kernel->authenticationMiddleware('api_bearer');
$kernel->authorizationMiddleware('student.view');
```

---

## 4. Installation

Install from Packagist:

```bash
composer require mnb/mnb-secure-core
```

Bootstrap Composer autoloading:

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Env\EnvLoader;

EnvLoader::load(__DIR__ . '/.env');

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

When installed through Composer, package files live under:

```text
vendor/mnb/mnb-secure-core
```

---

## 5. Recommended Configuration

Rate limit policy configuration normally lives in:

```text
config/security.php
config/security.production.php
```

A practical starting configuration:

```php
return [
    'limits' => [
        'request_max_bytes' => 12 * 1024 * 1024,
        'upload_max_bytes' => 10 * 1024 * 1024,

        'login' => [
            'max' => 5,
            'seconds' => 600,
            'key_by' => ['ip', 'route'],
        ],

        'api' => [
            'max' => 120,
            'seconds' => 60,
            'key_by' => ['ip', 'user', 'route'],
        ],

        'otp' => [
            'max' => 3,
            'seconds' => 600,
            'key_by' => ['ip', 'user', 'route'],
        ],

        'export' => [
            'max' => 10,
            'seconds' => 3600,
            'key_by' => ['user', 'route'],
        ],
    ],

    'rate_limiter' => [
        // Supported: file, redis, database
        'driver' => $_ENV['RATE_LIMIT_DRIVER'] ?? 'file',
        'prefix' => $_ENV['RATE_LIMIT_PREFIX'] ?? 'mnb:rate:',
        'table' => $_ENV['RATE_LIMIT_TABLE'] ?? 'mnb_rate_limits',
    ],

    'token_store' => [
        // Supported: file, redis, database
        'driver' => $_ENV['TOKEN_STORE_DRIVER'] ?? 'file',
        'prefix' => $_ENV['TOKEN_STORE_PREFIX'] ?? 'mnb:token:',
        'table' => $_ENV['TOKEN_STORE_TABLE'] ?? 'mnb_api_tokens',
    ],

    'cors' => [
        'enabled' => true,
        'allowed_origins' => ['https://app.example.com'],
        'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        'allowed_headers' => ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
        'exposed_headers' => [
            'X-Request-ID',
            'X-RateLimit-Policy',
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
        ],
        'allow_credentials' => false,
        'allow_null_origin' => false,
        'allow_private_network' => false,
        'max_age' => 600,
    ],
];
```

---

## 6. Rate Limit Policies

A rate limit policy defines:

| Option | Meaning |
|---|---|
| `max` / `max_attempts` | Number of allowed attempts in the window. |
| `seconds` / `decay_seconds` | Window duration in seconds. |
| `key_by` | Parts used to build the rate-limit identity. |
| `prefix` | Storage key prefix. |

Supported `key_by` parts:

```text
ip
user
route
path
method
auth
```

Examples:

```php
'limits' => [
    // Good for public login endpoints.
    'login' => [
        'max' => 5,
        'seconds' => 600,
        'key_by' => ['ip', 'route'],
    ],

    // Good for authenticated API endpoints.
    'api' => [
        'max' => 120,
        'seconds' => 60,
        'key_by' => ['ip', 'user', 'route'],
    ],

    // Good for OTP or verification endpoints.
    'otp' => [
        'max' => 3,
        'seconds' => 600,
        'key_by' => ['ip', 'user', 'route'],
    ],

    // Good for expensive reports or exports.
    'export' => [
        'max' => 10,
        'seconds' => 3600,
        'key_by' => ['user', 'route'],
    ],
],
```

---

## 7. Rate Limit Key Design

`RateLimitKeyBuilder` creates a safe key from the selected policy parts.

Example policy:

```php
'api' => [
    'max' => 120,
    'seconds' => 60,
    'key_by' => ['ip', 'user', 'route'],
],
```

Possible generated key shape:

```text
request:api:ip:203.0.113.10:user:42:route:api.students.index
```

Important design guidance:

| Endpoint type | Recommended key parts |
|---|---|
| Login | `ip`, `route` |
| OTP | `ip`, `user`, `route` |
| Authenticated API | `ip`, `user`, `route` |
| API token integrations | `auth`, `route` |
| Exports/reports | `user`, `route` |
| Public search | `ip`, `route`, `method` |
| Webhooks | `ip`, `route` plus webhook signature verification |

Avoid only using `ip` for authenticated APIs because users behind the same NAT may share one IP. Avoid only using `user` for public unauthenticated routes because anonymous abuse will not be separated correctly.

---

## 8. Storage Drivers

The package supports multiple rate limiter stores.

### File Driver

Good for:

```text
local development
small apps
shared hosting
simple PHP deployments
```

Config:

```php
'rate_limiter' => [
    'driver' => 'file',
],
```

The file driver stores hashed keys in the configured cache directory. It uses file locking for basic concurrency safety.

### Redis Driver

Good for:

```text
multi-server deployments
high-traffic APIs
horizontally scaled apps
fast central counters
```

Config:

```php
'rate_limiter' => [
    'driver' => 'redis',
    'prefix' => 'mnb:rate:',
],

'redis' => [
    'host' => '127.0.0.1',
    'port' => 6379,
    'password' => null,
    'database' => null,
    'timeout' => 1.5,
],
```

Use Redis for production when multiple application servers must share limits.

### Database Driver

Good for:

```text
apps that already use SQL storage
admin reporting on rate limit state
simple deployments without Redis
```

Config:

```php
'rate_limiter' => [
    'driver' => 'database',
    'table' => 'mnb_rate_limits',
],
```

For production, create the required database table according to your application migration strategy.

---

## 9. Basic API Response Usage

`ApiResponder` helps return consistent JSON responses.

```php
use Mnb\SecurityCore\Api\ApiResponder;

$responder = new ApiResponder();

return $responder->ok([
    'id' => 1001,
    'name' => 'Ananya',
], 'Student loaded.');
```

Failure response:

```php
return $responder->fail('Validation failed.', 422, [
    'email' => ['Invalid email address.'],
]);
```

Response shape:

```json
{
  "status": false,
  "message": "Validation failed.",
  "errors": {
    "email": ["Invalid email address."]
  }
}
```

For critical production APIs, combine `ApiResponder` with:

```text
SafeErrorHandler
ErrorResponseFactory
ProblemDetailsResponseFactory
DataProtectionPolicy
DatabaseResultFilter
```

---

## 10. Using a Rate Limiter Directly

You can use the rate limiter without middleware:

```php
$limiter = $kernel->rateLimiter();

$result = $limiter->attempt(
    key: 'api:ip:203.0.113.10:route:students.index',
    maxAttempts: 120,
    decaySeconds: 60
);

if (!$result->allowed) {
    return \Mnb\SecurityCore\Http\Response::json([
        'status' => false,
        'message' => 'Too many requests.',
    ], 429, [
        'Retry-After' => (string) $result->retryAfter,
        'X-RateLimit-Remaining' => '0',
        'X-RateLimit-Reset' => (string) $result->resetAt,
    ]);
}
```

The result contains:

```php
$result->allowed;    // bool
$result->remaining;  // int
$result->retryAfter; // int seconds
$result->resetAt;    // unix timestamp
```

---

## 11. Using a Registered Policy

Use a named policy from config:

```php
$policy = $kernel->rateLimitPolicy('api');

$key = $policy->key($request, 'api.students.index');

$result = $kernel->rateLimiter()->attempt(
    $key,
    $policy->maxAttempts(),
    $policy->decaySeconds()
);
```

Create a policy manually:

```php
use Mnb\SecurityCore\RateLimit\RateLimitPolicy;

$policy = new RateLimitPolicy(
    name: 'student_search',
    maxAttempts: 60,
    decaySeconds: 60,
    keyBy: ['ip', 'user', 'route'],
    prefix: 'api'
);
```

Register multiple policies:

```php
use Mnb\SecurityCore\RateLimit\RateLimitPolicyRegistry;

$registry = new RateLimitPolicyRegistry([
    'search' => [
        'max' => 60,
        'seconds' => 60,
        'key_by' => ['ip', 'user', 'route'],
    ],
]);

$policy = $registry->get('search');
```

---

## 12. Rate Limit Middleware

Recommended API middleware usage:

```php
use Mnb\SecurityCore\Http\MiddlewarePipeline;

$pipeline = new MiddlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->errorHandlingMiddleware(),
    $kernel->requestTrustMiddleware(),
    $kernel->trustedHostMiddleware(),
    $kernel->corsMiddleware(),
    $kernel->requestSizeMiddleware(),
    $kernel->contentTypeMiddleware(['application/json']),
    $kernel->jsonBodyParserMiddleware(),
    $kernel->suspiciousRequestMiddleware(),
    $kernel->rateLimitMiddleware('api', 'api.students.index'),
    $kernel->authenticationMiddleware('api_bearer'),
    $kernel->authorizationMiddleware('student.view'),
]);

$response = $pipeline->handle($request, function ($request) use ($controller) {
    return $controller->index($request);
});
```

When a request is allowed, `RateLimitMiddleware` adds headers:

```text
X-RateLimit-Policy: api
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 119
X-RateLimit-Reset: 1780000000
```

When blocked, it returns:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30
X-RateLimit-Remaining: 0
```

Safe JSON body:

```json
{
  "status": false,
  "message": "Too many requests"
}
```

---

## 13. Route-Specific Examples

### Login Endpoint

Login should be strict and should not reveal whether the email exists.

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->errorHandlingMiddleware(),
    $kernel->requestSizeMiddleware(),
    $kernel->contentTypeMiddleware(['application/json']),
    $kernel->jsonBodyParserMiddleware(),
    $kernel->rateLimitMiddleware('login', 'auth.login'),
]);

$response = $pipeline->handle($request, function ($request) use ($authService) {
    $result = $authService->login(
        (string) $request->input('email'),
        (string) $request->input('password')
    );

    if (!$result->successful()) {
        return \Mnb\SecurityCore\Http\Response::json([
            'status' => false,
            'message' => 'Invalid credentials',
        ], 401);
    }

    return \Mnb\SecurityCore\Http\Response::json([
        'status' => true,
        'message' => 'Login successful.',
        'data' => [
            'token' => $result->token(),
        ],
    ]);
});
```

Recommended policy:

```php
'login' => [
    'max' => 5,
    'seconds' => 600,
    'key_by' => ['ip', 'route'],
],
```

### OTP Verification Endpoint

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->errorHandlingMiddleware(),
    $kernel->rateLimitMiddleware('otp', 'auth.otp.verify'),
]);
```

Recommended policy:

```php
'otp' => [
    'max' => 3,
    'seconds' => 600,
    'key_by' => ['ip', 'user', 'route'],
],
```

### Authenticated API Endpoint

```php
$pipeline = new MiddlewarePipeline([
    $kernel->rateLimitMiddleware('api', 'api.students.show'),
    $kernel->authenticationMiddleware('api_bearer'),
    $kernel->authorizationMiddleware('student.view'),
]);
```

Recommended policy:

```php
'api' => [
    'max' => 120,
    'seconds' => 60,
    'key_by' => ['ip', 'user', 'route'],
],
```

### Export Endpoint

Expensive exports should usually be queued instead of running during the API request.

```php
$pipeline = new MiddlewarePipeline([
    $kernel->rateLimitMiddleware('export', 'api.exports.students'),
    $kernel->authenticationMiddleware('api_bearer'),
    $kernel->authorizationMiddleware('student.export'),
]);

$response = $pipeline->handle($request, function ($request) use ($kernel) {
    $accepted = $kernel->jobDispatcher()->dispatch(
        name: 'database_export',
        payload: ['type' => 'students'],
        queue: 'exports',
        idempotencyKey: 'students-export:' . (string) $request->attribute('auth_user_id')
    );

    return $kernel->asyncResponseFactory()->accepted($accepted);
});
```

Recommended policy:

```php
'export' => [
    'max' => 10,
    'seconds' => 3600,
    'key_by' => ['user', 'route'],
],
```

---

## 14. API Token Middleware

`ApiTokenMiddleware` validates bearer tokens and attaches an authenticated context to the request.

```php
$pipeline = new MiddlewarePipeline([
    $kernel->rateLimitMiddleware('api', 'api.profile'),
    $kernel->apiTokenMiddleware(),
]);
```

The middleware reads:

```http
Authorization: Bearer <token>
```

If valid, it attaches:

```text
AuthContext::ATTRIBUTE
auth_token
auth_user_id
auth_scopes
```

If missing:

```json
{
  "status": false,
  "message": "Missing bearer token"
}
```

If invalid or expired:

```json
{
  "status": false,
  "message": "Invalid or expired token"
}
```

For modern production APIs, combine token middleware with upgrade 35 token/session controls:

```php
$tokenStatus = $kernel->tokenValidator()->validate($tokenId);

if (!$tokenStatus->allowed()) {
    return Response::json([
        'status' => false,
        'message' => 'Invalid or expired token',
    ], 401);
}
```

---

## 15. CORS and API Security

CORS should only allow trusted frontend origins.

Good production example:

```php
'cors' => [
    'enabled' => true,
    'allowed_origins' => ['https://app.example.com'],
    'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    'allowed_headers' => ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
    'exposed_headers' => ['X-Request-ID', 'X-RateLimit-Policy', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    'allow_credentials' => false,
    'allow_null_origin' => false,
    'allow_private_network' => false,
    'max_age' => 600,
],
```

Avoid:

```php
'allowed_origins' => ['*'];
'allow_credentials' => true;
'allow_null_origin' => true;
```

Especially avoid wildcard origins with credentialed API requests.

---

## 16. Safe API Error Responses

API handlers should not leak raw exceptions.

Use `ErrorHandlingMiddleware` and safe error policy:

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->errorHandlingMiddleware(),
    $kernel->rateLimitMiddleware('api'),
    $kernel->authenticationMiddleware('api_bearer'),
]);
```

Unsafe response:

```json
{
  "error": "SQLSTATE[HY000] Access denied for user root..."
}
```

Safe response:

```json
{
  "status": false,
  "message": "Something went wrong. Please try again later.",
  "error": {
    "code": "INTERNAL_ERROR",
    "request_id": "req_abc123"
  }
}
```

For standards-style APIs, enable `problem_json` in the error configuration.

---

## 17. API Security with Request Receiving Profiles

Request receiving profiles can attach a `rate_policy` to endpoint groups.

Example concept:

```php
'profiles' => [
    'json_api' => [
        'methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        'content_types' => ['application/json'],
        'max_body_bytes' => 1048576,
        'rate_policy' => 'api',
        'auth_strategy' => 'api_bearer',
    ],

    'admin_api' => [
        'methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        'content_types' => ['application/json'],
        'max_body_bytes' => 1048576,
        'rate_policy' => 'api',
        'auth_strategy' => 'admin_bearer',
    ],
],
```

Usage:

```php
$pipeline = $kernel->requestReceivingPipeline('json_api');
```

This is the cleanest approach for larger apps because the profile controls request size, method, content type, suspicious request checks, rate policy, and auth handoff consistently.

---

## 18. Rate Limiting with Throughput and Queue Engines

Rate limiting controls request count. Throughput controls latency and capacity. Queue controls long-running work.

Use all three together:

```text
Rate limit → Is this client sending too many requests?
Throughput → Is this operation too slow or too expensive right now?
Queue → Should this work run in the background?
```

Example:

```php
$decision = $kernel->throughputPolicy()->evaluate('database_export', $sample);

if ($decision->requiresQueue()) {
    return $kernel->asyncResponseFactory()->accepted(
        $kernel->jobDispatcher()->dispatch(
            name: 'database_export',
            payload: ['export_id' => $exportId],
            queue: 'exports',
            idempotencyKey: 'export:' . $exportId
        )
    );
}
```

Recommended rule:

```text
Never use only rate limiting to protect expensive operations.
Use queue deferral and throughput budgets too.
```

---

## 19. API Security with Data Protection

Never return raw sensitive records directly.

Unsafe:

```php
return Response::json([
    'status' => true,
    'data' => $userRow,
]);
```

Safer:

```php
$safeUser = $kernel->databaseResultFilter()->filterRow(
    row: $userRow,
    fieldProtection: $kernel->databaseFieldProtection(),
    context: $authContext
);

return Response::json([
    'status' => true,
    'data' => $safeUser,
]);
```

For exports, use:

```text
SafeCsvExporter
DataMasker
DatabaseResultFilter
Queue engine
Memory stream guards
```

---

## 20. API Security with Authorization

Authentication proves identity. Authorization proves permission.

Do not stop at bearer token validation:

```php
$pipeline = new MiddlewarePipeline([
    $kernel->rateLimitMiddleware('api', 'api.students.show'),
    $kernel->authenticationMiddleware('api_bearer'),
    $kernel->authorizationMiddleware('student.view'),
    $kernel->trustBoundaryMiddleware('tenant'),
]);
```

Recommended checks for API route handlers:

```text
Request is rate-limited
Token/session is valid and not revoked
User has permission
Tenant boundary is enforced
Database query is tenant-scoped
Response fields are filtered/masked
Audit event is recorded
```

---

## 21. Webhook API Security

Webhook endpoints are APIs too, but they should usually use signature authentication instead of bearer tokens.

Recommended middleware flow:

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->errorHandlingMiddleware(),
    $kernel->requestSizeMiddleware(),
    $kernel->contentTypeMiddleware(['application/json']),
    $kernel->jsonBodyParserMiddleware(),
    $kernel->rateLimitMiddleware('api', 'webhook.payment.received'),
    $kernel->webhookSignatureMiddleware(),
]);
```

Webhook security checklist:

```text
Require HTTPS
Limit body size
Require JSON content type
Verify timestamp tolerance
Verify HMAC signature
Reject replayed timestamps when possible
Rate-limit by IP and route
Queue processing if the webhook work is expensive
Do not log raw payload secrets
```

---

## 22. Testing Examples

### Test That the First Request Is Allowed

```php
$limiter = $kernel->fileRateLimiter();

$result = $limiter->attempt('test:api:one', 2, 60);

assert($result->allowed === true);
assert($result->remaining === 1);
```

### Test That the Limit Blocks

```php
$limiter = $kernel->fileRateLimiter();

$limiter->attempt('test:api:block', 1, 60);
$result = $limiter->attempt('test:api:block', 1, 60);

assert($result->allowed === false);
assert($result->remaining === 0);
assert($result->retryAfter > 0);
```

### Test a Policy Key

```php
$policy = $kernel->rateLimitPolicy('api');
$key = $policy->key($request, 'api.students.index');

assert(str_contains($key, 'api'));
assert(str_contains($key, 'route:api.students.index'));
```

### Test Middleware Headers

```php
$middleware = $kernel->rateLimitMiddleware('api', 'api.test');

$response = $middleware->process($request, function ($request) {
    return \Mnb\SecurityCore\Http\Response::json(['status' => true]);
});

assert($response->header('X-RateLimit-Policy') === 'api');
```

---

## 23. CLI Commands

Useful project validation commands:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure vulnerabilities:report
```

Related feature commands from other engines:

```bash
php bin/mnb-secure token:policy
php bin/mnb-secure session:policy
php bin/mnb-secure throughput:policy
php bin/mnb-secure queue:policy
php bin/mnb-secure production:readiness
```

For manual testing, you can also create a temporary route and inspect returned headers:

```bash
curl -i https://api.example.com/v1/students
```

Expected headers:

```text
X-Request-ID: req_...
X-RateLimit-Policy: api
X-RateLimit-Limit: 120
X-RateLimit-Remaining: ...
X-RateLimit-Reset: ...
```

---

## 24. Production Checklist

Before enabling public APIs, verify:

```text
[ ] API routes are behind request receiving middleware.
[ ] Request size limits are configured.
[ ] JSON content-type checks are enabled.
[ ] CORS allows only trusted frontend origins.
[ ] Bearer token authentication is enabled where required.
[ ] Token revocation checks are active.
[ ] Session forced logout hooks are integrated.
[ ] Rate limit policies exist for login, API, OTP, webhook, and export routes.
[ ] Redis or database driver is used for multi-server production deployments.
[ ] Rate limit headers are exposed only where appropriate.
[ ] Safe error handling is enabled.
[ ] API responses are filtered and masked before return.
[ ] Expensive API jobs are queued.
[ ] Throughput and memory profiles exist for expensive operations.
[ ] Webhook routes verify HMAC signatures.
[ ] Logs redact Authorization headers, tokens, cookies, and API keys.
[ ] Vulnerability report and production readiness gate pass.
```

---

## 25. Common Mistakes

### Mistake 1: Using only IP-based limits for authenticated APIs

Bad:

```php
'api' => [
    'max' => 120,
    'seconds' => 60,
    'key_by' => ['ip'],
],
```

Better:

```php
'api' => [
    'max' => 120,
    'seconds' => 60,
    'key_by' => ['ip', 'user', 'route'],
],
```

### Mistake 2: Treating rate limits as authentication

Rate limiting does not identify users. Always use authentication middleware for protected APIs.

### Mistake 3: Allowing wildcard CORS with credentials

Avoid:

```php
'allowed_origins' => ['*'],
'allow_credentials' => true,
```

### Mistake 4: Running expensive exports synchronously

Bad:

```php
$rows = $db->fetchAll('SELECT * FROM students');
return exportCsv($rows);
```

Better:

```php
return $kernel->asyncResponseFactory()->accepted(
    $kernel->jobDispatcher()->dispatch('database_export', ['export_id' => $exportId], 'exports')
);
```

### Mistake 5: Returning database rows directly

Always filter, mask, and authorize fields before returning API responses.

### Mistake 6: Logging raw Authorization headers

Logs must redact:

```text
Authorization
Cookie
Set-Cookie
api_key
token
password
secret
```

---

## 26. Recommended Middleware Order for APIs

A practical order:

```text
1. RequestIdMiddleware
2. ErrorHandlingMiddleware
3. RequestTrustMiddleware
4. ServerIdentityProtectionMiddleware
5. TrustedHostMiddleware
6. HttpsMiddleware
7. CorsMiddleware
8. RequestMethodMiddleware
9. RequestSizeMiddleware
10. ContentTypeMiddleware
11. JsonBodyParserMiddleware
12. SuspiciousRequestMiddleware
13. SecurityHeadersMiddleware
14. RateLimitMiddleware / RateLimitPolicyMiddleware
15. AuthenticationMiddleware / ApiTokenMiddleware
16. Token/session revocation validation
17. AuthorizationMiddleware
18. TenantBoundaryMiddleware / TrustBoundaryMiddleware
19. InputValidationMiddleware
20. AutoAuditMiddleware
21. Controller
```

Place rate limiting before expensive authentication database lookups when possible, but make sure authenticated/user-based limits are applied after identity is available if your policy requires `user` or `auth` key parts. For high-security routes, you can apply two limits:

```text
early IP limit → before authentication
user/token limit → after authentication
```

---

## 27. Recommended Policy Examples

### Public API

```php
'public_api' => [
    'max' => 60,
    'seconds' => 60,
    'key_by' => ['ip', 'route'],
],
```

### Authenticated API

```php
'api' => [
    'max' => 120,
    'seconds' => 60,
    'key_by' => ['ip', 'user', 'route'],
],
```

### Admin API

```php
'admin_api' => [
    'max' => 60,
    'seconds' => 60,
    'key_by' => ['ip', 'user', 'route'],
],
```

### Login

```php
'login' => [
    'max' => 5,
    'seconds' => 600,
    'key_by' => ['ip', 'route'],
],
```

### Password Reset

```php
'password_reset' => [
    'max' => 3,
    'seconds' => 3600,
    'key_by' => ['ip', 'route'],
],
```

### OTP

```php
'otp' => [
    'max' => 3,
    'seconds' => 600,
    'key_by' => ['ip', 'user', 'route'],
],
```

### Export

```php
'export' => [
    'max' => 10,
    'seconds' => 3600,
    'key_by' => ['user', 'route'],
],
```

---

## 28. How This Feature Connects to Other Engines

| Engine | API security relationship |
|---|---|
| Secure Request Receiving | Rejects unsafe API requests before route code. |
| Authentication Strategy | Validates bearer tokens, sessions, signatures, and auth strategies. |
| Authorization Strategy | Ensures authenticated users can perform requested actions. |
| Token Revocation and Session Control | Blocks revoked tokens and stale sessions. |
| Data Protection | Masks and filters API response fields. |
| Database Governance | Ensures API queries are safe and tenant-scoped. |
| Safe Error Responses | Prevents technical API error leakage. |
| Memory Governance | Prevents large payload and response memory abuse. |
| Throughput Governance | Controls latency, overload, and backpressure. |
| Queue Engine | Defers long-running API work to background jobs. |
| Origin Protection | Prevents direct-origin and host spoofing API abuse. |
| Pentest Verification | Adds test coverage for brute force, token abuse, and API controls. |

---

## 29. Final Notes

API security should be layered. A strong production endpoint normally has:

```text
Request receiving checks
Rate limit policy
Authentication strategy
Token/session revocation check
Authorization policy
Tenant boundary
Input validation
Safe database access
Safe response filtering
Safe error handling
Audit event
Throughput/memory guard
Queue deferral for expensive work
```

Rate limiting is important, but it is only one part of API safety. The best results come from combining it with the rest of `mnb-secure-core` instead of using it as a standalone control.
