# Error Handling, Safe Error Responses, and Hidden Technical Logs

**Package:** `mnb/mnb-secure-core`  
**Version line:** `MNB Secure Core v1.0.1`  
**Feature area:** Exception governance, safe frontend errors, hidden technical logs, redaction, fingerprinting, and escalation.

---

## 1. Purpose

The **Error Handling, Safe Error Responses, and Hidden Technical Logs** module protects an application from accidental technical disclosure while still giving developers enough internal diagnostic detail to fix problems.

A secure application must never expose raw backend details to users, browsers, API clients, crawlers, or attackers.

Unsafe examples include:

```text
SQLSTATE[HY000]
PDOException stack trace
/var/www/app/src/Controller/UserController.php:84
APP_KEY=...
DB_PASSWORD=...
Bearer eyJ...
Undefined index password_hash
```

Instead, public responses should be safe, predictable, and support request correlation:

```json
{
  "status": false,
  "message": "Something went wrong. Please try again later.",
  "error": {
    "code": "INTERNAL_ERROR",
    "request_id": "req_01HX..."
  }
}
```

Internally, the same error can be logged with sanitized technical context:

```json
{
  "request_id": "req_01HX...",
  "exception_class": "PDOException",
  "safe_message": "SQLSTATE[HY000] [redacted]",
  "file": "[app]/src/Repository/UserRepository.php",
  "line": 84,
  "fingerprint": "err_..."
}
```

---

## 2. What this module protects

This module helps prevent:

```text
Error disclosure
Debug leakage
Stack trace exposure
Sensitive log exposure
PII leakage in logs
Unsafe validation error messages
Missing request correlation ID
Repeated unmonitored 500 errors
Security exceptions without escalation
Raw exception exposure in APIs
Unsafe HTML error pages
```

It is designed to support:

```text
API applications
Traditional PHP apps
Admin panels
Multi-tenant systems
Background jobs
Webhook endpoints
CLI tooling
Production release gates
```

---

## 3. Main components

Depending on the installed v1.0.1 build, the error module can include these classes:

```text
Mnb\SecureCore\Errors\ErrorContext
Mnb\SecureCore\Errors\ErrorResponseFactory
Mnb\SecureCore\Errors\ExceptionMapper
Mnb\SecureCore\Errors\SafeErrorHandler
Mnb\SecureCore\Http\Middleware\ErrorHandlingMiddleware

Mnb\SecureCore\Errors\ErrorPolicy
Mnb\SecureCore\Errors\ErrorDefinition
Mnb\SecureCore\Errors\ErrorCatalog
Mnb\SecureCore\Errors\ErrorCodeRegistry
Mnb\SecureCore\Errors\SafeErrorEvent
Mnb\SecureCore\Errors\ErrorEventFactory
Mnb\SecureCore\Errors\ErrorLogSanitizer
Mnb\SecureCore\Errors\StackTraceSanitizer
Mnb\SecureCore\Errors\ValidationErrorNormalizer
Mnb\SecureCore\Errors\ProblemDetailsResponseFactory
Mnb\SecureCore\Errors\SafeErrorPageRenderer
Mnb\SecureCore\Errors\ErrorFingerprint
Mnb\SecureCore\Errors\ErrorDeduplicator
Mnb\SecureCore\Errors\ErrorEscalationPolicy
Mnb\SecureCore\Errors\ErrorAlertDispatcher
Mnb\SecureCore\Errors\ErrorAuditEvents
```

Exception classes commonly mapped by the module:

```text
Mnb\SecureCore\Exceptions\AppException
Mnb\SecureCore\Exceptions\AuthorizationException
Mnb\SecureCore\Exceptions\BusinessRuleException
Mnb\SecureCore\Exceptions\NotFoundException
Mnb\SecureCore\Exceptions\ValidationException
Mnb\SecureCore\Exceptions\SecurityException
Mnb\SecureCore\Exceptions\MemoryLimitExceededException
Mnb\SecureCore\Exceptions\ThroughputLimitExceededException
```

---

## 4. Recommended configuration

Add or review the `errors` block in `config/security.php`.

```php
<?php

return [
    'errors' => [
        'enabled' => true,
        'hide_frontend_errors' => true,
        'response_format' => 'auto', // auto, json, html, text, problem_json
        'default_public_message' => 'Something went wrong. Please try again later.',
        'include_request_id' => true,
        'log_channel' => 'errors',

        'debug' => [
            'allow_in_production' => false,
            'include_stack_trace' => false,
            'include_file_line' => false,
            'max_stack_frames' => 8,
        ],

        'redaction' => [
            'enabled' => true,
            'redact_secrets' => true,
            'redact_paths' => true,
            'redact_pii' => true,
            'replacement' => '[redacted]',
        ],

        'validation' => [
            'normalize_field_names' => true,
            'hide_internal_fields' => true,
            'public_field_map' => [
                'password_hash' => 'password',
                'tenant_internal_id' => 'organization',
                'db_school_id' => 'school',
            ],
        ],

        'fingerprinting' => [
            'enabled' => true,
            'include_route' => true,
            'include_exception_class' => true,
            'include_error_code' => true,
        ],

        'escalation' => [
            'enabled' => true,
            'critical_error_threshold' => 5,
            'window_seconds' => 300,
            'alert_on_security_exception' => true,
            'alert_on_repeated_500' => true,
        ],
    ],
];
```

Production config should be stricter:

```php
'errors' => [
    'hide_frontend_errors' => true,
    'response_format' => 'auto',
    'include_request_id' => true,

    'debug' => [
        'allow_in_production' => false,
        'include_stack_trace' => false,
        'include_file_line' => false,
    ],

    'redaction' => [
        'enabled' => true,
        'redact_secrets' => true,
        'redact_paths' => true,
        'redact_pii' => true,
    ],
],
```

---

## 5. Basic usage with SecurityKernel

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Mnb\SecureCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);

$errorHandler = $kernel->safeErrorHandler();
```

Example wrapping a route or controller:

```php
try {
    // application logic
    throw new RuntimeException('SQLSTATE[HY000]: Access denied for user root');
} catch (Throwable $e) {
    $response = $kernel->safeErrorHandler()->handle($e, [
        'path' => '/api/users',
        'method' => 'GET',
        'format' => 'json',
    ]);

    http_response_code($response['status_code'] ?? 500);
    header('Content-Type: application/json');
    echo json_encode($response['body']);
}
```

Expected public output:

```json
{
  "status": false,
  "message": "Something went wrong. Please try again later.",
  "error": {
    "code": "INTERNAL_ERROR",
    "request_id": "req_..."
  }
}
```

---

## 6. Middleware usage

Place error handling middleware early in the HTTP pipeline so it can catch exceptions thrown by downstream middleware and controllers.

Recommended order:

```text
1. ErrorHandlingMiddleware
2. RequestTrustMiddleware
3. ServerIdentityProtectionMiddleware
4. TrustedHostMiddleware
5. ThroughputMiddleware
6. Memory/resource guard middleware
7. RequestReceivingMiddleware
8. Authentication middleware
9. Authorization middleware
10. CSRF / API / route middleware
11. Controller / route handler
```

Example:

```php
use Mnb\SecureCore\Http\Middleware\ErrorHandlingMiddleware;

$errorMiddleware = new ErrorHandlingMiddleware(
    safeErrorHandler: $kernel->safeErrorHandler()
);

$response = $errorMiddleware->handle($request, $next);
```

For framework integrations, adapt the middleware signature to the framework PSR-15, Slim, Laravel, Symfony, or custom pipeline style.

---

## 7. Exception mapping

The error module maps internal exceptions to safe public responses.

| Exception type | HTTP status | Public code | Public behavior |
|---|---:|---|---|
| `ValidationException` | 422 | `VALIDATION_FAILED` | Shows safe validation errors |
| `AuthorizationException` | 403 | `FORBIDDEN` | Hides internal permission logic |
| `NotFoundException` | 404 | `NOT_FOUND` | Hides whether protected records exist |
| `SecurityException` | 403 | `SECURITY_BLOCKED` | Can trigger security escalation |
| `MemoryLimitExceededException` | 503 | `RESOURCE_LIMIT_EXCEEDED` | Safe resource failure message |
| `ThroughputLimitExceededException` | 429/503 | `THROUGHPUT_LIMIT_EXCEEDED` | Backpressure-safe response |
| Unknown `Throwable` | 500 | `INTERNAL_ERROR` | Generic frontend response |

Example custom app exception:

```php
use Mnb\SecureCore\Exceptions\BusinessRuleException;

throw new BusinessRuleException(
    message: 'Student cannot be promoted before final review.',
    publicMessage: 'This action is not allowed until final review is completed.',
    code: 'PROMOTION_REVIEW_REQUIRED'
);
```

Public response:

```json
{
  "status": false,
  "message": "This action is not allowed until final review is completed.",
  "error": {
    "code": "PROMOTION_REVIEW_REQUIRED",
    "request_id": "req_..."
  }
}
```

---

## 8. Error catalog and error codes

Use stable error codes instead of exposing raw exception messages.

Common codes:

```text
AUTH_REQUIRED
FORBIDDEN
NOT_FOUND
VALIDATION_FAILED
RATE_LIMITED
UPLOAD_BLOCKED
CSRF_FAILED
SECURITY_BLOCKED
RESOURCE_LIMIT_EXCEEDED
THROUGHPUT_LIMIT_EXCEEDED
INTERNAL_ERROR
SERVICE_UNAVAILABLE
```

Example catalog usage:

```php
$definition = $kernel->errorCatalog()->get('VALIDATION_FAILED');

return [
    'status' => false,
    'message' => $definition->publicMessage(),
    'error' => [
        'code' => $definition->code(),
        'request_id' => $kernel->errorContext()->requestId(),
    ],
];
```

Benefits:

```text
Consistent API behavior
Easy frontend translation
Stable docs for API consumers
Cleaner monitoring and alert grouping
Reduced accidental technical disclosure
```

---

## 9. Safe validation errors

Validation errors are useful, but internal field names should not leak to users.

Unsafe:

```json
{
  "tenant_internal_id": ["tenant_internal_id is required"],
  "password_hash": ["password_hash is invalid"]
}
```

Safe:

```json
{
  "organization": ["Organization is required"],
  "password": ["Password is invalid"]
}
```

Example:

```php
$normalizer = $kernel->validationErrorNormalizer();

$publicErrors = $normalizer->normalize([
    'password_hash' => ['password_hash is too short'],
    'tenant_internal_id' => ['tenant_internal_id is required'],
]);
```

Output:

```php
[
    'password' => ['Password is too short'],
    'organization' => ['Organization is required'],
]
```

Recommended rule: validation errors may show user-facing field names, but should never show database columns, table names, internal IDs, or hidden system fields.

---

## 10. Problem+JSON API responses

The module can support RFC 7807-style `application/problem+json` responses.

Example:

```php
$response = $kernel->problemDetailsResponseFactory()->create([
    'type' => 'https://errors.example.com/validation-failed',
    'title' => 'Validation failed.',
    'status' => 422,
    'code' => 'VALIDATION_FAILED',
    'request_id' => 'req_...',
    'details' => [
        'email' => ['Email is required.'],
    ],
]);
```

Response:

```json
{
  "type": "https://errors.example.com/validation-failed",
  "title": "Validation failed.",
  "status": 422,
  "code": "VALIDATION_FAILED",
  "request_id": "req_...",
  "details": {
    "email": ["Email is required."]
  }
}
```

Use `problem_json` when building public APIs that benefit from standard machine-readable error details.

---

## 11. Safe HTML error pages

For browser routes, use safe HTML pages instead of raw PHP/Apache/Nginx errors.

```php
$html = $kernel->safeErrorPageRenderer()->render([
    'status' => 404,
    'title' => 'Page not found',
    'message' => 'The page you are looking for could not be found.',
    'request_id' => 'req_...',
]);

http_response_code(404);
header('Content-Type: text/html; charset=UTF-8');
echo $html;
```

Safe HTML pages should:

```text
Escape all dynamic content
Include request ID
Avoid stack traces
Avoid file paths
Avoid server/framework details
Avoid debug information
Avoid raw exception messages
```

---

## 12. Hidden technical logs

The user receives safe output. Developers receive internal diagnostics in protected logs.

Example logging flow:

```php
try {
    $service->run();
} catch (Throwable $e) {
    $event = $kernel->errorEventFactory()->fromThrowable($e, [
        'path' => '/api/export',
        'method' => 'POST',
        'user_id' => $userId,
        'tenant_id' => $tenantId,
    ]);

    $safeLog = $kernel->errorLogSanitizer()->sanitize($event->toArray());

    $kernel->logger()->error('Application error', $safeLog);

    return $kernel->errorResponseFactory()->fromEvent($event);
}
```

Technical logs should be protected by:

```text
File permissions
Log rotation
Retention policy
Secret redaction
PII redaction
Path redaction
Tamper-evident audit trail where required
No public web access
```

---

## 13. Log redaction

The module should redact values such as:

```text
password
password_hash
secret
token
api_key
authorization
cookie
set-cookie
bearer tokens
APP_KEY
DB_PASSWORD
JWT_SECRET
private filesystem paths
private IP addresses where configured
```

Example:

```php
$sanitized = $kernel->errorLogSanitizer()->sanitize([
    'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIs...',
    'password' => 'secret123',
    'file' => '/var/www/app/config/security.php',
]);
```

Output:

```php
[
    'Authorization' => '[redacted]',
    'password' => '[redacted]',
    'file' => '[app]/config/security.php',
]
```

---

## 14. Stack trace sanitization

Stack traces are useful during development, but dangerous in production.

Use stack trace sanitizer to:

```text
Limit stack frames
Remove function arguments
Redact secrets
Normalize absolute paths
Collapse vendor paths
Remove query strings
Remove tokens
```

Example:

```php
$trace = $kernel->stackTraceSanitizer()->sanitize($throwable);
```

Recommended production policy:

```text
Do not show stack traces publicly
Do not include stack traces in API responses
Keep sanitized traces only in internal logs
Limit retained stack frame count
Never log secrets from arguments
```

---

## 15. Error fingerprinting and deduplication

Fingerprinting groups repeated errors without storing sensitive values.

Typical fingerprint input:

```text
exception class
safe mapped error code
route pattern
sanitized message hash
```

Example:

```php
$fingerprint = $kernel->errorFingerprint()->create([
    'exception_class' => PDOException::class,
    'error_code' => 'INTERNAL_ERROR',
    'route' => 'GET /api/users',
    'sanitized_message' => 'SQLSTATE[HY000] [redacted]',
]);
```

Use cases:

```text
Group repeated 500 errors
Detect repeated blocked attacks
Reduce alert noise
Create remediation tickets
Monitor release regressions
```

---

## 16. Escalation policy

Some errors should become security or operations alerts.

Examples:

```text
Repeated 500 errors from same route
SecurityException thrown repeatedly
SSRF blocked repeatedly
Runtime command blocked
Schema alteration blocked
Token replay detected
Queue dead-letter growth
Audit integrity failure
```

Example:

```php
$decision = $kernel->errorEscalationPolicy()->evaluate([
    'code' => 'SECURITY_BLOCKED',
    'fingerprint' => $fingerprint,
    'occurrences' => 7,
    'window_seconds' => 300,
]);

if ($decision->shouldAlert()) {
    $kernel->errorAlertDispatcher()->dispatch($decision);
}
```

Escalation should integrate with:

```text
Logging
Audit trail
Monitoring alerts
Incident response
Security verification
Release gate
```

---

## 17. Integration with other engines

### Request receiving

Invalid or unsafe requests should return safe errors:

```text
REQUEST_TOO_LARGE
INVALID_CONTENT_TYPE
WEBHOOK_SIGNATURE_INVALID
CSRF_FAILED
```

### Authentication and token/session control

Auth failures should not reveal whether a user exists:

```text
Invalid email/password → generic login error
Revoked token → safe unauthenticated error
Expired session → safe session expired response
```

### Authorization

Authorization errors should not reveal hidden resources:

```text
Forbidden tenant record → 404 or 403 based on policy
No permission → safe forbidden response
```

### Database governance

Database errors should never expose SQL, schema names, table names, or connection details.

### File security

Upload failures should expose safe reason codes, not internal scanner details.

### Runtime and outbound network security

Blocked command execution or SSRF attempts should be logged internally and shown safely.

### Queue/background jobs

Job failure responses should expose job status and safe error code, not raw exception traces.

---

## 18. CLI commands

Useful error-handling commands:

```bash
php bin/mnb-secure errors:policy
php bin/mnb-secure errors:catalog
php bin/mnb-secure errors:simulate internal
php bin/mnb-secure errors:simulate validation
php bin/mnb-secure errors:simulate security
php bin/mnb-secure errors:fingerprint
php bin/mnb-secure errors:check-production
```

Examples:

```bash
php bin/mnb-secure errors:simulate internal
```

Expected behavior:

```text
- Generates a simulated internal exception
- Shows safe public response
- Confirms technical details are hidden
- Shows sanitized internal log structure
```

```bash
php bin/mnb-secure errors:catalog
```

Expected behavior:

```text
- Lists stable public error codes
- Shows HTTP status mapping
- Shows public messages
```

---

## 19. Demo

Run the demo:

```bash
php demos/34-safe-error-response-technical-log-isolation-engine.php
```

The demo should show:

```text
1. Error policy loaded
2. Internal exception mapped to safe frontend response
3. Request ID included
4. Technical details hidden from frontend
5. Technical details logged internally
6. Secrets redacted from logs
7. Stack trace sanitized
8. Validation errors normalized
9. Problem+JSON response generated
10. HTML error page rendered safely
11. Error fingerprint generated
12. Repeated error deduplicated
13. Security error escalated
14. Vulnerability matrix coverage improved
```

---

## 20. Testing examples

### Internal error should hide SQLSTATE

```php
public function testInternalErrorHidesSqlState(): void
{
    $handler = $this->kernel->safeErrorHandler();

    $response = $handler->handle(
        new RuntimeException('SQLSTATE[HY000]: Access denied for user root'),
        ['format' => 'json']
    );

    $json = json_encode($response);

    $this->assertStringNotContainsString('SQLSTATE', $json);
    $this->assertStringNotContainsString('root', $json);
    $this->assertStringContainsString('INTERNAL_ERROR', $json);
}
```

### Validation field names should normalize

```php
public function testValidationFieldNamesAreNormalized(): void
{
    $normalizer = $this->kernel->validationErrorNormalizer();

    $errors = $normalizer->normalize([
        'password_hash' => ['password_hash is invalid'],
        'tenant_internal_id' => ['tenant_internal_id is required'],
    ]);

    $this->assertArrayHasKey('password', $errors);
    $this->assertArrayHasKey('organization', $errors);
    $this->assertArrayNotHasKey('password_hash', $errors);
    $this->assertArrayNotHasKey('tenant_internal_id', $errors);
}
```

### Log sanitizer should redact bearer tokens

```php
public function testBearerTokenIsRedacted(): void
{
    $sanitizer = $this->kernel->errorLogSanitizer();

    $result = $sanitizer->sanitize([
        'Authorization' => 'Bearer abc.def.ghi',
    ]);

    $this->assertSame('[redacted]', $result['Authorization']);
}
```

### Fingerprint should not include secrets

```php
public function testFingerprintDoesNotIncludeSecrets(): void
{
    $fingerprint = $this->kernel->errorFingerprint()->create([
        'exception_class' => RuntimeException::class,
        'error_code' => 'INTERNAL_ERROR',
        'route' => '/api/test',
        'sanitized_message' => 'Token [redacted] failed',
    ]);

    $this->assertStringNotContainsString('abc.def.ghi', $fingerprint);
}
```

---

## 21. Production checklist

Before production, verify:

```text
APP_DEBUG=false
APP_ENV=production
errors.hide_frontend_errors=true
errors.debug.allow_in_production=false
errors.debug.include_stack_trace=false
errors.debug.include_file_line=false
errors.redaction.enabled=true
errors.redaction.redact_secrets=true
errors.redaction.redact_paths=true
errors.redaction.redact_pii=true
errors.include_request_id=true
error logs are outside public web root
log files have restricted permissions
log rotation is configured
retention policy is configured
monitoring alerts are configured
security exceptions escalate
repeated 500 errors escalate
validation errors do not expose internal field names
HTML error pages escape output
problem+JSON responses do not leak details
```

Run:

```bash
php bin/mnb-secure errors:check-production
php bin/mnb-secure config:validate
php bin/mnb-secure production:readiness
php bin/mnb-secure final:gate
```

---

## 22. Common mistakes

### Mistake: showing raw exception message to users

Bad:

```php
echo $exception->getMessage();
```

Good:

```php
return $kernel->safeErrorHandler()->handle($exception, ['format' => 'json']);
```

### Mistake: enabling debug in production

Bad:

```env
APP_ENV=production
APP_DEBUG=true
```

Good:

```env
APP_ENV=production
APP_DEBUG=false
```

### Mistake: logging full request headers

Bad:

```php
$logger->error('Request failed', $request->headers->all());
```

Good:

```php
$logger->error(
    'Request failed',
    $kernel->errorLogSanitizer()->sanitize($request->headers->all())
);
```

### Mistake: exposing internal validation fields

Bad:

```json
{"password_hash": ["password_hash is required"]}
```

Good:

```json
{"password": ["Password is required"]}
```

### Mistake: storing logs publicly

Bad:

```text
public/logs/error.log
```

Good:

```text
storage/logs/error.log
```

and block web access to storage directories.

---

## 23. Recommended route-level behavior

| Situation | Public response | Internal log |
|---|---|---|
| Validation failure | 422 with safe fields | Validation details, redacted |
| Unauthenticated | 401 generic | Auth context, no secrets |
| Unauthorized | 403 or 404 by policy | Permission/resource context |
| CSRF failure | 419/403 safe message | CSRF event |
| Rate limited | 429 safe message | Rate limit key hash |
| Upload blocked | 400/415 safe reason | Scanner/validator details |
| SSRF blocked | 403 safe message | URL host/IP redacted as needed |
| Command blocked | 403/500 safe message | Command name, no raw secrets |
| Internal crash | 500 generic | Sanitized exception details |

---

## 24. Best practices

```text
Use stable error codes.
Always include request IDs.
Never expose stack traces publicly.
Never expose raw SQL errors publicly.
Never expose file paths publicly.
Never log secrets or tokens.
Normalize validation fields.
Use problem+JSON for APIs when useful.
Use safe HTML error pages for browser routes.
Escalate repeated internal errors.
Escalate security exceptions.
Use fingerprinting for alert grouping.
Keep logs outside public web root.
Protect logs with retention and access controls.
```

---

## 25. Summary

The **Error Handling, Safe Error Responses, and Hidden Technical Logs** module makes application failure safe by separating public error behavior from internal diagnostics.

It ensures:

```text
Users receive clean, safe, consistent error responses.
Developers receive useful sanitized logs.
Attackers do not receive technical details.
Validation errors avoid internal field disclosure.
Stack traces and paths are hidden in production.
Repeated and security-sensitive errors can escalate.
Every error can be correlated with a request ID.
```

Use this module early in the middleware pipeline and keep production debug disabled. It is one of the most important final layers for preventing information disclosure in real applications.
