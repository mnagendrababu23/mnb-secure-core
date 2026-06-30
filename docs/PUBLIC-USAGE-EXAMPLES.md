# Public Usage Examples

These examples are safe starting points for developers using `mnb-secure-core v1.0.1`.

## 1. Create the kernel

```php
use Mnb\SecurityCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

## 2. Build a request from globals

```php
$request = $kernel->requestFromGlobals();
```

This uses the request trust layer so trusted proxy configuration can affect real client IP, forwarded host, and forwarded proto handling.

## 3. Apply a safe middleware order

Recommended order:

```text
Request Trust → Security Headers → Rate Limit Policy → API Token Auth → Application Handler
```

Plain PHP example:

```php
use Mnb\SecurityCore\Http\Middleware\ApiTokenMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Response;

$tokens = $kernel->opaqueTokens();

$pipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->rateLimitMiddleware('api', 'api.profile'),
    new ApiTokenMiddleware($tokens),
]);

$response = $pipeline->handle($request, function ($request) {
    $auth = $request->attribute('auth');

    return Response::json([
        'ok' => true,
        'user_id' => $auth?->userId(),
    ]);
});
```

## 4. Require a scope

```php
use Mnb\SecurityCore\Auth\PermissionGuard;

PermissionGuard::requireScope($request, 'profile.read');
```

## 5. Use named rate-limit policies

```php
$apiLimiter = $kernel->rateLimitMiddleware('api', 'api.profile');
$loginLimiter = $kernel->rateLimitMiddleware('login', 'auth.login');
$exportLimiter = $kernel->rateLimitMiddleware('export', 'reports.export');
```

## 6. Use upload profiles

```php
$images = $kernel->secureFileManager(profile: 'images');
$result = $images->accept($_FILES['avatar'], 'avatars');
```

Built-in profiles:

```text
default, images, documents, videos, archives, strict
```

## 7. Record structured audit events

```php
$audit = $kernel->auditTrail();

$audit->adminAction(
    'settings.updated',
    ['user_id' => 1],
    ['section' => 'security_headers']
);

$audit->sensitiveAction(
    'backup.exported',
    ['user_id' => 1],
    ['backup_id' => 'backup-2026-06-30']
);
```

## 8. Run doctor in CI or deployment checks

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
```

`doctor` returns JSON diagnostics and exits non-zero when blocking issues exist.

## 9. Issue a first token for local bootstrap

```bash
php bin/mnb-secure bootstrap:first-token demo-admin admin:*,profile.read,uploads.write 86400 --write-demo-user
```

The plain token is shown once. Store it safely and do not commit it.

## More complete examples

- `examples/framework-integration/plain-php-api.php`
- `examples/framework-integration/slim-app.php`
- `examples/framework-integration/doctor-workflow.php`
- `examples/quickstart/bootstrap-first-token.php`


## Auto audit, CORS, and suggestions add-on

Additional v1.0.1 additions include:

- `AutoAuditLogger` and `AutoAuditMiddleware` for safe automatic add/edit/delete/submission/email/auth/password-verification audit events.
- Improved `CorsMiddleware` and `CorsPolicy` with credential-safe origin reflection, preflight validation, exposed headers, origin patterns, max-age, and private-network opt-in.
- `AutoSuggestionEngine` for suggestions from typed words or pasted PHP code snippets.
- Kernel helpers: `autoAuditLogger()`, `autoAuditMiddleware()`, `corsMiddleware()`, and `suggestionEngine()`.

## 10. Validate and sanitize request input

```php
$validation = $kernel->inputValidationMiddleware([
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
]);
```

Use it before controllers so handlers receive normalized input:

```php
$name = $request->input('name');
$email = $request->validated('email');
```

This layer complements, but does not replace, prepared SQL, output escaping, CSRF protection, CSP, authorization, and business-rule checks.

## Trust Zone Boundary Engine

Use named trust boundary policies after authentication for sensitive resources. A boundary decision connects the resolved trust zone, resource data class, requested action, tenant context, permissions/scopes/roles, optional output filtering, and audit logging.

```php
use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

$request = $request
    ->withAttribute(AuthContext::ATTRIBUTE, $auth)
    ->withAttribute('tenant_context', new TenantContext(
        userId: 15,
        schoolId: 10,
        branchId: 5,
        academicYearId: 2026,
        permissions: ['student.view']
    ));

$pipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->corsMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->inputValidationMiddleware(),
    $kernel->rateLimitMiddleware('api', 'students.read'),
    $kernel->trustBoundaryMiddleware(
        'students.read',
        resourceResolver: fn (Request $request) => ['school_id' => 10],
        action: 'read',
        dataClass: 'sensitive',
        resourceName: 'students'
    ),
]);
```

Direct decision usage:

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

Safe output filtering:

```php
$record = ['id' => 44, 'name' => 'Ravi', 'parent_phone' => '9876543210', 'password_hash' => 'hash'];
$safe = $kernel->trustBoundaryRegistry()->filterForZone('students', $record, 'school_admin');
```

## Secure request receiving profile

Use a named receiver when you want the library to assemble the request intake stack in the recommended order.

```php
$request = $kernel->requestFromGlobals();

$response = $kernel->secureRequestReceiver('api_authenticated')->handle(
    $request,
    fn (Request $request) => Response::json([
        'status' => true,
        'request_id' => $request->attribute('request_id'),
        'user_id' => $request->attribute('auth')?->id(),
    ])
);
```

A small custom profile can be registered in `config/security.php`:

```php
'api_profile' => [
    'methods' => ['POST'],
    'max_bytes' => 1048576,
    'content_types' => ['application/json'],
    'rate_policy' => 'api',
    'auth' => 'bearer',
    'input_validation' => true,
    'auto_audit' => true,
]
```

Webhook signature receiving:

```php
$raw = $request->attribute('raw_body');
$middleware = $kernel->webhookSignatureMiddleware([
    'secret' => $_ENV['WEBHOOK_SECRET'],
]);
```

## Authentication Strategy Engine

```php
$auth = $kernel->authenticationMiddleware('api_bearer');
$response = (new MiddlewarePipeline([$auth]))->handle($request, $controller);
```

Optional bearer authentication allows guests but attaches an `AuthContext` either way:

```php
$auth = $kernel->authenticationMiddleware('optional_bearer');
```

A login flow can remain framework-independent by implementing `UserProviderInterface`:

```php
$result = $kernel->authWorkflow($userProvider)->login(
    identifier: $email,
    password: $password,
    scopes: ['profile.read']
);

if ($result->failed()) {
    return Response::json(['message' => 'Invalid credentials'], 401);
}

return Response::json([
    'token' => $result->plainToken(),
    'expires_at' => $result->metadata('expires_at'),
]);
```

## Authorization Strategy Engine

Use named authorization policies when a route needs roles, scopes, permissions, tenant ownership, trust-boundary checks, and field filtering in one decision.

```php
$decision = $kernel->authorizationRegistry()->decide(
    policyName: 'students.update',
    request: $request,
    resource: ['id' => 44, 'school_id' => 10],
    action: 'update',
    resourceName: 'students',
    dataClass: 'sensitive'
);

if ($decision->denied()) {
    return Response::json(['message' => $decision->safeMessage()], $decision->statusCode());
}
```

Middleware usage:

```php
$middleware = $kernel->authorizationMiddleware(
    'students.update',
    resourceResolver: fn (Request $request) => ['school_id' => 10],
    action: 'update',
    resourceName: 'students',
    dataClass: 'sensitive'
);
```

Field-level read filtering:

```php
$safe = $kernel->authorizationRegistry()->filterReadableFields(
    'students.read',
    $request,
    $studentRecord
);
```

Field-level write filtering:

```php
$clean = $kernel->authorizationRegistry()->filterWritableFields(
    'students.update',
    $request,
    $request->body()
);
```

Secure request receiving profiles can reference an authorization policy:

```php
'api_student_update' => [
    'methods' => ['PATCH'],
    'content_types' => ['application/json'],
    'auth_strategy' => 'api_bearer',
    'authorization' => 'students.update',
    'input_validation' => true,
]
```

## Data Protection Strategy

```php
$registry = $kernel->dataProtectionRegistry();

$stored = $registry->protectForStorage('students', [
    'name' => 'Ravi',
    'email' => 'ravi@example.com',
    'parent_phone' => '9876543210',
]);

$response = $registry->protectForResponse('students', $stored, $request);
$logSafe = $registry->protectForLog('students', $stored);
$csv = $kernel->safeCsvExporter()->export('students', [$stored]);
```

Use `data_protection.resources.*.fields` to define field classes, encryption, search hashes, masks, export behavior, and log rules.

## Web Security Controls

```php
$web = $kernel->webSecurityControls('browser_form');

echo $web->escapeHtml($name);
$body = $web->sanitizeHtml($request->input('body'));
$redirect = $web->safeRedirect($request->input('next'), '/dashboard');
$cookie = $web->cookies()->make('__Host-session_hint', $hint, ['max_age' => 600]);
$signed = $web->signedUrl()->sign('/download/invoice.pdf', ['invoice_id' => 42], time() + 900, 'download');
```
