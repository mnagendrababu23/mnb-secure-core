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
