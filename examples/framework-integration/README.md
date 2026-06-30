# Framework Integration Examples

These examples show how to wire **mnb-secure-core v1.0.1** into real applications without changing the library internals.

They are intentionally small and dependency-light:

- `plain-php-api.php` shows a native PHP front controller with request trust, security headers, rate-limit policies, API token auth, auth context, upload profiles, and structured audit logging.
- `slim-app.php` shows a Slim 4 style integration bridge. Slim is optional and is not required by this package.
- `doctor-workflow.php` shows how to run the same checks behind `php bin/mnb-secure doctor` from application code or CI.

## Safe order for web middleware

Recommended order for HTTP requests:

```php
$request = $kernel->requestFromGlobals();

$pipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->rateLimitMiddleware('api', 'api.profile'),
    new ApiTokenMiddleware($tokens),
]);
```

Why this order:

1. **Request trust** rejects spoofed forwarded headers before IP/rate/security decisions.
2. **Security headers** wraps every successful/blocked response consistently.
3. **Rate policies** apply per-route/per-user/per-IP throttling before expensive work.
4. **API token auth** exposes `AuthContext` for downstream permission checks.

## Auth context usage

```php
use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Auth\PermissionGuard;

$auth = $request->attribute(AuthContext::ATTRIBUTE);
PermissionGuard::requireScope($auth, 'profile.read');

$userId = $auth->id();
```

Legacy attributes are still available:

```php
$userId = $request->attribute('auth_user_id');
$scopes = $request->attribute('auth_scopes');
```

## Upload profile usage

```php
$files = $kernel->secureFileManager(profile: 'images', audit: $audit);
$stored = $files->storeFromPath(
    $_FILES['file']['tmp_name'],
    $_FILES['file']['name'],
    'avatars',
    ['user_id' => $auth->id()],
    SecurityAuditTrail::contextFromRequest($request)
);
```

Available built-in profiles:

```text
default, images, documents, videos, archives, strict
```

## Doctor workflow

Run locally or in CI:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure check:production
php bin/mnb-secure doctor
```

`doctor` exits with a non-zero status when blocking issues are found. That is expected and useful for CI gates.
