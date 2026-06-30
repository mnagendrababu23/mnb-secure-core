<?php
/**
 * Plain PHP integration example for mnb-secure-core v1.0.1.
 *
 * Example routes:
 * - GET  /health
 * - GET  /api/profile        requires Bearer token with profile.read scope
 * - POST /api/upload/avatar  requires Bearer token with files.upload scope
 */

require __DIR__ . '/../../autoload.php';

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Auth\PermissionGuard;
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Env\EnvLoader;
use Mnb\SecurityCore\Exceptions\AuthorizationException;
use Mnb\SecurityCore\Exceptions\SecurityException;
use Mnb\SecurityCore\Http\Middleware\ApiTokenMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

EnvLoader::load(__DIR__ . '/../../.env');
$config = require __DIR__ . '/../../config/security.php';

$kernel = new SecurityKernel($config);
$audit = $kernel->auditTrail();
$tokens = new OpaqueTokenService($kernel->tokenStore(), $audit);
$request = $kernel->requestFromGlobals();

$publicPipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->rateLimitMiddleware('api', 'public.health'),
]);

$apiPipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->rateLimitMiddleware('api', routeName($request)),
    new ApiTokenMiddleware($tokens),
]);

try {
    if ($request->method() === 'GET' && $request->path() === '/health') {
        $response = $publicPipeline->handle($request, fn() => Response::json([
            'status' => true,
            'service' => 'plain-php-api',
        ]));
        $response->send();
        return;
    }

    $response = $apiPipeline->handle($request, function (Request $request) use ($kernel, $audit): Response {
        $auth = PermissionGuard::requireAuthenticated($request);

        if ($request->method() === 'GET' && $request->path() === '/api/profile') {
            PermissionGuard::requireScope($auth, 'profile.read');

            return Response::json([
                'status' => true,
                'user_id' => $auth->id(),
                'scopes' => $auth->scopes(),
            ]);
        }

        if ($request->method() === 'POST' && $request->path() === '/api/upload/avatar') {
            PermissionGuard::requireScope($auth, 'files.upload');

            if (!isset($_FILES['file']) || !is_array($_FILES['file'])) {
                return Response::json(['status' => false, 'message' => 'Missing file upload.'], 400);
            }

            $upload = $_FILES['file'];
            if (($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                return Response::json(['status' => false, 'message' => 'Upload failed before validation.'], 400);
            }

            $files = $kernel->secureFileManager(profile: 'images', audit: $audit);
            $stored = $files->storeFromPath(
                (string)$upload['tmp_name'],
                (string)$upload['name'],
                'avatars',
                ['user_id' => $auth->id()],
                SecurityAuditTrail::contextFromRequest($request, ['route' => 'api.upload.avatar'])
            );

            return Response::json([
                'status' => true,
                'file' => $stored,
            ], 201);
        }

        return Response::json(['status' => false, 'message' => 'Route not found.'], 404);
    });

    $response->send();
} catch (AuthorizationException $e) {
    Response::json(['status' => false, 'message' => 'Forbidden.'], 403)->send();
} catch (SecurityException $e) {
    Response::json(['status' => false, 'message' => $e->getMessage()], 400)->send();
} catch (Throwable $e) {
    $audit->sensitiveAction('plain_php_api.unhandled_exception', [], SecurityAuditTrail::contextFromRequest($request), [
        'exception' => $e::class,
    ]);

    Response::json(['status' => false, 'message' => 'Internal server error.'], 500)->send();
}

function routeName(Request $request): string
{
    return match ($request->method() . ' ' . $request->path()) {
        'GET /api/profile' => 'api.profile',
        'POST /api/upload/avatar' => 'api.upload.avatar',
        default => 'api.unknown',
    };
}
