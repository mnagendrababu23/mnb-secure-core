<?php
/**
 * Slim 4 style integration example for mnb-secure-core v1.0.1.
 *
 * Slim is intentionally not a hard dependency of this library. Install it in your app:
 *
 *   composer require slim/slim slim/psr7
 */

require __DIR__ . '/../../autoload.php';

use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Auth\PermissionGuard;
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Env\EnvLoader;
use Mnb\SecurityCore\Http\Middleware\ApiTokenMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request as MnbRequest;
use Mnb\SecurityCore\Http\Response as MnbResponse;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Psr\Http\Message\ResponseInterface as PsrResponse;
use Psr\Http\Message\ServerRequestInterface as PsrRequest;
use Slim\Factory\AppFactory;

if (!class_exists(AppFactory::class)) {
    echo "Slim is not installed. Run: composer require slim/slim slim/psr7\n";
    return;
}

EnvLoader::load(__DIR__ . '/../../.env');
$config = require __DIR__ . '/../../config/security.php';

$kernel = new SecurityKernel($config);
$audit = $kernel->auditTrail();
$tokens = new OpaqueTokenService($kernel->tokenStore(), $audit);
$app = AppFactory::create();

$app->get('/health', function (PsrRequest $psrRequest, PsrResponse $psrResponse) use ($kernel, $config): PsrResponse {
    $mnbRequest = mnbRequestFromPsr($psrRequest, $config['app']['trusted_proxies'] ?? []);
    $pipeline = new MiddlewarePipeline([
        $kernel->requestTrustMiddleware(),
        $kernel->securityHeadersMiddleware(),
        $kernel->rateLimitMiddleware('api', 'slim.health'),
    ]);

    return psrResponseFromMnb(
        $pipeline->handle($mnbRequest, fn() => MnbResponse::json(['status' => true])),
        $psrResponse
    );
});

$app->get('/api/profile', function (PsrRequest $psrRequest, PsrResponse $psrResponse) use ($kernel, $tokens, $config): PsrResponse {
    $mnbRequest = mnbRequestFromPsr($psrRequest, $config['app']['trusted_proxies'] ?? []);
    $pipeline = new MiddlewarePipeline([
        $kernel->requestTrustMiddleware(),
        $kernel->securityHeadersMiddleware(),
        $kernel->rateLimitMiddleware('api', 'slim.profile'),
        new ApiTokenMiddleware($tokens),
    ]);

    $mnbResponse = $pipeline->handle($mnbRequest, function (MnbRequest $request): MnbResponse {
        $auth = PermissionGuard::requireScope($request, 'profile.read');

        return MnbResponse::json([
            'status' => true,
            'user_id' => $auth->id(),
            'scopes' => $auth->scopes(),
        ]);
    });

    return psrResponseFromMnb($mnbResponse, $psrResponse);
});

$app->post('/api/uploads/images', function (PsrRequest $psrRequest, PsrResponse $psrResponse) use ($kernel, $tokens, $audit, $config): PsrResponse {
    $mnbRequest = mnbRequestFromPsr($psrRequest, $config['app']['trusted_proxies'] ?? []);
    $pipeline = new MiddlewarePipeline([
        $kernel->requestTrustMiddleware(),
        $kernel->securityHeadersMiddleware(),
        $kernel->rateLimitMiddleware('api', 'slim.upload.images'),
        new ApiTokenMiddleware($tokens),
    ]);

    $mnbResponse = $pipeline->handle($mnbRequest, function (MnbRequest $request) use ($kernel, $audit, $psrRequest): MnbResponse {
        $auth = PermissionGuard::requireScope($request, 'files.upload');
        $uploadedFiles = $psrRequest->getUploadedFiles();
        $file = $uploadedFiles['file'] ?? null;

        if (!$file || $file->getError() !== UPLOAD_ERR_OK) {
            return MnbResponse::json(['status' => false, 'message' => 'Missing upload.'], 400);
        }

        $tmpPath = tempnam(sys_get_temp_dir(), 'mnb_upload_');
        if ($tmpPath === false) {
            return MnbResponse::json(['status' => false, 'message' => 'Unable to create temporary upload file.'], 500);
        }

        try {
            $file->moveTo($tmpPath);
            $stored = $kernel->secureFileManager(profile: 'images', audit: $audit)->storeFromPath(
                $tmpPath,
                $file->getClientFilename() ?: 'upload.bin',
                'images',
                ['user_id' => $auth->id()],
                SecurityAuditTrail::contextFromRequest($request, ['route' => 'slim.upload.images'])
            );

            return MnbResponse::json(['status' => true, 'file' => $stored], 201);
        } finally {
            @unlink($tmpPath);
        }
    });

    return psrResponseFromMnb($mnbResponse, $psrResponse);
});

$app->run();

function mnbRequestFromPsr(PsrRequest $request, array $trustedProxies = []): MnbRequest
{
    $server = $request->getServerParams();
    $headers = [];
    foreach ($request->getHeaders() as $name => $values) {
        $headers[$name] = implode(', ', $values);
    }

    $body = $request->getParsedBody();
    if (!is_array($body)) {
        $body = [];
    }

    return new MnbRequest(
        $request->getMethod(),
        $request->getUri()->getPath() ?: '/',
        $request->getQueryParams(),
        $body,
        $headers,
        $server,
        $trustedProxies
    );
}

function psrResponseFromMnb(MnbResponse $mnbResponse, PsrResponse $psrResponse): PsrResponse
{
    $psrResponse->getBody()->write($mnbResponse->body());
    foreach ($mnbResponse->headers() as $name => $value) {
        $psrResponse = $psrResponse->withHeader($name, $value);
    }

    return $psrResponse->withStatus($mnbResponse->status());
}

