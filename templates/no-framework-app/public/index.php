<?php
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Middleware\TrustedHostMiddleware;
use Mnb\SecurityCore\Http\Middleware\HttpsMiddleware;
use Mnb\SecurityCore\Http\Middleware\RequestSizeMiddleware;
use Mnb\SecurityCore\Http\Middleware\RateLimitMiddleware;

$boot = require __DIR__ . '/../app/security-bootstrap.php';
$config = $boot['config'];
$security = $boot['security'];
$request = Request::fromGlobals();

$pipeline = new MiddlewarePipeline([
    new TrustedHostMiddleware($config['app']['trusted_hosts']),
    new HttpsMiddleware($config['app']['force_https']),
    new RequestSizeMiddleware($config['limits']['request_max_bytes']),
    new RateLimitMiddleware($security->fileRateLimiter(), 120, 60, 'starter-web'),
]);

$response = $pipeline->handle($request, fn() => Response::text('Secure no-framework app is running.'));
$response->send();
