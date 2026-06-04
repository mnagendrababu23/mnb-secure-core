<?php
$config = require __DIR__ . '/bootstrap.php';

use Mnb\SecurityCore\Auth\Csrf;
use Mnb\SecurityCore\Http\Middleware\CsrfMiddleware;
use Mnb\SecurityCore\Http\Middleware\RequestSizeMiddleware;
use Mnb\SecurityCore\Http\Middleware\TrustedHostMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

$request = Request::fromGlobals();
$pipeline = new MiddlewarePipeline([
    new TrustedHostMiddleware($config['app']['trusted_hosts']),
    new RequestSizeMiddleware($config['limits']['request_max_bytes']),
    new CsrfMiddleware(new Csrf()),
]);

$response = $pipeline->handle($request, fn() => Response::text('Secure web request accepted'));
$response->send();
