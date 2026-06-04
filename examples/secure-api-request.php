<?php
$config = require __DIR__ . '/bootstrap.php';

use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Auth\Stores\FileTokenStore;
use Mnb\SecurityCore\Http\Middleware\ApiTokenMiddleware;
use Mnb\SecurityCore\Http\Middleware\RateLimitMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\RateLimit\FileRateLimiter;

$tokens = new OpaqueTokenService(new FileTokenStore(__DIR__ . '/../storage/tokens/api_tokens.json'));
$limiter = new FileRateLimiter(__DIR__ . '/../storage/cache/rate_limits');
$request = Request::fromGlobals();

$pipeline = new MiddlewarePipeline([
    new RateLimitMiddleware($limiter, $config['limits']['api']['max'], $config['limits']['api']['seconds'], 'api'),
    new ApiTokenMiddleware($tokens),
]);
$response = $pipeline->handle($request, fn() => Response::json(['status' => true, 'message' => 'Secure API request accepted']));
$response->send();
