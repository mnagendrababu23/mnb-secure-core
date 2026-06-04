<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Middleware\TrustedHostMiddleware;
use Mnb\SecurityCore\Http\Middleware\HttpsMiddleware;
use Mnb\SecurityCore\Http\Middleware\RequestSizeMiddleware;
use Mnb\SecurityCore\Http\Middleware\RateLimitMiddleware;
use Mnb\SecurityCore\RateLimit\FileRateLimiter;

demo_title('02. Secure Request Receiving Strategy');

$limiter = new FileRateLimiter(demo_storage_path('rate-limits'));
$pipeline = new MiddlewarePipeline([
    new TrustedHostMiddleware(['school.local']),
    new HttpsMiddleware(true),
    new RequestSizeMiddleware(1024),
    new RateLimitMiddleware($limiter, 2, 60, 'demo-web-' . getmypid()),
]);

$destination = fn() => Response::json(['status' => true, 'message' => 'Request reached controller']);

$badHost = new Request('GET', '/students', [], [], [], ['HTTP_HOST' => 'evil.local', 'HTTPS' => 'on', 'REMOTE_ADDR' => '10.0.0.1', 'CONTENT_LENGTH' => 10]);
$insecure = new Request('GET', '/students', [], [], [], ['HTTP_HOST' => 'school.local', 'HTTPS' => 'off', 'REMOTE_ADDR' => '10.0.0.1', 'CONTENT_LENGTH' => 10]);
$large = new Request('POST', '/students', [], [], [], ['HTTP_HOST' => 'school.local', 'HTTPS' => 'on', 'REMOTE_ADDR' => '10.0.0.1', 'CONTENT_LENGTH' => 9999]);
$good = new Request('GET', '/students', [], [], [], ['HTTP_HOST' => 'school.local', 'HTTPS' => 'on', 'REMOTE_ADDR' => '10.0.0.2', 'CONTENT_LENGTH' => 10]);

$responses = [
    'bad host' => $pipeline->handle($badHost, $destination)->status(),
    'insecure HTTP' => $pipeline->handle($insecure, $destination)->status(),
    'oversized request' => $pipeline->handle($large, $destination)->status(),
    'valid request' => $pipeline->handle($good, $destination)->status(),
];

demo_step('Response statuses', $responses);
demo_result($responses['bad host'] === 400 && $responses['insecure HTTP'] === 403 && $responses['oversized request'] === 413 && $responses['valid request'] === 200, 'Request middleware blocks bad host, insecure HTTP, large body, and allows valid traffic.');
