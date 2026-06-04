<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Auth\Stores\FileTokenStore;
use Mnb\SecurityCore\Http\Middleware\ApiTokenMiddleware;
use Mnb\SecurityCore\Http\Middleware\RateLimitMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\RateLimit\FileRateLimiter;
use Mnb\SecurityCore\Data\DataClassifier;
use Mnb\SecurityCore\Data\FieldFilter;
use Mnb\SecurityCore\Data\DataMasker;
use Mnb\SecurityCore\Http\SafeResponseBuilder;

demo_title('07. API Security and Rate Limiting');

$tokenStore = new FileTokenStore(demo_storage_path('tokens/api-demo.json'));
$tokens = new OpaqueTokenService($tokenStore);
$issued = $tokens->issue(25, ['student.profile'], 'phone-1', 'Parent Phone', 3600);

$limiter = new FileRateLimiter(demo_storage_path('rate-limits-api'));
$pipeline = new MiddlewarePipeline([
    new RateLimitMiddleware($limiter, 1, 60, 'demo-api-' . getmypid()),
    new ApiTokenMiddleware($tokens),
]);

$classifier = new DataClassifier(['parent_phone' => DataClassifier::SENSITIVE, 'password_hash' => DataClassifier::HIGHLY_SENSITIVE]);
$responder = new SafeResponseBuilder(new FieldFilter($classifier, new DataMasker()));
$destination = function () use ($responder) {
    return $responder->success([
        'id' => 25,
        'name' => 'Student Demo',
        'parent_phone' => '9876543210',
        'password_hash' => 'never-return-this',
    ], 'Profile loaded', ['id', 'name']);
};

$validRequest = new Request('GET', '/api/v1/profile', [], [], ['Authorization' => 'Bearer ' . $issued['plain_token']], ['REMOTE_ADDR' => '127.0.0.20']);
$first = $pipeline->handle($validRequest, $destination);
$second = $pipeline->handle($validRequest, $destination);
$missingToken = new Request('GET', '/api/v1/profile', [], [], [], ['REMOTE_ADDR' => '127.0.0.21']);
$missing = $pipeline->handle($missingToken, $destination);

demo_step('First valid request status', $first->status());
demo_step('First valid response body', json_decode($first->body(), true));
demo_step('Second request status after rate limit', $second->status());
demo_step('Missing token status', $missing->status());

demo_result($first->status() === 200 && $second->status() === 429 && $missing->status() === 401, 'API token middleware, field filtering, and endpoint rate limiting are working.');
