<?php
require __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Errors\SafeErrorHandler;
use Mnb\SecurityCore\Exceptions\AppException;
use Mnb\SecurityCore\Exceptions\AuthorizationException;
use Mnb\SecurityCore\Http\Middleware\ErrorHandlingMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Logging\FileLogger;

demo_title('16. Error Handling, Safe Error Responses, and Error Logs');

$logFile = demo_storage_path('logs/error-demo.log');
@unlink($logFile);

$config = require __DIR__ . '/../config/security.php';
$config['app']['env'] = 'production';
$config['app']['debug'] = false;
$config['errors']['response_format'] = 'json';

$handler = new SafeErrorHandler(new FileLogger($logFile), $config);
$request = new Request('GET', '/students/secret', [], [], ['accept' => 'application/json'], ['REMOTE_ADDR' => '127.0.0.1']);

$response = $handler->renderThrowable(new RuntimeException('SQLSTATE[HY000] password=secret /var/www/app/User.php'), $request);
$payload = json_decode($response->body(), true);

demo_step('Frontend status', $response->status());
demo_step('Frontend payload', $payload);
demo_result($response->status() === 500 && !str_contains($response->body(), 'SQLSTATE') && !str_contains($response->body(), '/var/www'), 'Raw internal error hidden from frontend');

$log = file_get_contents($logFile) ?: '';
demo_result(str_contains($log, 'SQLSTATE') && str_contains($log, 'request_id'), 'Internal error details logged with request ID');

$custom = $handler->renderThrowable(new AppException('Gateway private timeout token=abc', 'Payment service is temporarily unavailable.', 503, 'PAYMENT_DOWN'), $request);
demo_step('Custom safe error response', json_decode($custom->body(), true));
demo_result($custom->status() === 503 && str_contains($custom->body(), 'Payment service is temporarily unavailable.') && !str_contains($custom->body(), 'token=abc'), 'Custom exception returns safe public message only');

$pipeline = new MiddlewarePipeline([
    new ErrorHandlingMiddleware($handler),
]);
$pipeResponse = $pipeline->handle($request, function () {
    throw new AuthorizationException('Teacher tried fees.delete without permission');
});
demo_step('Middleware-caught response', json_decode($pipeResponse->body(), true));
demo_result($pipeResponse->status() === 403 && str_contains($pipeResponse->body(), 'not allowed'), 'ErrorHandlingMiddleware catches exceptions and returns safe response');

$debugConfig = $config;
$debugConfig['app']['env'] = 'local';
$debugConfig['app']['debug'] = true;
$debug = (new SafeErrorHandler(new FileLogger($logFile), $debugConfig))->renderThrowable(new RuntimeException('Debug visible in local only'), $request);
demo_result(str_contains($debug->body(), 'debug') && str_contains($debug->body(), 'Debug visible in local only'), 'Debug detail is available only in non-production debug mode');
