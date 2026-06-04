<?php
require __DIR__ . '/bootstrap.php';

use Mnb\SecurityCore\Errors\SafeErrorHandler;
use Mnb\SecurityCore\Exceptions\AppException;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Logging\FileLogger;

$config = require __DIR__ . '/../config/security.php';
$config['app']['env'] = 'production';
$config['app']['debug'] = false;
$config['errors']['response_format'] = 'json';

$logger = new FileLogger(__DIR__ . '/../storage/logs/example-errors.log');
$handler = new SafeErrorHandler($logger, $config);

$request = new Request('POST', '/fees/collect', [], [], ['accept' => 'application/json'], [
    'REMOTE_ADDR' => '127.0.0.1',
]);

try {
    throw new AppException(
        internalMessage: 'Receipt insert failed: duplicate receipt_no RCPT-1001',
        publicMessage: 'Receipt could not be created. Please try again.',
        statusCode: 500,
        errorCode: 'RECEIPT_CREATE_FAILED'
    );
} catch (Throwable $throwable) {
    $response = $handler->renderThrowable($throwable, $request);
    echo $response->body() . PHP_EOL;
}
