<?php
require __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Http\WebhookSignatureVerifier;
use Mnb\SecurityCore\Http\Middleware\WebhookSignatureMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;

demo_title('20. Secure Request Receiving Strategy Engine');

$config = require __DIR__ . '/../config/security.php';
$config['app']['trusted_hosts'] = [];
$config['origin_protection']['enabled'] = false;
$config['cors']['enabled'] = false;
$config['security_headers']['enabled'] = false;
$config['audit']['enabled'] = false;
$config['request_receiving']['profiles']['demo_api'] = [
    'methods' => ['POST'],
    'max_bytes' => 1024,
    'content_types' => ['application/json'],
    'rate_policy' => null,
    'auth' => null,
    'request_trust' => false,
    'origin_protection' => false,
    'https' => false,
    'trusted_host' => false,
    'cors' => false,
    'security_headers' => false,
    'input_validation' => false,
    'auto_audit' => false,
    'suspicious_detection' => true,
    'json_body' => true,
];

$kernel = new SecurityKernel($config);

$request = (new Request('POST', '/api/demo', [], [], ['content-type' => 'application/json'], ['REMOTE_ADDR' => '127.0.0.1', 'CONTENT_LENGTH' => 16]))
    ->withAttribute('raw_body', '{"name":"Demo"}');

$response = $kernel->secureRequestReceiver('demo_api')->handle($request, function (Request $request): Response {
    return Response::json([
        'status' => true,
        'profile' => $request->attribute('request_receiving_profile'),
        'request_id' => $request->attribute('request_id'),
        'name' => $request->input('name'),
    ]);
});

demo_result($response->status() === 200, 'Receiving profile accepted safe JSON request');
$body = json_decode($response->body(), true);
demo_result(($body['profile'] ?? null) === 'demo_api' && ($body['name'] ?? null) === 'Demo', 'Receiver attached profile metadata and parsed JSON body');
demo_result(isset($response->headers()['X-Request-ID']), 'Receiver emitted X-Request-ID header');

$badMethod = $kernel->secureRequestReceiver('demo_api')->handle(new Request('GET', '/api/demo'), fn() => Response::json(['status' => true]));
demo_result($badMethod->status() === 405, 'Receiver blocked disallowed HTTP method');

$badJson = $kernel->secureRequestReceiver('demo_api')->handle(
    (new Request('POST', '/api/demo', [], [], ['content-type' => 'application/json'], ['CONTENT_LENGTH' => 4]))->withAttribute('raw_body', '{bad'),
    fn() => Response::json(['status' => true])
);
demo_result($badJson->status() === 400, 'Receiver blocked invalid JSON before controller');

$raw = '{"event":"demo"}';
$timestamp = (string)time();
$secret = 'demo-webhook-secret';
$signature = hash_hmac('sha256', $timestamp . '.' . $raw, $secret);
$webhookRequest = (new Request('POST', '/webhook', [], [], ['x-timestamp' => $timestamp, 'x-signature' => 'sha256=' . $signature], ['CONTENT_LENGTH' => strlen($raw)]))
    ->withAttribute('raw_body', $raw);
$webhook = (new MiddlewarePipeline([new WebhookSignatureMiddleware(new WebhookSignatureVerifier(['secret' => $secret]))]))
    ->handle($webhookRequest, fn(Request $request) => Response::json(['verified' => $request->attribute('webhook_signature_verified')]));
demo_result($webhook->status() === 200, 'Webhook signature middleware accepted valid HMAC signature');

demo_step('Secure request receiving strategy engine demo complete');
