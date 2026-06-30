<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Http\WebhookSignatureVerifier;

class WebhookSignatureMiddleware implements MiddlewareInterface
{
    public function __construct(private WebhookSignatureVerifier $verifier) {}

    public function process(Request $request, callable $next): Response
    {
        $raw = $request->attribute('raw_body');
        if (!is_string($raw)) {
            $raw = '';
        }
        $result = $this->verifier->verify($request, $raw);
        if (!$result['valid']) {
            return Response::json(['status' => false, 'message' => 'Invalid webhook signature'], 401);
        }
        return $next($request->withAttribute('webhook_signature_verified', true));
    }
}
