<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class RequestTrustMiddleware implements MiddlewareInterface
{
    public function __construct(private array $config = []) {}

    public function process(Request $request, callable $next): Response
    {
        if (!empty($this->config['block_untrusted_forwarded_headers']) && $request->hasForwardedHeaders() && !$request->isFromTrustedProxy()) {
            return Response::json([
                'status' => false,
                'message' => 'Untrusted forwarded request headers are not allowed.',
            ], 400);
        }

        if (!empty($this->config['require_trusted_proxy']) && !$request->isFromTrustedProxy()) {
            return Response::json([
                'status' => false,
                'message' => 'Direct origin access is not allowed.',
            ], 421);
        }

        $response = $next($request);

        if (!empty($this->config['emit_headers'])) {
            $response = $response
                ->withHeader('X-Client-IP-Trusted', $request->isFromTrustedProxy() ? '1' : '0')
                ->withHeader('X-Request-Remote-IP', $request->remoteIp());
        }

        return $response;
    }
}
