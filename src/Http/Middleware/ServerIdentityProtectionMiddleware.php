<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Security\ServerIdentityHider;

class ServerIdentityProtectionMiddleware implements MiddlewareInterface
{
    private ServerIdentityHider $hider;

    public function __construct(private array $config = [])
    {
        $this->hider = new ServerIdentityHider($config);
    }

    public function process(Request $request, callable $next): Response
    {
        if (!empty($this->config['enabled'])) {
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

            if ($this->hider->shouldBlockDirectIpHost($request)) {
                return Response::json([
                    'status' => false,
                    'message' => 'Direct server access is not allowed.',
                ], 421);
            }
        }

        $response = $next($request);

        if (empty($this->config['enabled'])) {
            return $response;
        }

        return $this->hider->sanitizeResponse($response);
    }
}
