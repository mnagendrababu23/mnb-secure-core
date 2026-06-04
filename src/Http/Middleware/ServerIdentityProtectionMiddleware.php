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
        if (!empty($this->config['enabled']) && $this->hider->shouldBlockDirectIpHost($request)) {
            return Response::json([
                'status' => false,
                'message' => 'Direct server access is not allowed.',
            ], 421);
        }

        $response = $next($request);

        if (empty($this->config['enabled'])) {
            return $response;
        }

        return $this->hider->sanitizeResponse($response);
    }
}
