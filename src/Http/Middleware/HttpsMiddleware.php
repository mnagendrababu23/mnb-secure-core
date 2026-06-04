<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class HttpsMiddleware implements MiddlewareInterface
{
    public function __construct(private bool $forceHttps = true) {}

    public function process(Request $request, callable $next): Response
    {
        if ($this->forceHttps && !$request->isSecure()) {
            return Response::json(['status' => false, 'message' => 'HTTPS is required'], 403);
        }
        return $next($request);
    }
}
