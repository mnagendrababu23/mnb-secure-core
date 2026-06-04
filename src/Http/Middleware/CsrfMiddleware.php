<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Auth\Csrf;
use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class CsrfMiddleware implements MiddlewareInterface
{
    public function __construct(private Csrf $csrf) {}

    public function process(Request $request, callable $next): Response
    {
        if (in_array($request->method(), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $token = $request->header('x-csrf-token') ?? $request->input('_csrf');
            if (!$this->csrf->verify((string)$token)) {
                return Response::json(['status' => false, 'message' => 'Invalid CSRF token'], 419);
            }
        }
        return $next($request);
    }
}
