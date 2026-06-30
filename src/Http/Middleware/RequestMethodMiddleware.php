<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class RequestMethodMiddleware implements MiddlewareInterface
{
    /** @param list<string> $allowedMethods @param list<string> $blockedMethods */
    public function __construct(private array $allowedMethods = [], private array $blockedMethods = ['TRACE', 'CONNECT'])
    {
        $this->allowedMethods = array_map('strtoupper', array_map('strval', $allowedMethods));
        $this->blockedMethods = array_map('strtoupper', array_map('strval', $blockedMethods));
    }

    public function process(Request $request, callable $next): Response
    {
        $method = $request->method();
        if (in_array($method, $this->blockedMethods, true)) {
            return Response::json(['status' => false, 'message' => 'HTTP method is not allowed'], 405)
                ->withHeader('Allow', implode(', ', $this->allowedMethods ?: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']));
        }
        if ($this->allowedMethods !== [] && !in_array($method, $this->allowedMethods, true)) {
            return Response::json(['status' => false, 'message' => 'HTTP method is not allowed'], 405)
                ->withHeader('Allow', implode(', ', $this->allowedMethods));
        }
        return $next($request);
    }
}
