<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class TrustedHostMiddleware implements MiddlewareInterface
{
    public function __construct(private array $trustedHosts) {}

    public function process(Request $request, callable $next): Response
    {
        if ($this->trustedHosts && !in_array($request->host(), array_map('strtolower', $this->trustedHosts), true)) {
            return Response::json(['status' => false, 'message' => 'Untrusted host'], 400);
        }
        return $next($request);
    }
}
