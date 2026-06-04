<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class RequestSizeMiddleware implements MiddlewareInterface
{
    public function __construct(private int $maxBytes) {}

    public function process(Request $request, callable $next): Response
    {
        if ($this->maxBytes > 0 && $request->contentLength() > $this->maxBytes) {
            return Response::json(['status' => false, 'message' => 'Request too large'], 413);
        }
        return $next($request);
    }
}
