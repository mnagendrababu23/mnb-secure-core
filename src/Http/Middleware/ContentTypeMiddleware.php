<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class ContentTypeMiddleware implements MiddlewareInterface
{
    /** @param list<string> $allowedTypes */
    public function __construct(private array $allowedTypes = [], private bool $rejectBodyOnGet = true) {
        $this->allowedTypes = array_values(array_filter(array_map(fn($v): string => strtolower(trim((string)$v)), $allowedTypes)));
    }

    public function process(Request $request, callable $next): Response
    {
        if ($this->rejectBodyOnGet && in_array($request->method(), ['GET', 'HEAD'], true) && $request->contentLength() > 0) {
            return Response::json(['status' => false, 'message' => 'Request body is not allowed for this method'], 400);
        }

        if ($this->allowedTypes === []) {
            return $next($request);
        }

        if (!in_array($request->method(), ['POST', 'PUT', 'PATCH', 'DELETE'], true) && $request->contentLength() === 0) {
            return $next($request);
        }

        $contentType = strtolower(trim((string)$request->header('content-type', '')));
        if ($contentType === '' && $request->contentLength() === 0) {
            return $next($request);
        }
        foreach ($this->allowedTypes as $allowed) {
            if ($allowed === '*' || $contentType === $allowed || str_starts_with($contentType, $allowed . ';')) {
                return $next($request);
            }
        }
        return Response::json(['status' => false, 'message' => 'Unsupported content type'], 415)
            ->withHeader('Accept', implode(', ', $this->allowedTypes));
    }
}
