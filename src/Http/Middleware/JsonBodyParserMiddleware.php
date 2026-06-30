<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class JsonBodyParserMiddleware implements MiddlewareInterface
{
    public function __construct(private int $maxDepth = 64, private int $maxBytes = 0, private bool $requireObject = true) {}

    public function process(Request $request, callable $next): Response
    {
        $contentType = strtolower((string)$request->header('content-type', ''));
        if (!str_contains($contentType, 'application/json') && !str_contains($contentType, '+json')) {
            return $next($request);
        }

        if ($this->maxBytes > 0 && $request->contentLength() > $this->maxBytes) {
            return Response::json(['status' => false, 'message' => 'JSON body too large'], 413);
        }

        $raw = $request->attribute('raw_body');
        if ($raw === null) {
            $raw = $request->attribute('request_body_raw');
        }
        if (!is_string($raw)) {
            return $next($request->withAttribute('json_body_checked', true));
        }

        if ($this->maxBytes > 0 && strlen($raw) > $this->maxBytes) {
            return Response::json(['status' => false, 'message' => 'JSON body too large'], 413);
        }
        if (trim($raw) === '') {
            $data = [];
        } else {
            try {
                $data = json_decode($raw, true, max(1, $this->maxDepth), JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                return Response::json(['status' => false, 'message' => 'Invalid JSON body'], 400);
            }
        }

        if ($this->requireObject && !is_array($data)) {
            return Response::json(['status' => false, 'message' => 'JSON body must be an object or array'], 400);
        }

        return $next($request->withBody(is_array($data) ? $data : [])->withAttribute('json_body_checked', true));
    }
}
