<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class CorsMiddleware implements MiddlewareInterface
{
    public function __construct(private array $config) {}

    public function process(Request $request, callable $next): Response
    {
        $origin = $request->header('origin');
        $allowed = $this->config['allowed_origins'] ?? [];
        if ($origin && !in_array($origin, $allowed, true)) {
            return Response::json(['status' => false, 'message' => 'CORS origin denied'], 403);
        }
        if ($request->method() === 'OPTIONS') {
            $response = Response::text('', 204);
        } else {
            $response = $next($request);
        }
        if ($origin) {
            $response = $response->withHeader('Access-Control-Allow-Origin', $origin)
                ->withHeader('Vary', 'Origin')
                ->withHeader('Access-Control-Allow-Methods', implode(', ', $this->config['allowed_methods'] ?? ['GET', 'POST']))
                ->withHeader('Access-Control-Allow-Headers', implode(', ', $this->config['allowed_headers'] ?? ['Content-Type', 'Authorization']));
        }
        return $response;
    }
}
