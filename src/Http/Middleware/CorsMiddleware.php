<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\CorsPolicy;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class CorsMiddleware implements MiddlewareInterface
{
    private CorsPolicy $policy;

    public function __construct(private array $config)
    {
        $this->policy = new CorsPolicy($config);
    }

    public function process(Request $request, callable $next): Response
    {
        if (!$this->policy->enabled()) {
            return $next($request);
        }

        $origin = $request->header('origin');
        $origin = is_scalar($origin) ? (string)$origin : null;

        if (!$this->policy->originAllowed($origin)) {
            return Response::json(['status' => false, 'message' => 'CORS origin denied'], 403)
                ->withHeader('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
        }

        if ($request->method() === 'OPTIONS') {
            $requestedMethod = $request->header('access-control-request-method');
            $requestedHeaders = $request->header('access-control-request-headers');

            if (!$this->policy->methodAllowed(is_scalar($requestedMethod) ? (string)$requestedMethod : null)) {
                return Response::json(['status' => false, 'message' => 'CORS method denied'], 405)
                    ->withHeader('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
            }
            if (!$this->policy->requestedHeadersAllowed(is_scalar($requestedHeaders) ? (string)$requestedHeaders : null)) {
                return Response::json(['status' => false, 'message' => 'CORS headers denied'], 403)
                    ->withHeader('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
            }

            return $this->policy->apply($request, Response::text('', 204), $origin);
        }

        return $this->policy->apply($request, $next($request), $origin);
    }
}
