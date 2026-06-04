<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Contracts\RateLimiterInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class RateLimitMiddleware implements MiddlewareInterface
{
    public function __construct(
        private RateLimiterInterface $limiter,
        private int $maxAttempts,
        private int $decaySeconds,
        private string $prefix = 'request'
    ) {}

    public function process(Request $request, callable $next): Response
    {
        $key = $this->prefix . ':' . $request->ip() . ':' . $request->path();
        $result = $this->limiter->attempt($key, $this->maxAttempts, $this->decaySeconds);
        if (!$result->allowed) {
            return Response::json(['status' => false, 'message' => 'Too many requests'], 429, [
                'Retry-After' => (string)$result->retryAfter,
                'X-RateLimit-Remaining' => '0',
            ]);
        }
        return $next($request)->withHeader('X-RateLimit-Remaining', (string)$result->remaining);
    }
}
