<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Contracts\RateLimiterInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\RateLimit\RateLimitPolicy;

class RateLimitMiddleware implements MiddlewareInterface
{
    private RateLimitPolicy $policy;
    private ?string $routeName;

    public function __construct(
        private RateLimiterInterface $limiter,
        int|RateLimitPolicy $maxAttempts,
        ?int $decaySeconds = null,
        string $prefix = 'request',
        ?string $routeName = null
    ) {
        $this->policy = $maxAttempts instanceof RateLimitPolicy
            ? $maxAttempts
            : RateLimitPolicy::default($maxAttempts, $decaySeconds ?? 60, $prefix);
        $this->routeName = $routeName;
    }

    public static function forPolicy(RateLimiterInterface $limiter, RateLimitPolicy $policy, ?string $routeName = null): self
    {
        return new self($limiter, $policy, null, $policy->prefix(), $routeName);
    }

    public function process(Request $request, callable $next): Response
    {
        $result = $this->limiter->attempt(
            $this->policy->key($request, $this->routeName),
            $this->policy->maxAttempts(),
            $this->policy->decaySeconds()
        );

        $headers = [
            'X-RateLimit-Policy' => $this->policy->name(),
            'X-RateLimit-Limit' => (string)$this->policy->maxAttempts(),
            'X-RateLimit-Remaining' => (string)$result->remaining,
            'X-RateLimit-Reset' => (string)$result->resetAt,
        ];

        if (!$result->allowed) {
            return Response::json(['status' => false, 'message' => 'Too many requests'], 429, $headers + [
                'Retry-After' => (string)$result->retryAfter,
                'X-RateLimit-Remaining' => '0',
            ]);
        }

        $response = $next($request);
        foreach ($headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        return $response;
    }
}
