<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Contracts\RateLimiterInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\RateLimit\RateLimitPolicyRegistry;

class RateLimitPolicyMiddleware implements MiddlewareInterface
{
    public function __construct(
        private RateLimiterInterface $limiter,
        private RateLimitPolicyRegistry $policies,
        private string $policyName,
        private ?string $routeName = null
    ) {}

    public function process(Request $request, callable $next): Response
    {
        return RateLimitMiddleware::forPolicy(
            $this->limiter,
            $this->policies->get($this->policyName),
            $this->routeName
        )->process($request, $next);
    }
}
