<?php
namespace Mnb\SecurityCore\Contracts;

use Mnb\SecurityCore\RateLimit\RateLimitResult;

interface RateLimiterInterface
{
    public function attempt(string $key, int $maxAttempts, int $decaySeconds): RateLimitResult;
    public function clear(string $key): void;
}
