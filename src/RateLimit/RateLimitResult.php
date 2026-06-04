<?php
namespace Mnb\SecurityCore\RateLimit;

class RateLimitResult
{
    public function __construct(
        public readonly bool $allowed,
        public readonly int $remaining,
        public readonly int $retryAfter,
        public readonly int $resetAt
    ) {}
}
