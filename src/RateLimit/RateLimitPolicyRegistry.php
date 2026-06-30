<?php
namespace Mnb\SecurityCore\RateLimit;

use InvalidArgumentException;

class RateLimitPolicyRegistry
{
    /** @var array<string,RateLimitPolicy> */
    private array $policies = [];

    /**
     * @param array<string,mixed> $policies
     */
    public function __construct(array $policies = [])
    {
        foreach ($policies as $name => $policy) {
            if ($policy instanceof RateLimitPolicy) {
                $this->register($policy);
                continue;
            }
            if (is_array($policy)) {
                $this->register(RateLimitPolicy::fromArray((string)$name, $policy));
                continue;
            }
            throw new InvalidArgumentException("Rate limit policy '{$name}' must be an array or RateLimitPolicy instance.");
        }
    }

    /**
     * @param array<string,mixed> $config
     */
    public static function fromConfig(array $config): self
    {
        $limits = is_array($config['limits'] ?? null) ? $config['limits'] : $config;
        $policies = [];
        foreach ($limits as $name => $policy) {
            if (!is_string($name) || !is_array($policy)) {
                continue;
            }
            if (array_key_exists('max', $policy) || array_key_exists('max_attempts', $policy)) {
                $policies[$name] = $policy;
            }
        }
        return new self($policies);
    }

    public function register(RateLimitPolicy $policy): self
    {
        $this->policies[$policy->name()] = $policy;
        return $this;
    }

    public function has(string $name): bool
    {
        return isset($this->policies[$this->normalizeLookupName($name)]);
    }

    public function get(string $name): RateLimitPolicy
    {
        $name = $this->normalizeLookupName($name);
        if (!isset($this->policies[$name])) {
            throw new InvalidArgumentException("Rate limit policy '{$name}' is not registered.");
        }
        return $this->policies[$name];
    }

    /** @return array<string,RateLimitPolicy> */
    public function all(): array
    {
        return $this->policies;
    }

    private function normalizeLookupName(string $name): string
    {
        return strtolower(trim($name));
    }
}
