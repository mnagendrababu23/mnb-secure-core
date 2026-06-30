<?php
namespace Mnb\SecurityCore\Auth;

class AuthenticationRegistry
{
    /** @var array<string,AuthenticationStrategy> */
    private array $strategies = [];

    /** @param array<string,AuthenticationStrategy|array<string,mixed>> $strategies */
    public function __construct(array $strategies = [])
    {
        foreach ($strategies as $name => $strategy) {
            if ($strategy instanceof AuthenticationStrategy) {
                $this->strategies[$strategy->name()] = $strategy;
                continue;
            }
            if (is_array($strategy)) {
                $this->strategies[(string)$name] = AuthenticationStrategy::fromArray((string)$name, $strategy);
            }
        }
    }

    public static function fromConfig(array $config): self
    {
        $auth = is_array($config['authentication'] ?? null) ? $config['authentication'] : [];
        $defaults = is_array($auth['defaults'] ?? null) ? $auth['defaults'] : [];
        $strategies = is_array($auth['strategies'] ?? null) ? $auth['strategies'] : [];
        $merged = [];
        foreach ($strategies as $name => $strategy) {
            if (is_array($strategy)) {
                $merged[$name] = array_replace($defaults, $strategy);
            }
        }
        return new self($merged);
    }

    public function has(string $name): bool { return isset($this->strategies[$name]); }

    public function get(string $name): AuthenticationStrategy
    {
        if (!$this->has($name)) {
            throw new \InvalidArgumentException("Authentication strategy '{$name}' is not configured.");
        }
        return $this->strategies[$name];
    }

    /** @return array<string,AuthenticationStrategy> */ public function all(): array { return $this->strategies; }
}
