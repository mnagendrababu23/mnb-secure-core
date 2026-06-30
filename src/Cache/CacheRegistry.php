<?php
namespace Mnb\SecurityCore\Cache;

class CacheRegistry
{
    /** @var array<string,CachePolicy> */
    private array $policies = [];

    /** @param array<string,CachePolicy|array<string,mixed>> $policies @param array<string,mixed> $defaults */
    public function __construct(array $policies = [], private array $defaults = [])
    {
        foreach ($policies as $name => $policy) {
            $this->add($name, $policy);
        }
    }

    public static function fromConfig(array $config): self
    {
        $caching = is_array($config['caching'] ?? null) ? $config['caching'] : [];
        $defaults = [
            'ttl' => (int)($caching['default_ttl'] ?? 300),
            'data_class' => 'internal',
            'scope' => ['global'],
            'encrypt' => (bool)($caching['security']['encrypt_sensitive'] ?? false),
            'max_value_bytes' => (int)($caching['security']['max_value_bytes'] ?? 1048576),
        ];
        return new self(is_array($caching['policies'] ?? null) ? $caching['policies'] : [], $defaults);
    }

    public function add(string $name, CachePolicy|array $policy): void
    {
        $this->policies[$name] = $policy instanceof CachePolicy ? $policy : CachePolicy::fromArray($name, $policy, $this->defaults);
    }

    public function has(string $name): bool { return isset($this->policies[$name]); }

    public function get(string $name): CachePolicy
    {
        if (!$this->has($name)) {
            throw new \InvalidArgumentException("Unknown cache policy '{$name}'.");
        }
        return $this->policies[$name];
    }

    /** @return array<string,CachePolicy> */
    public function all(): array { return $this->policies; }
}
