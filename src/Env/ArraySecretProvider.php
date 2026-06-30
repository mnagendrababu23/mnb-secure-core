<?php
namespace Mnb\SecurityCore\Env;

class ArraySecretProvider implements SecretProviderInterface
{
    /** @param array<string,mixed> $secrets */
    public function __construct(private array $secrets, private string $name = 'array') {}

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->secrets) ? $this->secrets[$key] : $default;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->secrets);
    }

    public function source(): string
    {
        return $this->name;
    }
}
