<?php
namespace Mnb\SecurityCore\Env;

class EnvSecretProvider implements SecretProviderInterface
{
    public function __construct(private string $prefix = '') {}

    public function get(string $key, mixed $default = null): mixed
    {
        $name = $this->prefix . $key;
        if (array_key_exists($name, $_ENV)) {
            return $_ENV[$name];
        }
        $value = getenv($name);
        return $value === false ? $default : $value;
    }

    public function has(string $key): bool
    {
        $name = $this->prefix . $key;
        return array_key_exists($name, $_ENV) || getenv($name) !== false;
    }

    public function source(): string
    {
        return 'env';
    }
}
