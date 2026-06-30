<?php
namespace Mnb\SecurityCore\Env;

interface SecretProviderInterface
{
    public function get(string $key, mixed $default = null): mixed;
    public function has(string $key): bool;
    public function source(): string;
}
