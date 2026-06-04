<?php
namespace Mnb\SecurityCore\Contracts;

interface CacheInterface
{
    public function get(string $key, mixed $default = null): mixed;
    public function put(string $key, mixed $value, int $ttlSeconds): void;
    public function forget(string $key): void;
    public function has(string $key): bool;
}
