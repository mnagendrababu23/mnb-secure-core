<?php
namespace Mnb\SecurityCore\Cache;

use Mnb\SecurityCore\Contracts\CacheInterface;

class NullCache implements CacheInterface
{
    public function get(string $key, mixed $default = null): mixed { return $default; }
    public function put(string $key, mixed $value, int $ttlSeconds): void {}
    public function forget(string $key): void {}
    public function has(string $key): bool { return false; }
}
