<?php
namespace Mnb\SecurityCore\Cache;

use Mnb\SecurityCore\Contracts\CacheInterface;

class FileCache implements CacheInterface
{
    public function __construct(private string $path)
    {
        if (!is_dir($path)) {
            mkdir($path, 0775, true);
        }
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $file = $this->file($key);
        if (!is_file($file)) {
            return $default;
        }
        $payload = json_decode(file_get_contents($file) ?: '', true);
        if (!is_array($payload) || ($payload['expires_at'] ?? 0) < time()) {
            @unlink($file);
            return $default;
        }
        return $payload['data'];
    }

    public function put(string $key, mixed $value, int $ttlSeconds): void
    {
        file_put_contents($this->file($key), json_encode([
            'expires_at' => time() + $ttlSeconds,
            'data' => $value,
        ], JSON_PRETTY_PRINT), LOCK_EX);
    }

    public function forget(string $key): void
    {
        @unlink($this->file($key));
    }

    public function has(string $key): bool
    {
        return $this->get($key, null) !== null;
    }

    private function file(string $key): string
    {
        return rtrim($this->path, '/') . '/' . hash('sha256', $key) . '.cache.json';
    }
}
