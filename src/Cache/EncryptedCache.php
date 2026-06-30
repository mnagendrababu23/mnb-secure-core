<?php
namespace Mnb\SecurityCore\Cache;

use Mnb\SecurityCore\Contracts\CacheInterface;
use Mnb\SecurityCore\Data\KeyRing;

class EncryptedCache implements CacheInterface
{
    public function __construct(
        private CacheInterface $inner,
        private KeyRing $keys,
        private SafeCacheSerializer $serializer = new SafeCacheSerializer(),
        private string $aadPrefix = 'cache'
    ) {}

    public function get(string $key, mixed $default = null): mixed
    {
        $stored = $this->inner->get($key);
        if (!is_string($stored) || !$this->keys->isEncrypted($stored)) {
            return $default;
        }
        try {
            return $this->serializer->decode($this->keys->decrypt($stored, $this->aad($key)));
        } catch (\Throwable) {
            return $default;
        }
    }

    public function put(string $key, mixed $value, int $ttlSeconds): void
    {
        $payload = $this->serializer->encode($value);
        $this->inner->put($key, $this->keys->encrypt($payload, $this->aad($key)), $ttlSeconds);
    }

    public function forget(string $key): void { $this->inner->forget($key); }
    public function has(string $key): bool { return $this->get($key, null) !== null; }

    private function aad(string $key): string
    {
        return $this->aadPrefix . ':' . hash('sha256', $key);
    }
}
