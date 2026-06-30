<?php
namespace Mnb\SecurityCore\Files;

use Mnb\SecurityCore\Contracts\StorageInterface;
use Mnb\SecurityCore\Data\KeyRing;

class EncryptedStorage implements StorageInterface
{
    public function __construct(private StorageInterface $inner, private KeyRing $keys, private string $aadPrefix = 'file') {}

    public function put(string $path, string $contents): void
    {
        $this->inner->put($path, $this->keys->encrypt($contents, $this->aad($path)));
    }

    public function read(string $path): string
    {
        $contents = $this->inner->read($path);
        return $this->keys->isEncrypted($contents) ? $this->keys->decrypt($contents, $this->aad($path)) : $contents;
    }

    public function delete(string $path): void
    {
        $this->inner->delete($path);
    }

    public function exists(string $path): bool
    {
        return $this->inner->exists($path);
    }

    public function absolutePath(string $path): string
    {
        return $this->inner->absolutePath($path);
    }

    private function aad(string $path): string
    {
        return $this->aadPrefix . ':' . ltrim(str_replace('\\', '/', $path), '/');
    }
}
