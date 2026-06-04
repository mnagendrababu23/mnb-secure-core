<?php
namespace Mnb\SecurityCore\Files;

use Mnb\SecurityCore\Contracts\StorageInterface;

class LocalPrivateStorage implements StorageInterface
{
    private string $root;

    public function __construct(string $root)
    {
        $this->root = rtrim($root, DIRECTORY_SEPARATOR);
        if (!is_dir($this->root)) {
            mkdir($this->root, 0775, true);
        }
    }

    public function put(string $path, string $contents): void
    {
        $absolute = $this->absolutePath($path);
        $dir = dirname($absolute);
        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }
        file_put_contents($absolute, $contents, LOCK_EX);
    }

    public function read(string $path): string
    {
        return file_get_contents($this->absolutePath($path));
    }

    public function delete(string $path): void
    {
        @unlink($this->absolutePath($path));
    }

    public function exists(string $path): bool
    {
        return is_file($this->absolutePath($path));
    }

    public function absolutePath(string $path): string
    {
        $path = ltrim(str_replace(['..', '\\'], ['', '/'], $path), '/');
        return $this->root . DIRECTORY_SEPARATOR . $path;
    }
}
