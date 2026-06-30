<?php
namespace Mnb\SecurityCore\Throughput;

class FileConcurrencyStore implements ConcurrencyStore
{
    public function __construct(private string $path)
    {
        if ($this->path !== '' && !is_dir($this->path)) {
            @mkdir($this->path, 0775, true);
        }
    }

    public function acquire(string $profile, string $tokenId, int $limit, int $ttlSeconds): bool
    {
        $this->cleanupExpired();
        $dir = $this->dir($profile);
        if (!is_dir($dir)) { @mkdir($dir, 0775, true); }
        if ($this->activeCount($profile) >= max(1, $limit)) {
            return false;
        }
        return file_put_contents($dir . '/' . $this->safe($tokenId) . '.lock', (string)(time() + max(1, $ttlSeconds)), LOCK_EX) !== false;
    }

    public function release(string $profile, string $tokenId): void
    {
        $file = $this->dir($profile) . '/' . $this->safe($tokenId) . '.lock';
        if (is_file($file)) { @unlink($file); }
    }

    public function activeCount(string $profile): int
    {
        $this->cleanupExpired();
        $files = glob($this->dir($profile) . '/*.lock') ?: [];
        return count($files);
    }

    public function cleanupExpired(): int
    {
        $removed = 0;
        foreach (glob(rtrim($this->path, '/\\') . '/*/*.lock') ?: [] as $file) {
            $expiresAt = (int)trim((string)@file_get_contents($file));
            if ($expiresAt > 0 && $expiresAt <= time()) {
                @unlink($file);
                $removed++;
            }
        }
        return $removed;
    }

    private function dir(string $profile): string
    {
        return rtrim($this->path, '/\\') . '/' . $this->safe($profile);
    }

    private function safe(string $value): string
    {
        return preg_replace('/[^A-Za-z0-9_.-]+/', '_', $value) ?: 'default';
    }
}
