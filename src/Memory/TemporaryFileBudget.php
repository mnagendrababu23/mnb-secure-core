<?php
namespace Mnb\SecurityCore\Memory;

class TemporaryFileBudget
{
    public function __construct(private int $maxFiles = 100, private int $maxTotalBytes = 104857600, private int $maxAgeSeconds = 3600, private bool $cleanupOnShutdown = true) {}
    public static function fromArray(array $config): self { return new self((int)($config['max_files'] ?? 100), (int)($config['max_total_bytes'] ?? 104857600), (int)($config['max_age_seconds'] ?? 3600), !array_key_exists('cleanup_on_shutdown', $config) || (bool)$config['cleanup_on_shutdown']); }
    public function maxFiles(): int { return $this->maxFiles; }
    public function maxTotalBytes(): int { return $this->maxTotalBytes; }
    public function maxAgeSeconds(): int { return $this->maxAgeSeconds; }
    public function cleanupOnShutdown(): bool { return $this->cleanupOnShutdown; }
    public function toArray(): array { return ['max_files' => $this->maxFiles, 'max_total_bytes' => $this->maxTotalBytes, 'max_age_seconds' => $this->maxAgeSeconds, 'cleanup_on_shutdown' => $this->cleanupOnShutdown]; }
}
