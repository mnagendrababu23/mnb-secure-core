<?php
namespace Mnb\SecurityCore\Memory;

use InvalidArgumentException;

class MemoryBudget
{
    public function __construct(
        private int $maxBytes,
        private float $warningRatio = 0.75,
        private float $criticalRatio = 0.90
    ) {
        if ($this->maxBytes < 0) {
            throw new InvalidArgumentException('Memory budget max bytes cannot be negative.');
        }
        if ($this->warningRatio <= 0 || $this->warningRatio >= 1) {
            throw new InvalidArgumentException('Memory budget warning ratio must be between 0 and 1.');
        }
        if ($this->criticalRatio <= 0 || $this->criticalRatio > 1) {
            throw new InvalidArgumentException('Memory budget critical ratio must be between 0 and 1.');
        }
        if ($this->warningRatio >= $this->criticalRatio) {
            throw new InvalidArgumentException('Memory budget warning ratio must be lower than critical ratio.');
        }
    }

    public static function fromArray(array $config, ?MemoryConfig $fallback = null): self
    {
        $max = array_key_exists('max_bytes', $config)
            ? MemoryConfig::parseBytes($config['max_bytes'])
            : ($fallback?->maxBytes() ?? 0);
        return new self(
            $max,
            (float)($config['warning_ratio'] ?? $fallback?->warningRatio() ?? 0.75),
            (float)($config['critical_ratio'] ?? $fallback?->criticalRatio() ?? 0.90)
        );
    }

    public function maxBytes(): int { return $this->maxBytes; }
    public function warningRatio(): float { return $this->warningRatio; }
    public function criticalRatio(): float { return $this->criticalRatio; }
    public function unlimited(): bool { return $this->maxBytes <= 0; }
    public function warningBytes(): int { return $this->unlimited() ? 0 : (int)floor($this->maxBytes * $this->warningRatio); }
    public function criticalBytes(): int { return $this->unlimited() ? 0 : (int)floor($this->maxBytes * $this->criticalRatio); }

    public function toArray(): array
    {
        return [
            'max_bytes' => $this->maxBytes,
            'max_human' => MemoryGuard::bytesToHuman($this->maxBytes),
            'warning_ratio' => $this->warningRatio,
            'warning_bytes' => $this->warningBytes(),
            'critical_ratio' => $this->criticalRatio,
            'critical_bytes' => $this->criticalBytes(),
            'unlimited' => $this->unlimited(),
        ];
    }
}
