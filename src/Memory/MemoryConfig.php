<?php
namespace Mnb\SecurityCore\Memory;

use InvalidArgumentException;

class MemoryConfig
{
    public function __construct(
        private int $maxBytes = 0,
        private float $warningRatio = 0.75,
        private float $criticalRatio = 0.90,
        private int $defaultChunkSize = 500,
        private int $minChunkSize = 25,
        private int $maxChunkSize = 5000
    ) {
        if ($this->warningRatio <= 0 || $this->warningRatio >= 1) {
            throw new InvalidArgumentException('warningRatio must be between 0 and 1.');
        }
        if ($this->criticalRatio <= 0 || $this->criticalRatio > 1) {
            throw new InvalidArgumentException('criticalRatio must be between 0 and 1.');
        }
        if ($this->warningRatio >= $this->criticalRatio) {
            throw new InvalidArgumentException('warningRatio must be lower than criticalRatio.');
        }
        if ($this->minChunkSize < 1 || $this->defaultChunkSize < 1 || $this->maxChunkSize < $this->minChunkSize) {
            throw new InvalidArgumentException('Invalid chunk size configuration.');
        }
    }

    public static function fromArray(array $config): self
    {
        $max = $config['max_bytes'] ?? $config['limit'] ?? null;
        return new self(
            max(0, self::parseBytes($max ?? ini_get('memory_limit'))),
            (float)($config['warning_ratio'] ?? 0.75),
            (float)($config['critical_ratio'] ?? 0.90),
            (int)($config['default_chunk_size'] ?? 500),
            (int)($config['min_chunk_size'] ?? 25),
            (int)($config['max_chunk_size'] ?? 5000)
        );
    }

    public static function fromPhpIni(float $warningRatio = 0.75, float $criticalRatio = 0.90): self
    {
        return new self(self::parseBytes(ini_get('memory_limit')), $warningRatio, $criticalRatio);
    }

    public static function parseBytes(int|string|false|null $value): int
    {
        if ($value === false || $value === null || $value === '') {
            return 0;
        }
        if (is_int($value)) {
            return max(0, $value);
        }
        $raw = trim($value);
        if ($raw === '-1') {
            return 0;
        }
        if (is_numeric($raw)) {
            return max(0, (int)$raw);
        }
        if (!preg_match('/^([0-9]+(?:\.[0-9]+)?)\s*([kmgt])?b?$/i', $raw, $matches)) {
            throw new InvalidArgumentException('Invalid byte size: ' . $value);
        }
        $number = (float)$matches[1];
        $unit = strtolower($matches[2] ?? '');
        $multiplier = match ($unit) {
            'k' => 1024,
            'm' => 1024 ** 2,
            'g' => 1024 ** 3,
            't' => 1024 ** 4,
            default => 1,
        };
        return (int)round($number * $multiplier);
    }

    public function maxBytes(): int { return $this->maxBytes; }
    public function warningRatio(): float { return $this->warningRatio; }
    public function criticalRatio(): float { return $this->criticalRatio; }
    public function defaultChunkSize(): int { return $this->defaultChunkSize; }
    public function minChunkSize(): int { return $this->minChunkSize; }
    public function maxChunkSize(): int { return $this->maxChunkSize; }
    public function isUnlimited(): bool { return $this->maxBytes <= 0; }
    public function warningBytes(): int { return $this->isUnlimited() ? 0 : (int)floor($this->maxBytes * $this->warningRatio); }
    public function criticalBytes(): int { return $this->isUnlimited() ? 0 : (int)floor($this->maxBytes * $this->criticalRatio); }
}
