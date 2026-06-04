<?php
namespace Mnb\SecurityCore\Memory;

class MemorySnapshot
{
    public function __construct(
        private int $currentBytes,
        private int $peakBytes,
        private int $limitBytes,
        private string $label = 'snapshot',
        private ?float $time = null
    ) {
        $this->time ??= microtime(true);
    }

    public static function capture(MemoryConfig $config, string $label = 'snapshot'): self
    {
        return new self(memory_get_usage(true), memory_get_peak_usage(true), $config->maxBytes(), $label);
    }

    public function currentBytes(): int { return $this->currentBytes; }
    public function peakBytes(): int { return $this->peakBytes; }
    public function limitBytes(): int { return $this->limitBytes; }
    public function label(): string { return $this->label; }
    public function time(): float { return (float)$this->time; }

    public function currentMb(): float { return round($this->currentBytes / 1048576, 2); }
    public function peakMb(): float { return round($this->peakBytes / 1048576, 2); }
    public function limitMb(): ?float { return $this->limitBytes > 0 ? round($this->limitBytes / 1048576, 2) : null; }

    public function usageRatio(): float
    {
        return $this->limitBytes > 0 ? $this->currentBytes / $this->limitBytes : 0.0;
    }

    public function peakRatio(): float
    {
        return $this->limitBytes > 0 ? $this->peakBytes / $this->limitBytes : 0.0;
    }

    public function toArray(): array
    {
        return [
            'label' => $this->label,
            'current_bytes' => $this->currentBytes,
            'current_mb' => $this->currentMb(),
            'peak_bytes' => $this->peakBytes,
            'peak_mb' => $this->peakMb(),
            'limit_bytes' => $this->limitBytes,
            'limit_mb' => $this->limitMb(),
            'usage_ratio' => round($this->usageRatio(), 4),
            'peak_ratio' => round($this->peakRatio(), 4),
            'time' => $this->time,
        ];
    }
}
