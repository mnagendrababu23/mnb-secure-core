<?php
namespace Mnb\SecurityCore\Memory;

class StreamBudget
{
    public function __construct(
        private int $maxReadBytes = 10485760,
        private int $maxWriteBytes = 52428800,
        private int $bufferSize = 8192,
        private bool $failClosed = true
    ) {}

    public static function fromArray(array $config): self
    {
        return new self(
            max(1, (int)($config['max_read_bytes'] ?? 10485760)),
            max(1, (int)($config['max_write_bytes'] ?? 52428800)),
            max(1, (int)($config['buffer_size'] ?? 8192)),
            !array_key_exists('fail_closed', $config) || (bool)$config['fail_closed']
        );
    }

    public function maxReadBytes(): int { return $this->maxReadBytes; }
    public function maxWriteBytes(): int { return $this->maxWriteBytes; }
    public function bufferSize(): int { return $this->bufferSize; }
    public function failClosed(): bool { return $this->failClosed; }
    public function toArray(): array { return ['max_read_bytes' => $this->maxReadBytes, 'max_write_bytes' => $this->maxWriteBytes, 'buffer_size' => $this->bufferSize, 'fail_closed' => $this->failClosed]; }
}
