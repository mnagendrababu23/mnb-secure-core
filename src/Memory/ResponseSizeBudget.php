<?php
namespace Mnb\SecurityCore\Memory;

class ResponseSizeBudget
{
    public function __construct(private int $maxBufferBytes = 1048576, private bool $failClosed = true) {}
    public static function fromArray(array $config): self { return new self((int)($config['max_buffer_bytes'] ?? 1048576), !array_key_exists('fail_closed', $config) || (bool)$config['fail_closed']); }
    public function maxBufferBytes(): int { return $this->maxBufferBytes; }
    public function failClosed(): bool { return $this->failClosed; }
    public function toArray(): array { return ['max_buffer_bytes' => $this->maxBufferBytes, 'fail_closed' => $this->failClosed]; }
}
