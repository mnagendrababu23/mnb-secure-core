<?php
namespace Mnb\SecurityCore\Queue;

final class JobPayload
{
    public function __construct(private array $data = []) {}

    public static function fromArray(array $data): self { return new self($data); }
    public function all(): array { return $this->data; }
    public function bytes(): int { return strlen(json_encode($this->data, JSON_UNESCAPED_SLASHES) ?: ''); }
    public function toArray(): array { return $this->data; }
}
