<?php
namespace Mnb\SecurityCore\Token;

final class TokenMetadata
{
    public function __construct(private array $data = []) {}
    public static function fromArray(array $data): self { return new self($data); }
    public function get(string $key, mixed $default = null): mixed { return $this->data[$key] ?? $default; }
    public function with(string $key, mixed $value): self { $copy = clone $this; $copy->data[$key] = $value; return $copy; }
    public function toArray(): array { return $this->data; }
}
