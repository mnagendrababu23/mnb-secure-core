<?php
namespace Mnb\SecurityCore\Data;

class ProtectedPayload
{
    /** @param array<string,mixed> $data @param array<string,mixed> $meta */
    public function __construct(private array $data, private array $meta = []) {}

    /** @return array<string,mixed> */
    public function data(): array { return $this->data; }

    /** @return array<string,mixed> */
    public function meta(): array { return $this->meta; }

    public function metaValue(string $key, mixed $default = null): mixed { return $this->meta[$key] ?? $default; }
}
