<?php
namespace Mnb\SecurityCore\Env;

class SecretRotationReport
{
    /** @param array<int,array<string,mixed>> $items */
    public function __construct(private array $items) {}

    /** @return array<int,array<string,mixed>> */
    public function items(): array { return $this->items; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'passed' => count(array_filter($this->items, fn(array $item): bool => ($item['severity'] ?? '') === 'high')) === 0,
            'items' => $this->items,
        ];
    }
}
