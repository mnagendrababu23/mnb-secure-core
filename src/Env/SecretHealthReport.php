<?php
namespace Mnb\SecurityCore\Env;

class SecretHealthReport
{
    /** @param array<int,array<string,mixed>> $items */
    public function __construct(private array $items) {}

    /** @return array<int,array<string,mixed>> */
    public function items(): array
    {
        return $this->items;
    }

    public function passed(): bool
    {
        foreach ($this->items as $item) {
            if (in_array($item['status'] ?? '', ['missing', 'weak', 'invalid'], true) && !empty($item['required'])) {
                return false;
            }
            if (($item['severity'] ?? '') === 'high') {
                return false;
            }
        }
        return true;
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'passed' => $this->passed(),
            'items' => $this->items,
            'summary' => [
                'total' => count($this->items),
                'present' => count(array_filter($this->items, fn(array $i): bool => ($i['present'] ?? false) === true)),
                'missing' => count(array_filter($this->items, fn(array $i): bool => ($i['status'] ?? '') === 'missing')),
                'weak' => count(array_filter($this->items, fn(array $i): bool => ($i['status'] ?? '') === 'weak')),
            ],
        ];
    }
}
