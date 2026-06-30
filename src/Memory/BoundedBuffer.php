<?php
namespace Mnb\SecurityCore\Memory;

use RuntimeException;

class BoundedBuffer
{
    private array $items = [];
    public function __construct(private int $maxItems = 500, private mixed $onFlush = null)
    {
        if ($this->maxItems < 1) { throw new RuntimeException('Bounded buffer maxItems must be positive.'); }
    }
    public function push(mixed $item): void
    {
        if (count($this->items) >= $this->maxItems) {
            if ($this->onFlush) { $this->flush(); }
            else { throw new RuntimeException('Bounded buffer capacity exceeded.'); }
        }
        $this->items[] = $item;
    }
    public function isFull(): bool { return count($this->items) >= $this->maxItems; }
    public function count(): int { return count($this->items); }
    public function items(): array { return $this->items; }
    public function flush(): array
    {
        $items = $this->items;
        $this->items = [];
        if ($this->onFlush) { ($this->onFlush)($items); }
        return $items;
    }
}
