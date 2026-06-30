<?php
namespace Mnb\SecurityCore\Memory;

use RuntimeException;

class ArrayDepthGuard
{
    public function __construct(private int $maxDepth = 32) {}
    public function assertWithinDepth(array $value): void
    {
        if ($this->depth($value) > $this->maxDepth) { throw new RuntimeException('Array depth limit exceeded.'); }
    }
    public function depth(array $value): int
    {
        $max = 1;
        foreach ($value as $item) {
            if (is_array($item)) { $max = max($max, 1 + $this->depth($item)); }
        }
        return $max;
    }
    public function maxDepth(): int { return $this->maxDepth; }
}
