<?php
namespace Mnb\SecurityCore\Memory;

class CleanupStack
{
    private array $callbacks = [];
    public function push(callable $callback): void { $this->callbacks[] = $callback; }
    public function run(): int
    {
        $count = 0;
        while ($callback = array_pop($this->callbacks)) {
            try { $callback(); $count++; } catch (\Throwable) {}
        }
        return $count;
    }
    public function count(): int { return count($this->callbacks); }
}
