<?php
namespace Mnb\SecurityCore\Memory;

use Mnb\SecurityCore\Contracts\LoggerInterface;

class MemoryMonitor
{
    private array $snapshots = [];

    public function __construct(
        private MemoryGuard $guard,
        private ?LoggerInterface $logger = null
    ) {}

    public function mark(string $label): MemorySnapshot
    {
        $snapshot = $this->guard->snapshot($label);
        $this->snapshots[] = $snapshot;
        $this->logger?->info('Memory snapshot', $snapshot->toArray());
        return $snapshot;
    }

    public function report(): array
    {
        return array_map(fn(MemorySnapshot $snapshot) => $snapshot->toArray(), $this->snapshots);
    }

    public function highestPeakBytes(): int
    {
        $peaks = array_map(fn(MemorySnapshot $snapshot) => $snapshot->peakBytes(), $this->snapshots);
        return $peaks ? max($peaks) : 0;
    }
}
