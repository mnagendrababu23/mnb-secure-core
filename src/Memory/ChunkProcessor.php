<?php
namespace Mnb\SecurityCore\Memory;

class ChunkProcessor
{
    public function __construct(private ?MemoryGuard $guard = null) {}

    public function process(iterable $items, callable $callback, int $chunkSize = 500, string $operation = 'chunked_process'): array
    {
        $chunkSize = max(1, $chunkSize);
        $chunk = [];
        $processed = 0;
        $chunks = 0;
        $peak = memory_get_peak_usage(true);

        foreach ($items as $item) {
            $chunk[] = $item;
            if (count($chunk) >= $chunkSize) {
                $callback($chunk, $chunks + 1);
                $processed += count($chunk);
                $chunks++;
                $chunk = [];
                $this->guard?->assertWithinBudget($operation);
                $peak = max($peak, memory_get_peak_usage(true));
            }
        }

        if ($chunk) {
            $callback($chunk, $chunks + 1);
            $processed += count($chunk);
            $chunks++;
            $this->guard?->assertWithinBudget($operation);
            $peak = max($peak, memory_get_peak_usage(true));
        }

        return [
            'processed' => $processed,
            'chunks' => $chunks,
            'chunk_size' => $chunkSize,
            'peak_bytes' => $peak,
            'peak_mb' => round($peak / 1048576, 2),
        ];
    }

    public static function lazyRange(int $start, int $end): iterable
    {
        for ($i = $start; $i <= $end; $i++) {
            yield $i;
        }
    }
}
