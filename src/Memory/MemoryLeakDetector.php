<?php
namespace Mnb\SecurityCore\Memory;

class MemoryLeakDetector
{
    private ?int $baselineBytes = null;
    public function start(): int { return $this->baselineBytes = memory_get_usage(true); }
    public function analyze(?int $startBytes = null, ?int $endBytes = null, int $thresholdBytes = 67108864): array
    {
        $start = $startBytes ?? $this->baselineBytes ?? memory_get_usage(true);
        $end = $endBytes ?? memory_get_usage(true);
        $growth = max(0, $end - $start);
        return ['passed' => $growth < $thresholdBytes, 'restart_recommended' => $growth >= $thresholdBytes, 'start_bytes' => $start, 'end_bytes' => $end, 'growth_bytes' => $growth, 'growth_mb' => round($growth / 1048576, 2), 'threshold_bytes' => $thresholdBytes];
    }
}
