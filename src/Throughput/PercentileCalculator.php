<?php
namespace Mnb\SecurityCore\Throughput;

class PercentileCalculator
{
    /** @param array<int,float|int> $values */
    public function percentile(array $values, float $percentile): float
    {
        if ($values === []) { return 0.0; }
        sort($values, SORT_NUMERIC);
        $index = min(count($values) - 1, max(0, (int)ceil(count($values) * ($percentile / 100)) - 1));
        return round((float)$values[$index], 3);
    }

    public function summary(array $values): array
    {
        if ($values === []) { return ['count' => 0, 'p50' => 0.0, 'p90' => 0.0, 'p95' => 0.0, 'p99' => 0.0, 'max' => 0.0, 'avg' => 0.0]; }
        return [
            'count' => count($values),
            'p50' => $this->percentile($values, 50),
            'p90' => $this->percentile($values, 90),
            'p95' => $this->percentile($values, 95),
            'p99' => $this->percentile($values, 99),
            'max' => round((float)max($values), 3),
            'avg' => round(array_sum($values) / count($values), 3),
        ];
    }
}
