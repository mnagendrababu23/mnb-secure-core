<?php
namespace Mnb\SecurityCore\Production;

final class ProductionReadinessReport
{
    /** @param list<array<string,mixed>> $checks */
    public function __construct(private array $checks) {}
    public function passed(): bool
    {
        foreach ($this->checks as $check) {
            if (($check['level'] ?? 'info') === 'high' && empty($check['passed'])) return false;
            if (($check['level'] ?? 'info') === 'critical' && empty($check['passed'])) return false;
        }
        return true;
    }
    public function toArray(): array
    {
        $failed = array_values(array_filter($this->checks, fn(array $c): bool => empty($c['passed'])));
        return ['passed' => $this->passed(), 'score' => $this->score(), 'failed_count' => count($failed), 'checks' => $this->checks, 'failed' => $failed];
    }
    private function score(): float
    {
        if ($this->checks === []) return 100.0;
        $passed = count(array_filter($this->checks, fn(array $c): bool => !empty($c['passed'])));
        return round(($passed / count($this->checks)) * 100, 2);
    }
}
