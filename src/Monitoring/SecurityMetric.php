<?php
namespace Mnb\SecurityCore\Monitoring;

class SecurityMetric
{
    /** @param array<string,string|int|float|bool|null> $labels */
    public function __construct(public readonly string $name, public readonly float $value, public readonly array $labels = [], public readonly ?string $time = null)
    {
        if (!preg_match('/^[a-z][a-z0-9_:]{1,120}$/', $name)) {
            throw new \InvalidArgumentException('Metric name must be a safe identifier.');
        }
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return ['name' => $this->name, 'value' => $this->value, 'labels' => $this->labels, 'time' => $this->time ?: date('c')];
    }
}
