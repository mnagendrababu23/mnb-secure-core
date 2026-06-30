<?php
namespace Mnb\SecurityCore\Throughput;

class PerformanceSlo
{
    public function __construct(private string $name, private array $objectives = []) {}

    public static function fromConfig(array $config): self
    {
        $throughput = is_array($config['throughput'] ?? null) ? $config['throughput'] : [];
        $slo = is_array($throughput['slo'] ?? null) ? $throughput['slo'] : [];
        return new self('default', is_array($slo['objectives'] ?? null) ? $slo['objectives'] : []);
    }

    public function objectives(): array { return $this->objectives; }
    public function objective(string $name): array { return is_array($this->objectives[$name] ?? null) ? $this->objectives[$name] : []; }
    public function toArray(): array { return ['name' => $this->name, 'objectives' => $this->objectives]; }
}
