<?php
namespace Mnb\SecurityCore\Throughput;

class FeatureLoadShedder
{
    public function __construct(private DegradationPolicy $policy) {}

    public function shouldDisable(string $feature, string $pressure = 'critical'): bool
    {
        return $this->policy->decide($feature, $pressure)->decision() === 'degrade';
    }

    public function decision(string $feature, string $pressure = 'critical'): DegradationDecision
    {
        return $this->policy->decide($feature, $pressure);
    }
}
