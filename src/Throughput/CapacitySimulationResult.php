<?php
namespace Mnb\SecurityCore\Throughput;

class CapacitySimulationResult
{
    public function __construct(private LoadTestProfile $profile, private array $plan, private array $risk) {}

    public function toArray(): array
    {
        return ['profile' => $this->profile->toArray(), 'capacity_plan' => $this->plan, 'risk' => $this->risk];
    }
}
