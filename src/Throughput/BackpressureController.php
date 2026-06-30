<?php
namespace Mnb\SecurityCore\Throughput;

class BackpressureController
{
    public function __construct(private AdaptiveThrottle $throttle, private DegradationPolicy $degradationPolicy) {}

    public function decide(string $profileName, array $metrics = [], ?string $feature = null): array
    {
        $decision = $this->throttle->decide($profileName, $metrics);
        $degradation = $feature ? $this->degradationPolicy->decide($feature, $decision->decision()) : null;
        return [
            'throttle' => $decision->toArray(),
            'degradation' => $degradation?->toArray(),
        ];
    }
}
