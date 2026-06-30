<?php
namespace Mnb\SecurityCore\Origin;

class FingerprintRiskReport
{
    public function __construct(private array $findings = [], private int $riskScore = 0) {}
    public function passed(): bool { return $this->riskScore === 0; }
    public function findings(): array { return $this->findings; }
    public function riskScore(): int { return $this->riskScore; }
    public function toArray(): array { return ['passed'=>$this->passed(),'risk_score'=>$this->riskScore,'findings'=>$this->findings]; }
}
