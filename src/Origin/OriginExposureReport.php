<?php
namespace Mnb\SecurityCore\Origin;

class OriginExposureReport
{
    public function __construct(private array $findings = []) {}
    public function passed(): bool { return count(array_filter($this->findings, fn($f) => in_array(($f instanceof OriginExposureFinding ? $f->level : ($f['level'] ?? '')), ['critical','high'], true))) === 0; }
    public function riskScore(): int
    {
        $score = 0;
        foreach ($this->findings as $f) { $level = $f instanceof OriginExposureFinding ? $f->level : ($f['level'] ?? 'medium'); $score += ['critical'=>35,'high'=>25,'medium'=>10,'low'=>3][$level] ?? 5; }
        return min(100, $score);
    }
    public function toArray(): array { return ['passed'=>$this->passed(),'risk_score'=>$this->riskScore(),'findings'=>array_map(fn($f)=>$f instanceof OriginExposureFinding?$f->toArray():$f, $this->findings)]; }
}
