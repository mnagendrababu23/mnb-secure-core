<?php
namespace Mnb\SecurityCore\Origin;

class ProxyIpFreshnessReport
{
    public function __construct(private ?string $updatedAt, private int $maxAgeDays, private int $now) {}
    public function ageDays(): ?int
    {
        if (!$this->updatedAt) { return null; }
        $ts = strtotime($this->updatedAt);
        return $ts === false ? null : max(0, (int)floor(($this->now - $ts) / 86400));
    }
    public function passed(): bool { $age = $this->ageDays(); return $age !== null && $age <= $this->maxAgeDays; }
    public function toArray(): array
    {
        $age = $this->ageDays();
        return ['passed'=>$this->passed(),'updated_at'=>$this->updatedAt,'age_days'=>$age,'max_age_days'=>$this->maxAgeDays,'warnings'=>$age === null ? ['proxy allow-list freshness date is missing'] : ($age > $this->maxAgeDays ? ['proxy allow-list is stale'] : [])];
    }
}
