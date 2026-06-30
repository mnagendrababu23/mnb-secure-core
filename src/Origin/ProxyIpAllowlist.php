<?php
namespace Mnb\SecurityCore\Origin;

class ProxyIpAllowlist
{
    public function __construct(private ProxyIpRangeSet $ranges, private ?string $updatedAt = null, private int $maxAgeDays = 30) {}

    public static function fromConfig(array $config): self
    {
        $origin = is_array($config['origin_protection'] ?? null) ? $config['origin_protection'] : [];
        $app = is_array($config['app'] ?? null) ? $config['app'] : [];
        return new self(new ProxyIpRangeSet((array)($origin['trusted_proxy_ranges'] ?? $app['trusted_proxies'] ?? [])), $origin['proxy_ip_allowlist_updated_at'] ?? null, (int)($origin['proxy_ip_allowlist_max_age_days'] ?? 30));
    }
    public function ranges(): ProxyIpRangeSet { return $this->ranges; }
    public function freshnessReport(?int $now = null): ProxyIpFreshnessReport { return new ProxyIpFreshnessReport($this->updatedAt, $this->maxAgeDays, $now ?? time()); }
    public function toArray(): array { return ['ranges'=>$this->ranges->ranges(),'freshness'=>$this->freshnessReport()->toArray()]; }
}
