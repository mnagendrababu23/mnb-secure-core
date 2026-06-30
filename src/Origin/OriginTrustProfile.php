<?php
namespace Mnb\SecurityCore\Origin;

class OriginTrustProfile
{
    public function __construct(
        private string $provider = 'custom',
        private array $trustedProxyRanges = [],
        private array $trustedHeaders = [],
        private int $maxAgeDays = 30
    ) {}

    public static function fromConfig(array $config): self
    {
        $origin = is_array($config['origin_protection'] ?? null) ? $config['origin_protection'] : [];
        $app = is_array($config['app'] ?? null) ? $config['app'] : [];
        return new self(
            (string)($origin['proxy_provider'] ?? 'custom'),
            array_values(array_filter(array_map('strval', (array)($origin['trusted_proxy_ranges'] ?? $app['trusted_proxies'] ?? [])))),
            array_values(array_filter(array_map('strtolower', (array)($origin['trusted_proxy_headers'] ?? [])))),
            (int)($origin['proxy_ip_allowlist_max_age_days'] ?? 30)
        );
    }

    public function provider(): string { return $this->provider; }
    public function trustedProxyRanges(): array { return $this->trustedProxyRanges; }
    public function trustedHeaders(): array { return $this->trustedHeaders; }
    public function maxAgeDays(): int { return $this->maxAgeDays; }
    public function toArray(): array { return ['provider'=>$this->provider,'trusted_proxy_ranges'=>$this->trustedProxyRanges,'trusted_headers'=>$this->trustedHeaders,'max_age_days'=>$this->maxAgeDays]; }
}
