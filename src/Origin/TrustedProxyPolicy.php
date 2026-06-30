<?php
namespace Mnb\SecurityCore\Origin;

use Mnb\SecurityCore\Http\RequestTrust;

class TrustedProxyPolicy
{
    public function __construct(private array $ranges = [])
    {
        $this->ranges = RequestTrust::normalizeTrustedProxies($ranges);
    }

    public static function fromConfig(array $config): self
    {
        $origin = is_array($config['origin_protection'] ?? null) ? $config['origin_protection'] : [];
        $app = is_array($config['app'] ?? null) ? $config['app'] : [];
        return new self((array)($origin['trusted_proxy_ranges'] ?? $app['trusted_proxies'] ?? []));
    }

    public function ranges(): array { return $this->ranges; }
    public function hasRanges(): bool { return $this->ranges !== []; }
    public function isTrusted(string $ip): bool { return RequestTrust::isTrustedProxy($ip, $this->ranges); }
    public function toArray(): array { return ['trusted_proxy_ranges' => $this->ranges, 'configured' => $this->hasRanges()]; }
}
