<?php
namespace Mnb\SecurityCore\Origin;

class OriginExposureScanner
{
    public function __construct(private array $config) {}
    public static function fromConfig(array $config): self { return new self($config); }
    public function scan(): OriginExposureReport
    {
        $origin = is_array($this->config['origin_protection'] ?? null) ? $this->config['origin_protection'] : [];
        $app = is_array($this->config['app'] ?? null) ? $this->config['app'] : [];
        $findings = [];
        if (empty($origin['enabled'])) { $findings[] = new OriginExposureFinding('origin_protection_disabled','high','Origin protection is disabled.','Enable origin_protection.enabled.'); }
        if (empty($origin['block_direct_ip_host'])) { $findings[] = new OriginExposureFinding('direct_ip_host_allowed','high','Direct IP Host requests are not blocked.','Enable block_direct_ip_host.'); }
        if (empty($app['trusted_hosts']) && empty($origin['allowed_public_hosts'])) { $findings[] = new OriginExposureFinding('trusted_hosts_missing','medium','No trusted public hosts are configured.','Configure app.trusted_hosts or origin_protection.allowed_public_hosts.'); }
        if (!empty($origin['require_cdn_or_proxy_in_production']) && empty($origin['cdn_or_proxy_enabled'])) { $findings[] = new OriginExposureFinding('cdn_proxy_missing','medium','CDN/reverse proxy is required but not marked enabled.','Put the app behind a trusted proxy/CDN and set CDN_OR_PROXY_ENABLED=true.'); }
        $trusted = array_filter((array)($origin['trusted_proxy_ranges'] ?? $app['trusted_proxies'] ?? []));
        if (!empty($origin['cdn_or_proxy_enabled']) && $trusted === []) { $findings[] = new OriginExposureFinding('trusted_proxy_ranges_missing','medium','Proxy/CDN mode is enabled but trusted proxy ranges are empty.','Configure trusted proxy CIDR ranges.'); }
        $allowlist = ProxyIpAllowlist::fromConfig($this->config);
        foreach ($allowlist->ranges()->invalidRanges() as $range) { $findings[] = new OriginExposureFinding('invalid_proxy_range','medium','Invalid trusted proxy range: ' . $range,'Use valid IP/CIDR ranges.'); }
        if (!$allowlist->freshnessReport()->passed()) { $findings[] = new OriginExposureFinding('proxy_allowlist_freshness_unknown','low','Proxy allow-list freshness cannot be verified.','Record proxy_ip_allowlist_updated_at when ranges are imported.'); }
        return new OriginExposureReport($findings);
    }
}
