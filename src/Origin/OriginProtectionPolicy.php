<?php
namespace Mnb\SecurityCore\Origin;

use Mnb\SecurityCore\Http\Request;

class OriginProtectionPolicy
{
    public function __construct(private array $config = [], private ?CanonicalHostPolicy $canonical = null) { $this->canonical ??= CanonicalHostPolicy::fromConfig(['origin_protection'=>$config]); }

    public static function fromConfig(array $config): self
    {
        return new self(is_array($config['origin_protection'] ?? null) ? $config['origin_protection'] : [], CanonicalHostPolicy::fromConfig($config));
    }

    public function enabled(): bool { return (bool)($this->config['enabled'] ?? true); }
    public function evaluateRequest(Request $request): OriginProtectionDecision
    {
        if (!$this->enabled()) { return OriginProtectionDecision::allow('origin_protection_disabled'); }
        if (!empty($this->config['block_untrusted_forwarded_headers']) && $request->hasForwardedHeaders() && !$request->isFromTrustedProxy()) {
            return OriginProtectionDecision::block('untrusted_forwarded_headers', 400);
        }
        if (!empty($this->config['require_trusted_proxy']) && !$request->isFromTrustedProxy()) {
            return OriginProtectionDecision::block('trusted_proxy_required', 421);
        }
        $host = $request->effectiveHost();
        if (!empty($this->config['block_direct_ip_host']) && HostExposureGuard::isDirectIpHost($host)) {
            return OriginProtectionDecision::block('direct_ip_host', 421);
        }
        if (!empty($this->config['block_internal_hosts']) && HostExposureGuard::looksInternalHost($host)) {
            return OriginProtectionDecision::block('internal_host', 421);
        }
        return $this->canonical->evaluate($host);
    }

    public function profile(): OriginTrustProfile { return new OriginTrustProfile((string)($this->config['proxy_provider'] ?? 'custom'), (array)($this->config['trusted_proxy_ranges'] ?? []), (array)($this->config['trusted_proxy_headers'] ?? []), (int)($this->config['proxy_ip_allowlist_max_age_days'] ?? 30)); }
    public function toArray(): array { return array_replace(['enabled'=>true], $this->config, ['canonical_policy'=>$this->canonical->toArray()]); }
}
