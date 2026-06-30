<?php
namespace Mnb\SecurityCore\Origin;

class CanonicalHostPolicy
{
    public function __construct(private string $canonicalHost = '', private array $allowedHosts = [], private bool $redirect = false, private bool $blockUnknown = true)
    {
        $this->canonicalHost = HostExposureGuard::normalizeHost($canonicalHost);
        $this->allowedHosts = array_values(array_unique(array_filter(array_map([HostExposureGuard::class, 'normalizeHost'], $allowedHosts))));
    }
    public static function fromConfig(array $config): self
    {
        $origin = is_array($config['origin_protection'] ?? null) ? $config['origin_protection'] : [];
        $app = is_array($config['app'] ?? null) ? $config['app'] : [];
        return new self((string)($origin['canonical_host'] ?? ''), (array)($origin['allowed_public_hosts'] ?? $app['trusted_hosts'] ?? []), !empty($origin['redirect_to_canonical_host']), (bool)($origin['block_unknown_hosts'] ?? true));
    }
    public function evaluate(string $host): OriginProtectionDecision
    {
        $host = HostExposureGuard::normalizeHost($host);
        if ($this->canonicalHost !== '' && $host !== $this->canonicalHost && in_array($host, $this->allowedHosts, true) && $this->redirect) {
            return OriginProtectionDecision::redirect($this->canonicalHost);
        }
        if ($this->allowedHosts !== [] && !in_array($host, $this->allowedHosts, true) && $host !== $this->canonicalHost) {
            return $this->blockUnknown ? OriginProtectionDecision::block('unknown_host', 400) : OriginProtectionDecision::allow('unknown_host_allowed');
        }
        return OriginProtectionDecision::allow('host_allowed');
    }
    public function toArray(): array { return ['canonical_host'=>$this->canonicalHost,'allowed_public_hosts'=>$this->allowedHosts,'redirect_to_canonical_host'=>$this->redirect,'block_unknown_hosts'=>$this->blockUnknown]; }
}
