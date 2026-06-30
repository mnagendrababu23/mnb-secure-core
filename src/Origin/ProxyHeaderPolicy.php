<?php
namespace Mnb\SecurityCore\Origin;

class ProxyHeaderPolicy
{
    public function __construct(private array $trustedHeaders = [])
    {
        $this->trustedHeaders = array_values(array_unique(array_map('strtolower', $this->trustedHeaders)));
    }

    public static function fromConfig(array $config): self
    {
        $origin = is_array($config['origin_protection'] ?? null) ? $config['origin_protection'] : [];
        $headers = (array)($origin['trusted_proxy_headers'] ?? ProxyProviderProfile::named((string)($origin['proxy_provider'] ?? 'custom'))->headers());
        return new self($headers);
    }

    public function isTrustedHeader(string $name): bool { return in_array(strtolower($name), $this->trustedHeaders, true); }
    public function headers(): array { return $this->trustedHeaders; }
    public function toArray(): array { return ['trusted_headers' => $this->trustedHeaders]; }
}
