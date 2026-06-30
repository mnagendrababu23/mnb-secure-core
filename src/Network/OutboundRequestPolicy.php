<?php
namespace Mnb\SecurityCore\Network;

final class OutboundRequestPolicy
{
    public function __construct(
        private bool $enabled = true,
        private bool $httpsOnly = true,
        private array $allowedSchemes = ['https'],
        private array $allowedHosts = [],
        private array $blockedHosts = ['localhost'],
        private bool $blockPrivateIps = true,
        private bool $blockLoopbackIps = true,
        private bool $blockLinkLocalIps = true,
        private bool $blockMetadataIps = true,
        private int $maxRedirects = 3,
        private int $timeoutSeconds = 5,
        private int $maxResponseBytes = 1048576,
        private string $userAgent = 'mnb-secure-core/1.0.1'
    ) {
        $this->allowedSchemes = array_values(array_unique(array_map('strtolower', array_map('strval', $allowedSchemes))));
        $this->allowedHosts = self::stringList($allowedHosts);
        $this->blockedHosts = self::stringList($blockedHosts ?: ['localhost']);
        $this->maxRedirects = max(0, $maxRedirects);
        $this->timeoutSeconds = max(1, $timeoutSeconds);
        $this->maxResponseBytes = max(1024, $maxResponseBytes);
    }

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config): self
    {
        $network = is_array($config['network']['outbound'] ?? null) ? $config['network']['outbound'] : [];
        return new self(
            !array_key_exists('enabled', $network) || $network['enabled'] !== false,
            !array_key_exists('https_only', $network) || $network['https_only'] !== false,
            self::stringList($network['allowed_schemes'] ?? ['https']),
            self::stringList($network['allowed_hosts'] ?? []),
            self::stringList($network['blocked_hosts'] ?? ['localhost']),
            !array_key_exists('block_private_ips', $network) || $network['block_private_ips'] !== false,
            !array_key_exists('block_loopback_ips', $network) || $network['block_loopback_ips'] !== false,
            !array_key_exists('block_link_local_ips', $network) || $network['block_link_local_ips'] !== false,
            !array_key_exists('block_metadata_ips', $network) || $network['block_metadata_ips'] !== false,
            (int)($network['max_redirects'] ?? 3),
            (int)($network['timeout_seconds'] ?? 5),
            (int)($network['max_response_bytes'] ?? 1048576),
            (string)($network['user_agent'] ?? 'mnb-secure-core/1.0.1')
        );
    }

    /** @return array{passed:bool,url:string,scheme:?string,host:?string,resolved_ips:array<int,string>,reason:?string} */
    public function checkUrl(string $url): array
    {
        $url = trim($url);
        $parts = parse_url($url);
        if (!$this->enabled) {
            return $this->deny($url, null, null, [], 'outbound_network_disabled');
        }
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return $this->deny($url, null, null, [], 'invalid_url');
        }
        $scheme = strtolower((string)$parts['scheme']);
        $host = strtolower((string)$parts['host']);
        if ($this->httpsOnly && $scheme !== 'https') {
            return $this->deny($url, $scheme, $host, [], 'https_required');
        }
        if (!in_array($scheme, $this->allowedSchemes, true)) {
            return $this->deny($url, $scheme, $host, [], 'scheme_not_allowed');
        }

        $hostPolicy = new AllowedHostPolicy($this->allowedHosts, $this->blockedHosts);
        if (!$hostPolicy->isAllowed($host)) {
            return $this->deny($url, $scheme, $host, [], $hostPolicy->isBlocked($host) ? 'host_blocked' : 'host_not_allowed');
        }

        $ipPolicy = new BlockedIpRangePolicy($this->blockPrivateIps, $this->blockLoopbackIps, $this->blockLinkLocalIps, $this->blockMetadataIps);
        $dns = (new DnsResolutionGuard($ipPolicy))->check($host);
        if (!$dns['passed']) {
            return $this->deny($url, $scheme, $host, $dns['ips'], (string)$dns['reason']);
        }

        return ['passed' => true, 'url' => $url, 'scheme' => $scheme, 'host' => $host, 'resolved_ips' => $dns['ips'], 'reason' => null];
    }

    public function maxRedirects(): int { return $this->maxRedirects; }
    public function timeoutSeconds(): int { return $this->timeoutSeconds; }
    public function maxResponseBytes(): int { return $this->maxResponseBytes; }
    public function userAgent(): string { return $this->userAgent; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'enabled' => $this->enabled,
            'https_only' => $this->httpsOnly,
            'allowed_schemes' => $this->allowedSchemes,
            'allowed_hosts' => $this->allowedHosts,
            'blocked_hosts' => $this->blockedHosts,
            'block_private_ips' => $this->blockPrivateIps,
            'block_loopback_ips' => $this->blockLoopbackIps,
            'block_link_local_ips' => $this->blockLinkLocalIps,
            'block_metadata_ips' => $this->blockMetadataIps,
            'max_redirects' => $this->maxRedirects,
            'timeout_seconds' => $this->timeoutSeconds,
            'max_response_bytes' => $this->maxResponseBytes,
            'user_agent' => $this->userAgent,
        ];
    }

    /** @return array<int,string> */
    private static function stringList(mixed $value): array
    {
        if (is_string($value)) {
            $value = array_filter(array_map('trim', explode(',', $value)));
        }
        if (!is_array($value)) {
            return [];
        }
        $out = [];
        foreach ($value as $item) {
            if (is_scalar($item) && trim((string)$item) !== '') {
                $out[] = strtolower(trim((string)$item));
            }
        }
        return array_values(array_unique($out));
    }

    /** @return array{passed:bool,url:string,scheme:?string,host:?string,resolved_ips:array<int,string>,reason:string} */
    private function deny(string $url, ?string $scheme, ?string $host, array $ips, string $reason): array
    {
        return ['passed' => false, 'url' => $url, 'scheme' => $scheme, 'host' => $host, 'resolved_ips' => $ips, 'reason' => $reason];
    }
}
