<?php
namespace Mnb\SecurityCore\Network;

final class BlockedIpRangePolicy
{
    public function __construct(
        private bool $blockPrivate = true,
        private bool $blockLoopback = true,
        private bool $blockLinkLocal = true,
        private bool $blockMetadata = true
    ) {}

    /** @return array{blocked:bool,reason:?string} */
    public function check(string $ip): array
    {
        $ip = trim($ip, '[]');
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['blocked' => true, 'reason' => 'invalid_ip'];
        }
        if ($this->blockMetadata && $this->isMetadata($ip)) {
            return ['blocked' => true, 'reason' => 'metadata_ip_blocked'];
        }
        if ($this->blockLoopback && $this->isLoopback($ip)) {
            return ['blocked' => true, 'reason' => 'loopback_ip_blocked'];
        }
        if ($this->blockPrivate && $this->isPrivate($ip)) {
            return ['blocked' => true, 'reason' => 'private_ip_blocked'];
        }
        if ($this->blockLinkLocal && $this->isLinkLocal($ip)) {
            return ['blocked' => true, 'reason' => 'link_local_ip_blocked'];
        }
        if ($this->isUnspecified($ip)) {
            return ['blocked' => true, 'reason' => 'unspecified_ip_blocked'];
        }
        return ['blocked' => false, 'reason' => null];
    }

    private function isLoopback(string $ip): bool
    {
        return $this->cidr($ip, '127.0.0.0/8') || $ip === '::1';
    }

    private function isPrivate(string $ip): bool
    {
        return $this->cidr($ip, '10.0.0.0/8')
            || $this->cidr($ip, '172.16.0.0/12')
            || $this->cidr($ip, '192.168.0.0/16')
            || $this->cidr($ip, 'fc00::/7');
    }

    private function isLinkLocal(string $ip): bool
    {
        return $this->cidr($ip, '169.254.0.0/16') || $this->cidr($ip, 'fe80::/10');
    }

    private function isMetadata(string $ip): bool
    {
        return $ip === '169.254.169.254' || $ip === '100.100.100.200';
    }

    private function isUnspecified(string $ip): bool
    {
        return $ip === '0.0.0.0' || $ip === '::';
    }

    private function cidr(string $ip, string $cidr): bool
    {
        [$network, $bits] = explode('/', $cidr, 2);
        $ipBin = @inet_pton($ip);
        $networkBin = @inet_pton($network);
        if ($ipBin === false || $networkBin === false || strlen($ipBin) !== strlen($networkBin)) {
            return false;
        }
        $bits = (int)$bits;
        $bytes = intdiv($bits, 8);
        $remainder = $bits % 8;
        if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($networkBin, 0, $bytes)) {
            return false;
        }
        if ($remainder === 0) {
            return true;
        }
        $mask = (0xff << (8 - $remainder)) & 0xff;
        return (ord($ipBin[$bytes]) & $mask) === (ord($networkBin[$bytes]) & $mask);
    }
}
