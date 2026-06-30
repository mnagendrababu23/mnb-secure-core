<?php
namespace Mnb\SecurityCore\Origin;

use Mnb\SecurityCore\Security\ServerIdentityHider;

class HostExposureGuard
{
    public static function normalizeHost(string $host): string { return ServerIdentityHider::normalizeHost($host); }
    public static function isDirectIpHost(string $host): bool { return ServerIdentityHider::isIpAddressHost($host); }
    public static function isPrivateOrReservedIpHost(string $host): bool { return self::isDirectIpHost($host) && ServerIdentityHider::isPrivateOrReservedIp($host); }
    public static function looksInternalHost(string $host): bool
    {
        $host = self::normalizeHost($host);
        return $host === 'localhost' || str_ends_with($host, '.local') || str_ends_with($host, '.internal') || str_contains($host, '.lan') || self::isPrivateOrReservedIpHost($host);
    }
}
