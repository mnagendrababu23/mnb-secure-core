<?php
namespace Mnb\SecurityCore\Session;

final class SessionFingerprint
{
    public static function create(string $userAgent = '', string $ip = ''): string
    {
        $prefix = preg_replace('/\.\d+$/', '.0', $ip);
        return hash('sha256', strtolower($userAgent) . '|' . $prefix);
    }
    public static function matches(string $expected, string $actual): bool { return hash_equals($expected, $actual); }
}
