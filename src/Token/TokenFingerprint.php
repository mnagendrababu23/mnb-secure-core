<?php
namespace Mnb\SecurityCore\Token;

final class TokenFingerprint
{
    public static function fromToken(string $token): string { return hash('sha256', $token); }
    public static function fromContext(string $userAgent = '', string $ipPrefix = ''): string { return hash('sha256', strtolower($userAgent) . '|' . $ipPrefix); }
    public static function matches(string $expected, string $actual): bool { return hash_equals($expected, $actual); }
}
