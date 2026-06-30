<?php
namespace Mnb\SecurityCore\Token;

final class TokenStatus
{
    public const ACTIVE = 'active';
    public const REVOKED = 'revoked';
    public const EXPIRED = 'expired';
    public const ROTATED = 'rotated';
    public const REUSED = 'reused';
    public const COMPROMISED = 'compromised';

    public static function active(string $status): bool
    {
        return $status === self::ACTIVE;
    }
}
