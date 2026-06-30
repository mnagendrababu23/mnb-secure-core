<?php
namespace Mnb\SecurityCore\Trust;

class TrustZone
{
    public const PUBLIC = 'public';
    public const AUTHENTICATED = 'authenticated';
    public const SCHOOL_ADMIN = 'school_admin';
    public const SUPER_ADMIN = 'super_admin';
    public const INTERNAL_SYSTEM = 'internal_system';

    /** @return list<string> */
    public static function values(): array
    {
        return [self::PUBLIC, self::AUTHENTICATED, self::SCHOOL_ADMIN, self::SUPER_ADMIN, self::INTERNAL_SYSTEM];
    }

    public static function isValid(string $zone): bool
    {
        return in_array($zone, self::values(), true);
    }
}
