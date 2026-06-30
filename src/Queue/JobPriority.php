<?php
namespace Mnb\SecurityCore\Queue;

final class JobPriority
{
    public const LOW = 'low';
    public const NORMAL = 'normal';
    public const HIGH = 'high';
    public const CRITICAL = 'critical';

    public static function normalize(string $priority): string
    {
        return in_array($priority, [self::LOW, self::NORMAL, self::HIGH, self::CRITICAL], true) ? $priority : self::NORMAL;
    }

    public static function weight(string $priority): int
    {
        return match (self::normalize($priority)) {
            self::CRITICAL => 4,
            self::HIGH => 3,
            self::NORMAL => 2,
            default => 1,
        };
    }
}
