<?php
namespace Mnb\SecurityCore\Queue;

final class JobStatus
{
    public const QUEUED = 'queued';
    public const RESERVED = 'reserved';
    public const RUNNING = 'running';
    public const SUCCEEDED = 'succeeded';
    public const FAILED = 'failed';
    public const RETRYING = 'retrying';
    public const DEAD_LETTERED = 'dead_lettered';
    public const CANCELLED = 'cancelled';
    public const EXPIRED = 'expired';

    public static function all(): array
    {
        return [self::QUEUED, self::RESERVED, self::RUNNING, self::SUCCEEDED, self::FAILED, self::RETRYING, self::DEAD_LETTERED, self::CANCELLED, self::EXPIRED];
    }
}
