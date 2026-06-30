<?php
namespace Mnb\SecurityCore\Queue;

final class JobId
{
    public static function generate(): string
    {
        return 'job_' . bin2hex(random_bytes(12));
    }
}
