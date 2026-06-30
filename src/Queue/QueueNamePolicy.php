<?php
namespace Mnb\SecurityCore\Queue;

final class QueueNamePolicy
{
    public static function valid(string $name): bool
    {
        return $name !== '' && (bool)preg_match('/^[a-zA-Z0-9._:-]{1,80}$/', $name);
    }
}
