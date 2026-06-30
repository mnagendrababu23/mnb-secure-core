<?php
namespace Mnb\SecurityCore\Queue;

final class IdempotencyKey
{
    public static function normalize(?string $key): ?string
    {
        if ($key === null || trim($key) === '') { return null; }
        return substr(preg_replace('/[^a-zA-Z0-9._:-]/', '_', trim($key)), 0, 160);
    }
}
