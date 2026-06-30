<?php
namespace Mnb\SecurityCore\Session;

final class SessionId
{
    public static function generate(): string { return 'sess_' . bin2hex(random_bytes(18)); }
    public static function safe(string $value): string { return preg_replace('/[^a-zA-Z0-9._:-]/', '_', $value) ?: 'session'; }
}
