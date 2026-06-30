<?php
namespace Mnb\SecurityCore\Token;

final class TokenId
{
    public static function generate(string $prefix = 'tok'): string
    {
        return $prefix . '_' . bin2hex(random_bytes(16));
    }

    public static function fingerprint(string $value): string
    {
        return hash('sha256', $value);
    }

    public static function safe(string $value): string
    {
        return preg_replace('/[^a-zA-Z0-9._:-]/', '_', $value) ?: 'token';
    }
}
