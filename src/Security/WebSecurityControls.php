<?php
namespace Mnb\SecurityCore\Security;

class WebSecurityControls
{
    public static function escape(mixed $value): string
    {
        return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function validateRedirect(string $path, string $fallback = '/'): string
    {
        if ($path === '' || preg_match('/^https?:\/\//i', $path) || str_starts_with($path, '//')) {
            return $fallback;
        }
        return str_starts_with($path, '/') ? $path : $fallback;
    }
}
