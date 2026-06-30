<?php
namespace Mnb\SecurityCore\RateLimit;

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Http\Request;

class RateLimitKeyBuilder
{
    public static function forRequest(Request $request, RateLimitPolicy $policy, ?string $routeName = null): string
    {
        $parts = [$policy->prefix(), $policy->name()];
        $routeName = $routeName ?: self::routeName($request);

        foreach ($policy->keyBy() as $part) {
            $parts[] = match ($part) {
                'ip' => 'ip:' . self::safePart($request->ip()),
                'user' => 'user:' . self::safePart(self::userId($request)),
                'auth' => 'auth:' . self::safePart(self::authIdentity($request)),
                'route' => 'route:' . self::safePart($routeName ?: $request->path()),
                'path' => 'path:' . self::safePart($request->path()),
                'method' => 'method:' . self::safePart($request->method()),
                default => $part . ':unknown',
            };
        }

        return implode(':', $parts);
    }

    private static function routeName(Request $request): ?string
    {
        foreach (['route_name', 'route', 'matched_route'] as $attribute) {
            $value = $request->attribute($attribute);
            if (is_string($value) && trim($value) !== '') {
                return $value;
            }
        }
        return null;
    }

    private static function userId(Request $request): string
    {
        $auth = $request->attribute(AuthContext::ATTRIBUTE);
        if ($auth instanceof AuthContext && $auth->isAuthenticated() && $auth->id() !== null) {
            return (string)$auth->id();
        }

        $userId = $request->attribute('auth_user_id');
        if (is_int($userId) || is_string($userId)) {
            $userId = trim((string)$userId);
            if ($userId !== '') {
                return $userId;
            }
        }

        return 'guest';
    }

    private static function authIdentity(Request $request): string
    {
        $auth = $request->attribute(AuthContext::ATTRIBUTE);
        if ($auth instanceof AuthContext && $auth->isAuthenticated() && $auth->id() !== null) {
            return 'user-' . $auth->id();
        }

        $token = $request->attribute('auth_token');
        if (is_array($token) && isset($token['id'])) {
            return 'token-' . (string)$token['id'];
        }

        return self::userId($request);
    }

    private static function safePart(string $part): string
    {
        $part = trim($part);
        if ($part === '') {
            return 'none';
        }

        $safe = preg_replace('/[^A-Za-z0-9_.:@-]+/', '-', $part) ?: 'none';
        return trim($safe, '-') ?: 'none';
    }
}
