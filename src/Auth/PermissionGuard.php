<?php
namespace Mnb\SecurityCore\Auth;

use Mnb\SecurityCore\Exceptions\AuthorizationException;
use Mnb\SecurityCore\Http\Request;

class PermissionGuard
{
    public static function context(Request|AuthContext|null $subject): AuthContext
    {
        if ($subject instanceof AuthContext) {
            return $subject;
        }

        if (!$subject instanceof Request) {
            return AuthContext::guest();
        }

        $auth = $subject->attribute(AuthContext::ATTRIBUTE);
        if ($auth instanceof AuthContext) {
            return $auth;
        }

        $userId = $subject->attribute('auth_user_id');
        $scopes = $subject->attribute('auth_scopes', []);
        $token = $subject->attribute('auth_token');

        if ($userId !== null || (is_array($scopes) && $scopes !== [])) {
            return new AuthContext(
                true,
                $userId,
                is_array($scopes) ? $scopes : [],
                is_array($token['permissions'] ?? null) ? $token['permissions'] : [],
                is_array($token['roles'] ?? null) ? $token['roles'] : [],
                is_array($token) ? $token : null
            );
        }

        return AuthContext::guest();
    }

    public static function isAuthenticated(Request|AuthContext|null $subject): bool
    {
        return self::context($subject)->isAuthenticated();
    }

    public static function requireAuthenticated(Request|AuthContext|null $subject): AuthContext
    {
        $auth = self::context($subject);
        if (!$auth->isAuthenticated()) {
            throw new AuthorizationException('Authentication required', 'Authentication is required.');
        }
        return $auth;
    }

    public static function hasScope(Request|AuthContext|null $subject, string $scope): bool
    {
        return self::context($subject)->hasScope($scope);
    }

    public static function requireScope(Request|AuthContext|null $subject, string $scope): AuthContext
    {
        $auth = self::requireAuthenticated($subject);
        if (!$auth->hasScope($scope)) {
            throw new AuthorizationException("Required scope missing: {$scope}");
        }
        return $auth;
    }

    /** @param array<int,string> $scopes */
    public static function requireAnyScope(Request|AuthContext|null $subject, array $scopes): AuthContext
    {
        $auth = self::requireAuthenticated($subject);
        if (!$auth->hasAnyScope($scopes)) {
            throw new AuthorizationException('Required scope missing: any of ' . implode(', ', $scopes));
        }
        return $auth;
    }

    /** @param array<int,string> $scopes */
    public static function requireAllScopes(Request|AuthContext|null $subject, array $scopes): AuthContext
    {
        $auth = self::requireAuthenticated($subject);
        if (!$auth->hasAllScopes($scopes)) {
            throw new AuthorizationException('Required scopes missing: ' . implode(', ', $scopes));
        }
        return $auth;
    }

    public static function can(Request|AuthContext|null $subject, string $permission): bool
    {
        return self::context($subject)->can($permission);
    }

    public static function requirePermission(Request|AuthContext|null $subject, string $permission): AuthContext
    {
        $auth = self::requireAuthenticated($subject);
        if (!$auth->can($permission)) {
            throw new AuthorizationException("Required permission missing: {$permission}");
        }
        return $auth;
    }

    /** @param array<int,string> $permissions */
    public static function requireAnyPermission(Request|AuthContext|null $subject, array $permissions): AuthContext
    {
        $auth = self::requireAuthenticated($subject);
        if (!$auth->canAny($permissions)) {
            throw new AuthorizationException('Required permission missing: any of ' . implode(', ', $permissions));
        }
        return $auth;
    }

    /** @param array<int,string> $permissions */
    public static function requireAllPermissions(Request|AuthContext|null $subject, array $permissions): AuthContext
    {
        $auth = self::requireAuthenticated($subject);
        if (!$auth->canAll($permissions)) {
            throw new AuthorizationException('Required permissions missing: ' . implode(', ', $permissions));
        }
        return $auth;
    }

    public static function requireRole(Request|AuthContext|null $subject, string $role): AuthContext
    {
        $auth = self::requireAuthenticated($subject);
        if (!$auth->hasRole($role)) {
            throw new AuthorizationException("Required role missing: {$role}");
        }
        return $auth;
    }
}
