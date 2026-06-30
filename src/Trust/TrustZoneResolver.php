<?php
namespace Mnb\SecurityCore\Trust;

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Auth\PermissionGuard as AuthPermissionGuard;
use Mnb\SecurityCore\Http\Request;

class TrustZoneResolver
{
    /** @param array<string,mixed> $config */
    public function __construct(private array $config = []) {}

    public function resolve(?Request $request = null, ?AuthContext $auth = null): string
    {
        if ($request) {
            $explicit = $request->attribute('trust_zone');
            if (is_string($explicit) && $this->isKnownZone($explicit)) {
                return $explicit;
            }
        }

        $auth ??= $request ? AuthPermissionGuard::context($request) : AuthContext::guest();
        if (!$auth->isAuthenticated()) {
            return TrustZone::PUBLIC;
        }

        if ($this->matchesAny($auth, $this->zoneConfig(TrustZone::INTERNAL_SYSTEM, ['roles' => ['internal_system', 'system'], 'scopes' => ['system:*', 'internal:*']]))) {
            return TrustZone::INTERNAL_SYSTEM;
        }
        if ($this->matchesAny($auth, $this->zoneConfig(TrustZone::SUPER_ADMIN, ['roles' => ['super_admin', 'root', 'owner'], 'scopes' => ['admin:*', '*']]))) {
            return TrustZone::SUPER_ADMIN;
        }
        if ($this->matchesAny($auth, $this->zoneConfig(TrustZone::SCHOOL_ADMIN, ['roles' => ['school_admin', 'admin'], 'scopes' => ['school:*'], 'permissions' => ['school.manage', 'student.manage']]))) {
            return TrustZone::SCHOOL_ADMIN;
        }

        return TrustZone::AUTHENTICATED;
    }

    /** @param array<string,mixed> $fallback @return array<string,mixed> */
    private function zoneConfig(string $zone, array $fallback): array
    {
        $zones = is_array($this->config['zone_resolvers'] ?? null) ? $this->config['zone_resolvers'] : [];
        return is_array($zones[$zone] ?? null) ? array_replace_recursive($fallback, $zones[$zone]) : $fallback;
    }

    /** @param array<string,mixed> $rules */
    private function matchesAny(AuthContext $auth, array $rules): bool
    {
        foreach ((array)($rules['roles'] ?? []) as $role) {
            if ($auth->hasRole((string)$role)) {
                return true;
            }
        }
        foreach ((array)($rules['scopes'] ?? []) as $scope) {
            if ($this->authHasPattern($auth->scopes(), (string)$scope) || $auth->hasScope((string)$scope)) {
                return true;
            }
        }
        foreach ((array)($rules['permissions'] ?? []) as $permission) {
            if ($this->authHasPattern($auth->permissions(), (string)$permission) || $auth->can((string)$permission)) {
                return true;
            }
        }
        return false;
    }

    /** @param list<string> $granted */
    private function authHasPattern(array $granted, string $required): bool
    {
        if ($required === '*') {
            return in_array('*', $granted, true);
        }
        if (!str_ends_with($required, '*')) {
            return in_array($required, $granted, true);
        }
        $prefix = substr($required, 0, -1);
        foreach ($granted as $value) {
            if (str_starts_with($value, $prefix)) {
                return true;
            }
        }
        return false;
    }

    private function isKnownZone(string $zone): bool
    {
        $zones = is_array($this->config['zones'] ?? null) ? $this->config['zones'] : TrustZone::values();
        return in_array($zone, $zones, true);
    }
}
