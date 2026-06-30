<?php
namespace Mnb\SecurityCore\Authorization;

use Mnb\SecurityCore\Auth\AuthContext;

class FieldAuthorization
{
    /** @param array<string,mixed> $record */
    public static function filter(array $record, AuthorizationPolicy $policy, AuthContext $auth, string $mode = 'read'): array
    {
        $allowed = self::allowedFields($policy, $auth, $mode);
        if ($allowed === null) { return $record; }
        if ($allowed === []) { return []; }
        if (in_array('*', $allowed, true)) { return $record; }
        return array_intersect_key($record, array_flip($allowed));
    }

    /** @return list<string>|null Null means no field policy configured. */
    public static function allowedFields(AuthorizationPolicy $policy, AuthContext $auth, string $mode = 'read'): ?array
    {
        $fields = $policy->fields();
        $section = is_array($fields[$mode] ?? null) ? $fields[$mode] : [];
        if ($section === []) { return null; }

        $result = [];
        foreach ($section as $principal => $fieldList) {
            if (!self::principalMatches((string)$principal, $auth)) { continue; }
            foreach (self::listFrom($fieldList) as $field) {
                $result[] = $field;
            }
        }
        return array_values(array_unique($result));
    }

    private static function principalMatches(string $principal, AuthContext $auth): bool
    {
        $principal = trim($principal);
        if ($principal === '*' || $principal === 'authenticated' && $auth->isAuthenticated()) { return true; }
        if (str_starts_with($principal, 'role:')) { return $auth->hasRole(substr($principal, 5)); }
        if (str_starts_with($principal, 'scope:')) { return $auth->hasScope(substr($principal, 6)); }
        if (str_starts_with($principal, 'permission:')) { return $auth->can(substr($principal, 11)); }
        return $auth->hasRole($principal) || $auth->hasScope($principal) || $auth->can($principal);
    }

    /** @return list<string> */
    private static function listFrom(mixed $value): array
    {
        if (is_string($value)) { $value = array_filter(array_map('trim', explode(',', $value))); }
        if (!is_array($value)) { return []; }
        $out = [];
        foreach ($value as $item) {
            if (is_scalar($item) && trim((string)$item) !== '') { $out[] = trim((string)$item); }
        }
        return array_values(array_unique($out));
    }
}
