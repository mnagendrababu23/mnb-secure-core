<?php
namespace Mnb\SecurityCore\Auth;

class AuthContext
{
    public const ATTRIBUTE = 'auth';

    /** @var array<int,string> */
    private array $scopes;

    /** @var array<int,string> */
    private array $permissions;

    /** @var array<int,string> */
    private array $roles;

    /** @param array<int|string,mixed> $tokenRecord */
    public function __construct(
        private bool $authenticated = false,
        private int|string|null $userId = null,
        array $scopes = [],
        array $permissions = [],
        array $roles = [],
        private ?array $tokenRecord = null,
        private array $metadata = []
    ) {
        $this->scopes = $this->normalizeList($scopes);
        $this->permissions = $this->normalizeList($permissions);
        $this->roles = $this->normalizeList($roles);
    }

    public static function guest(): self
    {
        return new self(false);
    }

    /** @param array<string,mixed> $record */
    public static function fromTokenRecord(array $record): self
    {
        return new self(
            true,
            $record['user_id'] ?? null,
            is_array($record['scopes'] ?? null) ? $record['scopes'] : [],
            is_array($record['permissions'] ?? null) ? $record['permissions'] : [],
            is_array($record['roles'] ?? null) ? $record['roles'] : [],
            $record,
            [
                'device_id' => $record['device_id'] ?? null,
                'device_name' => $record['device_name'] ?? null,
                'expires_at' => $record['expires_at'] ?? null,
            ]
        );
    }

    /** @param array<string,mixed>|null $session */
    public static function fromSession(?array $session = null): self
    {
        if ($session === null) {
            if (session_status() !== PHP_SESSION_ACTIVE) {
                @session_start();
            }
            $session = $_SESSION ?? [];
        }

        $userId = $session['user_id'] ?? null;

        return new self(
            $userId !== null,
            $userId,
            is_array($session['scopes'] ?? null) ? $session['scopes'] : [],
            is_array($session['permissions'] ?? null) ? $session['permissions'] : [],
            is_array($session['roles'] ?? null) ? $session['roles'] : [],
            null,
            [
                'school_id' => $session['school_id'] ?? null,
                'branch_id' => $session['branch_id'] ?? null,
                'academic_year_id' => $session['academic_year_id'] ?? null,
            ]
        );
    }

    public function isAuthenticated(): bool
    {
        return $this->authenticated;
    }

    public function id(): int|string|null
    {
        return $this->userId;
    }

    public function userId(): int|string|null
    {
        return $this->userId;
    }

    /** @return array<int,string> */
    public function scopes(): array
    {
        return $this->scopes;
    }

    /** @return array<int,string> */
    public function permissions(): array
    {
        return $this->permissions;
    }

    /** @return array<int,string> */
    public function roles(): array
    {
        return $this->roles;
    }

    /** @return array<int|string,mixed>|null */
    public function tokenRecord(): ?array
    {
        return $this->tokenRecord;
    }

    public function metadata(string $key, mixed $default = null): mixed
    {
        return $this->metadata[$key] ?? $default;
    }

    /** @return array<string,mixed> */
    public function allMetadata(): array
    {
        return $this->metadata;
    }

    public function hasScope(string $scope): bool
    {
        return $this->matchesGrantedValue($scope, $this->scopes);
    }

    /** @param array<int,string> $scopes */
    public function hasAnyScope(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($this->hasScope((string)$scope)) {
                return true;
            }
        }
        return false;
    }

    /** @param array<int,string> $scopes */
    public function hasAllScopes(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if (!$this->hasScope((string)$scope)) {
                return false;
            }
        }
        return true;
    }

    public function can(string $permission): bool
    {
        return $this->matchesGrantedValue($permission, $this->permissions)
            || $this->matchesGrantedValue($permission, $this->scopes);
    }

    /** @param array<int,string> $permissions */
    public function canAny(array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if ($this->can((string)$permission)) {
                return true;
            }
        }
        return false;
    }

    /** @param array<int,string> $permissions */
    public function canAll(array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if (!$this->can((string)$permission)) {
                return false;
            }
        }
        return true;
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true) || in_array('*', $this->roles, true);
    }

    /** @param array<int,string> $roles */
    public function hasAnyRole(array $roles): bool
    {
        foreach ($roles as $role) {
            if ($this->hasRole((string)$role)) {
                return true;
            }
        }
        return false;
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'authenticated' => $this->authenticated,
            'user_id' => $this->userId,
            'scopes' => $this->scopes,
            'permissions' => $this->permissions,
            'roles' => $this->roles,
            'metadata' => $this->metadata,
        ];
    }

    /** @param array<int|string,mixed> $items @return array<int,string> */
    private function normalizeList(array $items): array
    {
        $normalized = [];
        foreach ($items as $item) {
            $value = trim((string)$item);
            if ($value !== '') {
                $normalized[] = $value;
            }
        }
        return array_values(array_unique($normalized));
    }

    /** @param array<int,string> $grantedValues */
    private function matchesGrantedValue(string $requiredValue, array $grantedValues): bool
    {
        $requiredValue = trim($requiredValue);
        if ($requiredValue === '') {
            return false;
        }

        foreach ($grantedValues as $grantedValue) {
            if ($grantedValue === '*' || hash_equals($grantedValue, $requiredValue)) {
                return true;
            }

            if (str_ends_with($grantedValue, '*')) {
                $prefix = substr($grantedValue, 0, -1);
                if ($prefix !== '' && str_starts_with($requiredValue, $prefix)) {
                    return true;
                }
            }
        }

        return false;
    }
}
