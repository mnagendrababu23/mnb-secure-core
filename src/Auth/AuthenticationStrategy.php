<?php
namespace Mnb\SecurityCore\Auth;

class AuthenticationStrategy
{
    public const TYPE_NONE = 'none';
    public const TYPE_BEARER = 'bearer';
    public const TYPE_SESSION = 'session';
    public const TYPE_SIGNATURE = 'signature';

    /** @param list<string> $scopes @param list<string> $roles @param list<string> $permissions @param array<string,mixed> $options */
    public function __construct(
        private string $name,
        private string $type = self::TYPE_BEARER,
        private bool $required = true,
        private array $scopes = [],
        private array $roles = [],
        private array $permissions = [],
        private ?string $ratePolicy = null,
        private bool $audit = true,
        private string $failureMessage = 'Authentication required',
        private array $options = []
    ) {
        self::assertName($name);
        if (!in_array($type, [self::TYPE_NONE, self::TYPE_BEARER, self::TYPE_SESSION, self::TYPE_SIGNATURE], true)) {
            throw new \InvalidArgumentException('Authentication strategy type must be none, bearer, session, or signature.');
        }
        $this->scopes = self::normalizeList($scopes);
        $this->roles = self::normalizeList($roles);
        $this->permissions = self::normalizeList($permissions);
    }

    public static function fromArray(string $name, array $config): self
    {
        $type = (string)($config['type'] ?? self::TYPE_BEARER);
        if ($type === 'optional_bearer') {
            $type = self::TYPE_BEARER;
            $config['required'] = false;
        }
        return new self(
            $name,
            $type,
            (bool)($config['required'] ?? true),
            self::listFrom($config['scopes'] ?? []),
            self::listFrom($config['roles'] ?? []),
            self::listFrom($config['permissions'] ?? []),
            isset($config['rate_policy']) && $config['rate_policy'] !== '' ? (string)$config['rate_policy'] : null,
            (bool)($config['audit'] ?? true),
            (string)($config['failure_message'] ?? 'Authentication required'),
            $config
        );
    }

    public function name(): string { return $this->name; }
    public function type(): string { return $this->type; }
    public function required(): bool { return $this->required; }
    /** @return list<string> */ public function scopes(): array { return $this->scopes; }
    /** @return list<string> */ public function roles(): array { return $this->roles; }
    /** @return list<string> */ public function permissions(): array { return $this->permissions; }
    public function ratePolicy(): ?string { return $this->ratePolicy; }
    public function audit(): bool { return $this->audit; }
    public function failureMessage(): string { return $this->failureMessage; }
    public function option(string $key, mixed $default = null): mixed { return $this->options[$key] ?? $default; }
    /** @return array<string,mixed> */ public function options(): array { return $this->options; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'type' => $this->type,
            'required' => $this->required,
            'scopes' => $this->scopes,
            'roles' => $this->roles,
            'permissions' => $this->permissions,
            'rate_policy' => $this->ratePolicy,
            'audit' => $this->audit,
        ];
    }

    /** @return list<string> */
    private static function listFrom(mixed $value): array
    {
        if (is_string($value)) { $value = explode(',', $value); }
        return is_array($value) ? self::normalizeList($value) : [];
    }

    /** @param array<int|string,mixed> $items @return list<string> */
    private static function normalizeList(array $items): array
    {
        $out = [];
        foreach ($items as $item) {
            if (!is_scalar($item)) { continue; }
            $value = trim((string)$item);
            if ($value !== '') { $out[] = $value; }
        }
        return array_values(array_unique($out));
    }

    public static function assertName(string $name): void
    {
        if (!preg_match('/^[a-z][a-z0-9_.:-]{1,95}$/', $name)) {
            throw new \InvalidArgumentException('Authentication strategy name must be a safe slug.');
        }
    }
}
