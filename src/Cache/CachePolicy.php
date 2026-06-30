<?php
namespace Mnb\SecurityCore\Cache;

class CachePolicy
{
    public const PUBLIC = 'public';
    public const INTERNAL = 'internal';
    public const CONFIDENTIAL = 'confidential';
    public const SENSITIVE = 'sensitive';
    public const HIGHLY_SENSITIVE = 'highly_sensitive';

    /** @param list<string> $scope @param list<string> $tags */
    public function __construct(
        private string $name,
        private int $ttlSeconds = 300,
        private string $dataClass = self::INTERNAL,
        private array $scope = ['global'],
        private array $tags = [],
        private bool $cache = true,
        private bool $encrypt = false,
        private int $maxValueBytes = 1048576,
        private int $staleTtlSeconds = 0,
        private bool $staleIfError = false,
        private bool $audit = false,
        private bool $tenantScoped = false,
        private bool $userScoped = false,
    ) {
        self::assertName($name, 'cache policy name');
        if ($ttlSeconds < 0) {
            throw new \InvalidArgumentException('Cache policy ttl must be zero or greater.');
        }
        if ($staleTtlSeconds < 0) {
            throw new \InvalidArgumentException('Cache policy stale ttl must be zero or greater.');
        }
        if ($maxValueBytes < 1) {
            throw new \InvalidArgumentException('Cache policy max value bytes must be greater than zero.');
        }
        $this->dataClass = self::normalizeDataClass($dataClass);
        $this->scope = self::normalizeList($scope, 'cache scope');
        $this->tags = self::normalizeList($tags, 'cache tag', allowEmpty: true);
    }

    /** @param array<string,mixed> $config */
    public static function fromArray(string $name, array $config, array $defaults = []): self
    {
        $dataClass = (string)($config['data_class'] ?? $defaults['data_class'] ?? self::INTERNAL);
        $scope = is_array($config['scope'] ?? null) ? $config['scope'] : (is_array($defaults['scope'] ?? null) ? $defaults['scope'] : ['global']);
        $tags = is_array($config['tags'] ?? null) ? $config['tags'] : (is_array($defaults['tags'] ?? null) ? $defaults['tags'] : []);
        $encrypt = array_key_exists('encrypt', $config) ? (bool)$config['encrypt'] : (bool)($defaults['encrypt'] ?? false);
        $cache = array_key_exists('cache', $config) ? (bool)$config['cache'] : (bool)($defaults['cache'] ?? true);
        $ttl = (int)($config['ttl'] ?? $config['ttl_seconds'] ?? $defaults['ttl'] ?? $defaults['ttl_seconds'] ?? 300);
        $stale = (int)($config['stale_ttl'] ?? $config['stale_ttl_seconds'] ?? $defaults['stale_ttl'] ?? 0);
        return new self(
            $name,
            $ttl,
            $dataClass,
            $scope,
            $tags,
            $cache,
            $encrypt,
            (int)($config['max_value_bytes'] ?? $defaults['max_value_bytes'] ?? 1048576),
            $stale,
            (bool)($config['stale_if_error'] ?? $defaults['stale_if_error'] ?? false),
            (bool)($config['audit'] ?? $defaults['audit'] ?? false),
            in_array('tenant', $scope, true) || (bool)($config['tenant_scoped'] ?? $defaults['tenant_scoped'] ?? false),
            in_array('user', $scope, true) || (bool)($config['user_scoped'] ?? $defaults['user_scoped'] ?? false),
        );
    }

    public function name(): string { return $this->name; }
    public function ttlSeconds(): int { return $this->ttlSeconds; }
    public function dataClass(): string { return $this->dataClass; }
    /** @return list<string> */ public function scope(): array { return $this->scope; }
    /** @return list<string> */ public function tags(): array { return $this->tags; }
    public function cacheEnabled(): bool { return $this->cache && $this->ttlSeconds > 0; }
    public function encrypt(): bool { return $this->encrypt; }
    public function maxValueBytes(): int { return $this->maxValueBytes; }
    public function staleTtlSeconds(): int { return $this->staleTtlSeconds; }
    public function staleIfError(): bool { return $this->staleIfError; }
    public function audit(): bool { return $this->audit; }
    public function tenantScoped(): bool { return $this->tenantScoped; }
    public function userScoped(): bool { return $this->userScoped; }

    public function shouldEncrypt(bool $encryptSensitive = true): bool
    {
        return $this->encrypt || ($encryptSensitive && in_array($this->dataClass, [self::SENSITIVE, self::HIGHLY_SENSITIVE], true));
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'ttl' => $this->ttlSeconds,
            'data_class' => $this->dataClass,
            'scope' => $this->scope,
            'tags' => $this->tags,
            'cache' => $this->cache,
            'encrypt' => $this->encrypt,
            'max_value_bytes' => $this->maxValueBytes,
            'stale_ttl' => $this->staleTtlSeconds,
            'stale_if_error' => $this->staleIfError,
            'audit' => $this->audit,
        ];
    }

    public static function normalizeDataClass(string $class): string
    {
        $class = strtolower(trim($class));
        if (!in_array($class, [self::PUBLIC, self::INTERNAL, self::CONFIDENTIAL, self::SENSITIVE, self::HIGHLY_SENSITIVE], true)) {
            throw new \InvalidArgumentException('Unknown cache data class: ' . $class);
        }
        return $class;
    }

    private static function assertName(string $name, string $label): void
    {
        if (!preg_match('/^[A-Za-z0-9_.:-]{1,120}$/', $name)) {
            throw new \InvalidArgumentException($label . ' must be a safe identifier.');
        }
    }

    /** @param array<int,mixed> $list @return list<string> */
    private static function normalizeList(array $list, string $label, bool $allowEmpty = false): array
    {
        $out = [];
        foreach ($list as $value) {
            if (!is_scalar($value) || trim((string)$value) === '') {
                throw new \InvalidArgumentException($label . ' values must be non-empty strings.');
            }
            $item = trim((string)$value);
            if (!preg_match('/^[A-Za-z0-9_.:-]{1,120}$/', $item)) {
                throw new \InvalidArgumentException($label . ' values must be safe identifiers.');
            }
            $out[] = $item;
        }
        if (!$allowEmpty && $out === []) {
            throw new \InvalidArgumentException($label . ' list cannot be empty.');
        }
        return array_values(array_unique($out));
    }
}
