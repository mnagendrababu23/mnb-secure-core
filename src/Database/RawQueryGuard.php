<?php
namespace Mnb\SecurityCore\Database;

use InvalidArgumentException;

final class RawQueryGuard
{
    public function __construct(private DatabaseOperationPolicy $policy = new DatabaseOperationPolicy()) {}

    public static function fromConfig(array $config): self
    {
        return new self(DatabaseOperationPolicy::fromConfig($config));
    }

    public function assertAllowed(string $sql, bool $trusted = false): void
    {
        if ($trusted) {
            return;
        }
        if ($this->policy->denyRawSql) {
            throw new InvalidArgumentException('Raw SQL is disabled by database.deny_raw_sql. Use SecureDatabase/SecureQueryBuilder.');
        }
        if (preg_match('/\b(drop|truncate|rename|grant|revoke|create\s+user|alter\s+user)\b/i', $sql)) {
            throw new InvalidArgumentException('Dangerous raw SQL operation blocked by RawQueryGuard.');
        }
    }
}
