<?php
namespace Mnb\SecurityCore\Database;

final class DatabaseOperationPolicy
{
    public function __construct(
        public readonly bool $requirePolicies = true,
        public readonly bool $softDeleteDefault = true,
        public readonly bool $denyRawSql = true,
        public readonly bool $auditQueries = true,
        public readonly bool $auditBindings = false
    ) {}

    public static function fromConfig(array $config): self
    {
        $db = is_array($config['database'] ?? null) ? $config['database'] : [];
        return new self(
            (bool)($db['require_policies'] ?? true),
            (bool)($db['soft_delete_default'] ?? true),
            (bool)($db['deny_raw_sql'] ?? true),
            (bool)($db['audit_queries'] ?? true),
            (bool)($db['audit_bindings'] ?? false)
        );
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'require_policies' => $this->requirePolicies,
            'soft_delete_default' => $this->softDeleteDefault,
            'deny_raw_sql' => $this->denyRawSql,
            'audit_queries' => $this->auditQueries,
            'audit_bindings' => $this->auditBindings,
        ];
    }
}
