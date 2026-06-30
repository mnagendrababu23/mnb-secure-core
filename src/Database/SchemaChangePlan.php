<?php
namespace Mnb\SecurityCore\Database;

final class SchemaChangePlan
{
    public function __construct(
        public readonly bool $allowed,
        public readonly string $operation,
        public readonly string $table,
        public readonly ?string $sql = null,
        public readonly array $bindings = [],
        public readonly bool $dryRun = true,
        public readonly bool $destructive = false,
        public readonly bool $requiresBackup = true,
        public readonly ?string $reason = null,
        public readonly array $meta = []
    ) {}

    public static function blocked(string $operation, string $table, string $reason, bool $destructive = false, array $meta = []): self
    {
        return new self(false, $operation, $table, null, [], true, $destructive, true, $reason, $meta);
    }

    public static function fromQueryPlan(QueryPlan $plan, bool $dryRun, bool $requiresBackup, array $meta = []): self
    {
        return new self(true, $plan->operation, $plan->table, $plan->sql, $plan->bindings, $dryRun, false, $requiresBackup, null, $plan->meta + $meta);
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'operation' => $this->operation,
            'table' => $this->table,
            'sql_shape' => $this->sql ? preg_replace('/\s+/', ' ', $this->sql) : null,
            'binding_count' => count($this->bindings),
            'dry_run' => $this->dryRun,
            'destructive' => $this->destructive,
            'requires_backup' => $this->requiresBackup,
            'reason' => $this->reason,
            'meta' => $this->meta,
        ];
    }
}
