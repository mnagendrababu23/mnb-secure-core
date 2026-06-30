<?php
namespace Mnb\SecurityCore\Database;

use InvalidArgumentException;
use Mnb\SecurityCore\Authz\TenantContext;

final class SchemaMigrationGuard
{
    public function __construct(
        private SchemaChangePolicy $policy = new SchemaChangePolicy(),
        private SchemaGuard $schemaGuard = new SchemaGuard()
    ) {}

    public static function fromConfig(array $config): self
    {
        return new self(SchemaChangePolicy::fromConfig($config));
    }

    public function planAddColumn(TenantContext $context, string $table, string $column, string $type, bool $nullable = true, mixed $default = null, ?bool $dryRun = null): SchemaChangePlan
    {
        $this->assertAllowed($context, 'add_column', false);
        $plan = $this->schemaGuard->addColumn($table, $column, $type, $nullable, $default);
        return SchemaChangePlan::fromQueryPlan($plan, $dryRun ?? $this->policy->dryRunDefault, $this->policy->requireBackupBeforeAlter, ['column' => $column, 'type' => strtoupper(trim($type))]);
    }

    public function planAddIndex(TenantContext $context, string $table, string $indexName, array $columns, ?bool $dryRun = null): SchemaChangePlan
    {
        $this->assertAllowed($context, 'add_index', false);
        $plan = $this->schemaGuard->addIndex($table, $indexName, $columns);
        return SchemaChangePlan::fromQueryPlan($plan, $dryRun ?? $this->policy->dryRunDefault, $this->policy->requireBackupBeforeAlter, ['index' => $indexName]);
    }

    public function planDestructive(TenantContext $context, string $operation, string $table): SchemaChangePlan
    {
        try {
            $this->assertAllowed($context, $operation, true);
        } catch (InvalidArgumentException $e) {
            return SchemaChangePlan::blocked($operation, SqlIdentifier::assert($table, 'schema table'), $e->getMessage(), true);
        }
        return SchemaChangePlan::blocked($operation, SqlIdentifier::assert($table, 'schema table'), 'Destructive schema plan creation is intentionally not implemented by default.', true);
    }

    private function assertAllowed(TenantContext $context, string $operation, bool $destructive): void
    {
        if (!$this->policy->enabled) {
            throw new InvalidArgumentException('Schema change blocked: schema change engine disabled.');
        }
        if (!in_array($operation, $this->policy->allowedOperations, true)) {
            throw new InvalidArgumentException("Schema operation not allowed: {$operation}");
        }
        if ($destructive && !$this->policy->allowDestructiveChanges) {
            throw new InvalidArgumentException('Destructive schema changes are blocked by policy.');
        }
        if ($this->policy->requireSuperAdmin && !in_array('super_admin', $context->roles, true)) {
            throw new InvalidArgumentException('Schema change blocked: super_admin role required.');
        }
        $this->schemaGuard->assertSchemaChangeAllowed($context, 'schema.alter');
    }
}
