<?php
namespace Mnb\SecurityCore\Database;

use Mnb\SecurityCore\Authz\PolicyRegistry;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Contracts\DatabaseConnectionInterface;
use Mnb\SecurityCore\Exceptions\SecurityException;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Throwable;

class SecureDatabase
{
    public function __construct(
        private DatabaseConnectionInterface $connection,
        private ?PolicyRegistry $policies = null,
        private ?object $audit = null,
        private SecureQueryBuilder $builder = new SecureQueryBuilder(),
        private SchemaGuard $schemaGuard = new SchemaGuard(),
        private ?DatabasePolicyRegistry $databasePolicies = null,
        private ?QueryComplexityGuard $queryGuard = null,
        private ?DatabaseResultFilter $resultFilter = null,
        private ?SchemaMigrationGuard $schemaMigrationGuard = null
    ) {}

    public function policy(string $name): TableSecurityPolicy
    {
        if (!$this->databasePolicies) {
            throw new \InvalidArgumentException('Database policy registry is not configured.');
        }
        return $this->databasePolicies->get($name);
    }

    /** @return array<int,array<string,mixed>> */
    public function search(TenantContext $context, TableSecurityPolicy $policy, string $term, array $filters = [], ?string $orderBy = null, string $direction = 'ASC', int $limit = 50, int $offset = 0): array
    {
        $this->guard()->assertSearch($term, $filters, $limit, $offset);
        $this->authorize($context, $policy, 'view', ['search' => true]);
        $plan = $this->builder->select($policy, $policy->selectableColumns, $filters, $this->tenantScopes($context, $policy), $term, $policy->searchableColumns, $orderBy, $direction, $limit, $offset);
        $this->audit('db.search', $context, $policy, $plan);
        return $this->filter()->filterRows($context, $policy, $this->connection->fetchAll($plan->sql, $plan->bindings));
    }

    /** @return array<int,array<string,mixed>> */
    public function searchPolicy(TenantContext $context, string $policyName, string $term = '', array $filters = [], ?string $orderBy = null, string $direction = 'ASC', int $limit = 50, int $offset = 0): array
    {
        return $this->search($context, $this->policy($policyName), $term, $filters, $orderBy, $direction, $limit, $offset);
    }

    public function findById(TenantContext $context, TableSecurityPolicy $policy, int|string $id): ?array
    {
        $this->authorize($context, $policy, 'view', ['id' => $id]);
        $plan = $this->builder->findById($policy, $id, $this->tenantScopes($context, $policy), $policy->selectableColumns);
        $this->audit('db.find', $context, $policy, $plan, ['id' => $id]);
        return $this->filter()->filterOne($context, $policy, $this->connection->fetchOne($plan->sql, $plan->bindings));
    }

    public function create(TenantContext $context, TableSecurityPolicy $policy, array $data): string
    {
        $this->authorize($context, $policy, 'create', $data);
        $plan = $this->builder->insert($policy, $data, $this->tenantScopes($context, $policy));
        $this->connection->execute($plan->sql, $plan->bindings);
        $this->audit('db.create', $context, $policy, $plan);
        return $this->connection->lastInsertId();
    }

    public function updateById(TenantContext $context, TableSecurityPolicy $policy, int|string $id, array $data): int
    {
        $this->authorize($context, $policy, 'update', ['id' => $id] + $data);
        $plan = $this->builder->updateById($policy, $id, $data, $this->tenantScopes($context, $policy));
        $affected = $this->connection->execute($plan->sql, $plan->bindings);
        $this->audit('db.update', $context, $policy, $plan, ['id' => $id]);
        return $affected;
    }

    public function deleteById(TenantContext $context, TableSecurityPolicy $policy, int|string $id, bool $hardDelete = false): int
    {
        $this->authorize($context, $policy, $hardDelete ? 'hard_delete' : 'delete', ['id' => $id]);
        $plan = $this->builder->deleteById($policy, $id, $this->tenantScopes($context, $policy), $hardDelete);
        $affected = $this->connection->execute($plan->sql, $plan->bindings);
        $this->audit($hardDelete ? 'db.hard_delete' : 'db.delete', $context, $policy, $plan, ['id' => $id]);
        return $affected;
    }

    public function restoreById(TenantContext $context, TableSecurityPolicy $policy, int|string $id): int
    {
        $this->authorize($context, $policy, 'restore', ['id' => $id]);
        $plan = $this->builder->restoreById($policy, $id, $this->tenantScopes($context, $policy));
        $affected = $this->connection->execute($plan->sql, $plan->bindings);
        $this->audit('db.restore', $context, $policy, $plan, ['id' => $id]);
        return $affected;
    }

    /** @template T @param callable(self):T $callback @return T */
    public function transaction(TenantContext $context, callable $callback): mixed
    {
        $this->auditRaw(DatabaseAuditEvents::TRANSACTION_BEGIN, $context, new QueryPlan('transaction_begin', 'transaction', 'TRANSACTION BEGIN'));
        try {
            $result = $this->connection->transaction(fn() => $callback($this));
            $this->auditRaw(DatabaseAuditEvents::TRANSACTION_COMMIT, $context, new QueryPlan('transaction_commit', 'transaction', 'TRANSACTION COMMIT'));
            return $result;
        } catch (Throwable $e) {
            $this->auditRaw(DatabaseAuditEvents::TRANSACTION_ROLLBACK, $context, new QueryPlan('transaction_rollback', 'transaction', 'TRANSACTION ROLLBACK', [], ['error_class' => get_class($e)]));
            throw $e;
        }
    }

    public function alterAddColumn(TenantContext $context, string $table, string $column, string $type, bool $nullable = true, mixed $default = null): int
    {
        $this->schemaGuard->assertSchemaChangeAllowed($context, 'schema.alter');
        $plan = $this->schemaGuard->addColumn($table, $column, $type, $nullable, $default);
        $affected = $this->connection->execute($plan->sql, $plan->bindings);
        $this->auditRaw('db.schema.add_column', $context, $plan);
        return $affected;
    }

    public function alterAddIndex(TenantContext $context, string $table, string $indexName, array $columns): int
    {
        $this->schemaGuard->assertSchemaChangeAllowed($context, 'schema.alter');
        $plan = $this->schemaGuard->addIndex($table, $indexName, $columns);
        $affected = $this->connection->execute($plan->sql, $plan->bindings);
        $this->auditRaw('db.schema.add_index', $context, $plan);
        return $affected;
    }

    public function schemaPlanAddColumn(TenantContext $context, string $table, string $column, string $type, bool $nullable = true, mixed $default = null, ?bool $dryRun = null): SchemaChangePlan
    {
        $plan = $this->schemaMigration()->planAddColumn($context, $table, $column, $type, $nullable, $default, $dryRun);
        $this->auditRaw(DatabaseAuditEvents::SCHEMA_PLAN_CREATED, $context, new QueryPlan($plan->operation, $plan->table, $plan->sql ?? 'SCHEMA PLAN', $plan->bindings, $plan->toArray()));
        return $plan;
    }

    public function schemaPlanAddIndex(TenantContext $context, string $table, string $indexName, array $columns, ?bool $dryRun = null): SchemaChangePlan
    {
        $plan = $this->schemaMigration()->planAddIndex($context, $table, $indexName, $columns, $dryRun);
        $this->auditRaw(DatabaseAuditEvents::SCHEMA_PLAN_CREATED, $context, new QueryPlan($plan->operation, $plan->table, $plan->sql ?? 'SCHEMA PLAN', $plan->bindings, $plan->toArray()));
        return $plan;
    }

    private function authorize(TenantContext $context, TableSecurityPolicy $policy, string $ability, mixed $resource): void
    {
        if ($this->policies && $this->policies->allows($context, $policy->resourceType, $ability, $resource)) {
            return;
        }
        $permission = $policy->resourceType . '.' . $ability;
        if (in_array($permission, $context->permissions, true) || in_array('super_admin', $context->roles, true)) {
            return;
        }
        throw new SecurityException("Database {$ability} blocked for resource {$policy->resourceType}.");
    }

    /** @return array<string,mixed> */
    private function tenantScopes(TenantContext $context, TableSecurityPolicy $policy): array
    {
        $scopes = [];
        foreach ($policy->tenantColumns as $column => $property) {
            if (property_exists($context, $property) && $context->{$property} !== null) {
                $scopes[$column] = $context->{$property};
            }
        }
        return $scopes;
    }

    private function audit(string $action, TenantContext $context, TableSecurityPolicy $policy, QueryPlan $plan, array $target = []): void
    {
        $this->auditRaw($action, $context, $plan, ['table' => $policy->table, 'resource' => $policy->resourceType] + $target);
    }

    private function auditRaw(string $action, TenantContext $context, QueryPlan $plan, array $target = []): void
    {
        if (!$this->audit) {
            return;
        }

        $actor = ['user_id' => $context->userId];
        $target = $target + ['table' => $plan->table];
        $meta = [
            'operation' => $plan->operation,
            'sql_shape' => preg_replace('/\s+/', ' ', $plan->sql),
            'binding_count' => count($plan->bindings),
        ] + $plan->meta;

        if (method_exists($this->audit, 'recordEvent')) {
            $this->audit->recordEvent(SecurityAuditEvent::database($action, SecurityAuditEvent::OUTCOME_SUCCESS, $actor, $target, [], $meta));
            return;
        }

        if (method_exists($this->audit, 'record')) {
            $this->audit->record($action, $actor, $target, $meta);
        }
    }

    private function guard(): QueryComplexityGuard
    {
        return $this->queryGuard ??= new QueryComplexityGuard();
    }

    private function filter(): DatabaseResultFilter
    {
        return $this->resultFilter ??= new DatabaseResultFilter();
    }

    private function schemaMigration(): SchemaMigrationGuard
    {
        return $this->schemaMigrationGuard ??= new SchemaMigrationGuard();
    }
}
