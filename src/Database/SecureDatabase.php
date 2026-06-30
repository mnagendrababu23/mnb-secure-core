<?php
namespace Mnb\SecurityCore\Database;

use Mnb\SecurityCore\Authz\PolicyRegistry;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Contracts\DatabaseConnectionInterface;
use Mnb\SecurityCore\Exceptions\SecurityException;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;

class SecureDatabase
{
    public function __construct(
        private DatabaseConnectionInterface $connection,
        private ?PolicyRegistry $policies = null,
        private ?object $audit = null,
        private SecureQueryBuilder $builder = new SecureQueryBuilder(),
        private SchemaGuard $schemaGuard = new SchemaGuard()
    ) {}

    /** @return array<int,array<string,mixed>> */
    public function search(TenantContext $context, TableSecurityPolicy $policy, string $term, array $filters = [], ?string $orderBy = null, string $direction = 'ASC', int $limit = 50, int $offset = 0): array
    {
        $this->authorize($context, $policy, 'view', ['search' => true]);
        $plan = $this->builder->select($policy, $policy->selectableColumns, $filters, $this->tenantScopes($context, $policy), $term, $policy->searchableColumns, $orderBy, $direction, $limit, $offset);
        $this->audit('db.search', $context, $policy, $plan);
        return $this->connection->fetchAll($plan->sql, $plan->bindings);
    }

    public function findById(TenantContext $context, TableSecurityPolicy $policy, int|string $id): ?array
    {
        $this->authorize($context, $policy, 'view', ['id' => $id]);
        $plan = $this->builder->findById($policy, $id, $this->tenantScopes($context, $policy), $policy->selectableColumns);
        $this->audit('db.find', $context, $policy, $plan, ['id' => $id]);
        return $this->connection->fetchOne($plan->sql, $plan->bindings);
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
        ];

        if (method_exists($this->audit, 'recordEvent')) {
            $this->audit->recordEvent(SecurityAuditEvent::database($action, SecurityAuditEvent::OUTCOME_SUCCESS, $actor, $target, [], $meta));
            return;
        }

        if (method_exists($this->audit, 'record')) {
            $this->audit->record($action, $actor, $target, $meta);
        }
    }
}
