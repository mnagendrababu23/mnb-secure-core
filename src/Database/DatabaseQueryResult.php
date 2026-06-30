<?php
namespace Mnb\SecurityCore\Database;

final class DatabaseQueryResult
{
    public function __construct(
        public readonly bool $passed,
        public readonly string $operation,
        public readonly mixed $result = null,
        public readonly ?QueryPlan $plan = null,
        public readonly array $meta = []
    ) {}

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'passed' => $this->passed,
            'operation' => $this->operation,
            'result' => $this->result,
            'plan' => $this->plan ? [
                'operation' => $this->plan->operation,
                'table' => $this->plan->table,
                'sql_shape' => preg_replace('/\s+/', ' ', $this->plan->sql),
                'binding_count' => count($this->plan->bindings),
                'meta' => $this->plan->meta,
            ] : null,
            'meta' => $this->meta,
        ];
    }
}
