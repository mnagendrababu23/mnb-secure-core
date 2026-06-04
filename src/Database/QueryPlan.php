<?php
namespace Mnb\SecurityCore\Database;

class QueryPlan
{
    public function __construct(
        public readonly string $operation,
        public readonly string $table,
        public readonly string $sql,
        public readonly array $bindings = [],
        public readonly array $meta = []
    ) {}
}
