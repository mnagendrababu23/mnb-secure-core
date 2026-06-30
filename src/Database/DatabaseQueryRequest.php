<?php
namespace Mnb\SecurityCore\Database;

final class DatabaseQueryRequest
{
    public function __construct(
        public readonly string $operation,
        public readonly TableSecurityPolicy $policy,
        public readonly array $filters = [],
        public readonly ?string $searchTerm = null,
        public readonly ?string $orderBy = null,
        public readonly string $direction = 'ASC',
        public readonly int $limit = 50,
        public readonly int $offset = 0
    ) {}

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'operation' => $this->operation,
            'table' => $this->policy->table,
            'resource_type' => $this->policy->resourceType,
            'filter_count' => count($this->filters),
            'search_length' => $this->searchTerm === null ? 0 : strlen($this->searchTerm),
            'order_by' => $this->orderBy,
            'direction' => $this->direction,
            'limit' => $this->limit,
            'offset' => $this->offset,
        ];
    }
}
