<?php
namespace Mnb\SecurityCore\Database;

use InvalidArgumentException;

final class QueryComplexityGuard
{
    public function __construct(private QueryCostPolicy $policy = new QueryCostPolicy()) {}

    public static function fromConfig(array $config): self
    {
        return new self(QueryCostPolicy::fromConfig($config));
    }

    public function policy(): QueryCostPolicy
    {
        return $this->policy;
    }

    public function assertSearch(?string $searchTerm, array $filters, int $limit, int $offset): void
    {
        if ($limit < 1 || $limit > $this->policy->maxLimit) {
            throw new InvalidArgumentException("Query limit must be between 1 and {$this->policy->maxLimit}.");
        }
        if ($offset < 0 || $offset > $this->policy->maxOffset) {
            throw new InvalidArgumentException("Query offset must be between 0 and {$this->policy->maxOffset}.");
        }
        if (count($filters) > $this->policy->maxFilterCount) {
            throw new InvalidArgumentException("Query filter count exceeds {$this->policy->maxFilterCount}.");
        }
        if ($searchTerm !== null && strlen($searchTerm) > $this->policy->maxSearchLength) {
            throw new InvalidArgumentException("Search term exceeds {$this->policy->maxSearchLength} characters.");
        }
        if ($this->policy->blockLeadingWildcard && is_string($searchTerm) && preg_match('/^\s*[%_*]/', $searchTerm)) {
            throw new InvalidArgumentException('Leading wildcard search is blocked by query policy.');
        }
        foreach (DatabaseSearchFilter::normalize($filters) as $filter) {
            if ($this->policy->allowedOperators && !in_array($filter->operator, $this->policy->allowedOperators, true)) {
                throw new InvalidArgumentException("Database filter operator not enabled by query policy: {$filter->operator}");
            }
            if (is_string($filter->value) && strlen($filter->value) > $this->policy->maxSearchLength && in_array($filter->operator, [DatabaseFilterOperator::LIKE, DatabaseFilterOperator::STARTS_WITH, DatabaseFilterOperator::ENDS_WITH], true)) {
                throw new InvalidArgumentException("Filter value for {$filter->column} exceeds {$this->policy->maxSearchLength} characters.");
            }
        }
    }
}
