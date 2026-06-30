<?php
namespace Mnb\SecurityCore\Database;

final class QueryCostPolicy
{
    public function __construct(
        public readonly int $maxLimit = 500,
        public readonly int $defaultLimit = 50,
        public readonly int $maxOffset = 10000,
        public readonly int $maxSearchLength = 100,
        public readonly int $maxFilterCount = 20,
        public readonly bool $blockLeadingWildcard = true,
        public readonly int $slowQueryMs = 750,
        public readonly array $allowedOperators = []
    ) {}

    public static function fromConfig(array $config): self
    {
        $db = is_array($config['database'] ?? null) ? $config['database'] : [];
        $limits = is_array($db['query_limits'] ?? null) ? $db['query_limits'] : [];
        return new self(
            max(1, (int)($limits['max_limit'] ?? 500)),
            max(1, (int)($limits['default_limit'] ?? 50)),
            max(0, (int)($limits['max_offset'] ?? 10000)),
            max(1, (int)($limits['max_search_length'] ?? 100)),
            max(0, (int)($limits['max_filter_count'] ?? 20)),
            (bool)($limits['block_leading_wildcard'] ?? true),
            max(1, (int)($limits['slow_query_ms'] ?? 750)),
            array_values((array)($limits['allowed_operators'] ?? DatabaseFilterOperator::allowed()))
        );
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'max_limit' => $this->maxLimit,
            'default_limit' => $this->defaultLimit,
            'max_offset' => $this->maxOffset,
            'max_search_length' => $this->maxSearchLength,
            'max_filter_count' => $this->maxFilterCount,
            'block_leading_wildcard' => $this->blockLeadingWildcard,
            'slow_query_ms' => $this->slowQueryMs,
            'allowed_operators' => $this->allowedOperators ?: DatabaseFilterOperator::allowed(),
        ];
    }
}
