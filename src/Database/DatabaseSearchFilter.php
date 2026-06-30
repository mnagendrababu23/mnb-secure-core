<?php
namespace Mnb\SecurityCore\Database;

use InvalidArgumentException;

final class DatabaseSearchFilter
{
    public function __construct(
        public readonly string $column,
        public readonly string $operator,
        public readonly mixed $value = null
    ) {}

    /** @return array<int,self> */
    public static function normalize(array $filters): array
    {
        $out = [];
        foreach ($filters as $column => $value) {
            if (!is_string($column) || $column === '') {
                throw new InvalidArgumentException('Database filter column must be a string.');
            }
            SqlIdentifier::assert($column, 'filter column');
            if (is_array($value) && count($value) === 1) {
                $operator = (string)array_key_first($value);
                $out[] = new self($column, DatabaseFilterOperator::assert($operator), $value[$operator]);
                continue;
            }
            $out[] = new self($column, DatabaseFilterOperator::EQ, $value);
        }
        return $out;
    }
}
