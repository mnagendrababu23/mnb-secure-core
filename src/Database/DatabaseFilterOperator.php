<?php
namespace Mnb\SecurityCore\Database;

use InvalidArgumentException;

final class DatabaseFilterOperator
{
    public const EQ = 'eq';
    public const NEQ = 'neq';
    public const IN = 'in';
    public const NOT_IN = 'not_in';
    public const LIKE = 'like';
    public const STARTS_WITH = 'starts_with';
    public const ENDS_WITH = 'ends_with';
    public const BETWEEN = 'between';
    public const GTE = 'gte';
    public const LTE = 'lte';
    public const GT = 'gt';
    public const LT = 'lt';
    public const IS_NULL = 'is_null';
    public const IS_NOT_NULL = 'is_not_null';

    /** @return array<int,string> */
    public static function allowed(): array
    {
        return [self::EQ, self::NEQ, self::IN, self::NOT_IN, self::LIKE, self::STARTS_WITH, self::ENDS_WITH, self::BETWEEN, self::GTE, self::LTE, self::GT, self::LT, self::IS_NULL, self::IS_NOT_NULL];
    }

    public static function assert(string $operator): string
    {
        $operator = strtolower(trim($operator));
        if (!in_array($operator, self::allowed(), true)) {
            throw new InvalidArgumentException("Database filter operator not allowed: {$operator}");
        }
        return $operator;
    }
}
