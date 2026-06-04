<?php
namespace Mnb\SecurityCore\Database;

use InvalidArgumentException;

class SqlIdentifier
{
    public static function assert(string $identifier, string $label = 'SQL identifier'): string
    {
        $parts = explode('.', $identifier);
        foreach ($parts as $part) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $part)) {
                throw new InvalidArgumentException("Unsafe {$label}: {$identifier}");
            }
        }
        return $identifier;
    }

    /** @param array<int,string> $identifiers @return array<int,string> */
    public static function assertMany(array $identifiers, string $label = 'SQL identifier'): array
    {
        return array_map(fn($id) => self::assert((string)$id, $label), $identifiers);
    }
}
