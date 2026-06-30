<?php
namespace Mnb\SecurityCore\Network;

final class AllowedHostPolicy
{
    /** @param array<int,string> $allowedHosts @param array<int,string> $blockedHosts */
    public function __construct(private array $allowedHosts = [], private array $blockedHosts = ['localhost'])
    {
        $this->allowedHosts = self::normalizeList($allowedHosts);
        $this->blockedHosts = self::normalizeList($blockedHosts);
    }

    public function isAllowed(string $host): bool
    {
        $host = $this->normalizeHost($host);
        if ($host === '') {
            return false;
        }
        if ($this->isBlocked($host)) {
            return false;
        }
        if ($this->allowedHosts === []) {
            return true;
        }
        foreach ($this->allowedHosts as $allowed) {
            if ($this->matches($host, $allowed)) {
                return true;
            }
        }
        return false;
    }

    public function isBlocked(string $host): bool
    {
        $host = $this->normalizeHost($host);
        foreach ($this->blockedHosts as $blocked) {
            if ($this->matches($host, $blocked)) {
                return true;
            }
        }
        return false;
    }

    private function matches(string $host, string $pattern): bool
    {
        $pattern = $this->normalizeHost($pattern);
        if ($pattern === '*') {
            return true;
        }
        if (str_starts_with($pattern, '*.')) {
            $suffix = substr($pattern, 1);
            return str_ends_with($host, $suffix) && $host !== ltrim($suffix, '.');
        }
        return $host === $pattern;
    }

    private function normalizeHost(string $host): string
    {
        $host = strtolower(trim($host));
        $host = trim($host, " \t\n\r\0\x0B.");
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            $host = substr($host, 1, -1);
        }
        return $host;
    }

    /** @return array<int,string> */
    private static function normalizeList(array $items): array
    {
        $out = [];
        foreach ($items as $item) {
            if (is_scalar($item) && trim((string)$item) !== '') {
                $out[] = strtolower(trim((string)$item));
            }
        }
        return array_values(array_unique($out));
    }
}
