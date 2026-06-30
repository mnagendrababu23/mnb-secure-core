<?php
namespace Mnb\SecurityCore\RateLimit;

use InvalidArgumentException;
use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Http\Request;

class RateLimitPolicy
{
    /** @var list<string> */
    private array $keyBy;

    /**
     * @param list<string> $keyBy Supported parts: ip, user, route, path, method, auth.
     */
    public function __construct(
        private string $name,
        private int $maxAttempts,
        private int $decaySeconds,
        array $keyBy = ['ip', 'path'],
        private string $prefix = 'request'
    ) {
        $this->name = self::normalizeName($name, 'policy name');
        if ($this->maxAttempts < 1) {
            throw new InvalidArgumentException('Rate limit max attempts must be greater than zero.');
        }
        if ($this->decaySeconds < 1) {
            throw new InvalidArgumentException('Rate limit decay seconds must be greater than zero.');
        }
        $this->prefix = self::normalizeName($prefix, 'policy prefix');
        $this->keyBy = self::normalizeKeyParts($keyBy);
    }

    public static function default(int $maxAttempts, int $decaySeconds, string $prefix = 'request'): self
    {
        return new self($prefix, $maxAttempts, $decaySeconds, ['ip', 'path'], $prefix);
    }

    /**
     * @param array<string,mixed> $config
     */
    public static function fromArray(string $name, array $config): self
    {
        $max = $config['max'] ?? $config['max_attempts'] ?? null;
        $seconds = $config['seconds'] ?? $config['decay_seconds'] ?? $config['decay'] ?? null;
        $keyBy = $config['key_by'] ?? $config['by'] ?? ['ip', 'path'];
        $prefix = $config['prefix'] ?? 'request';

        if (is_string($keyBy)) {
            $keyBy = array_map('trim', explode(',', $keyBy));
        }

        if (!is_int($max) && !(is_string($max) && ctype_digit($max))) {
            throw new InvalidArgumentException("Rate limit policy '{$name}' requires integer max attempts.");
        }
        if (!is_int($seconds) && !(is_string($seconds) && ctype_digit($seconds))) {
            throw new InvalidArgumentException("Rate limit policy '{$name}' requires integer decay seconds.");
        }
        if (!is_array($keyBy)) {
            throw new InvalidArgumentException("Rate limit policy '{$name}' key_by must be an array or comma-separated string.");
        }

        return new self($name, (int)$max, (int)$seconds, array_values($keyBy), (string)$prefix);
    }

    public function name(): string
    {
        return $this->name;
    }

    public function maxAttempts(): int
    {
        return $this->maxAttempts;
    }

    public function decaySeconds(): int
    {
        return $this->decaySeconds;
    }

    /** @return list<string> */
    public function keyBy(): array
    {
        return $this->keyBy;
    }

    public function prefix(): string
    {
        return $this->prefix;
    }

    public function key(Request $request, ?string $routeName = null): string
    {
        return RateLimitKeyBuilder::forRequest($request, $this, $routeName);
    }

    private static function normalizeName(string $name, string $label): string
    {
        $name = strtolower(trim($name));
        if ($name === '' || !preg_match('/^[a-z0-9][a-z0-9_.:-]{0,80}$/', $name)) {
            throw new InvalidArgumentException("Invalid rate limit {$label}. Use letters, numbers, dash, underscore, dot or colon.");
        }
        return $name;
    }

    /**
     * @param array<int,mixed> $parts
     * @return list<string>
     */
    private static function normalizeKeyParts(array $parts): array
    {
        $allowed = ['ip', 'user', 'route', 'path', 'method', 'auth'];
        $normalized = [];
        foreach ($parts as $part) {
            $part = strtolower(trim((string)$part));
            if ($part === '') {
                continue;
            }
            if (!in_array($part, $allowed, true)) {
                throw new InvalidArgumentException("Unsupported rate limit key part '{$part}'.");
            }
            if (!in_array($part, $normalized, true)) {
                $normalized[] = $part;
            }
        }

        return $normalized !== [] ? $normalized : ['ip', 'path'];
    }
}
