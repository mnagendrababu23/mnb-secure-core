<?php
namespace Mnb\SecurityCore\Cache;

class SafeCacheSerializer
{
    public function __construct(private int $maxBytes = 1048576) {}

    public function encode(mixed $value, ?int $maxBytes = null): string
    {
        $this->assertSafeValue($value);
        $payload = json_encode([
            'v' => 1,
            'type' => get_debug_type($value),
            'data' => $value,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $limit = $maxBytes ?? $this->maxBytes;
        if (strlen($payload) > $limit) {
            throw new \InvalidArgumentException('Cache value exceeds configured max_value_bytes.');
        }
        return $payload;
    }

    public function decode(string $payload): mixed
    {
        $decoded = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded) || ($decoded['v'] ?? null) !== 1 || !array_key_exists('data', $decoded)) {
            throw new \RuntimeException('Invalid safe cache payload.');
        }
        return $decoded['data'];
    }

    private function assertSafeValue(mixed $value): void
    {
        if (is_resource($value)) {
            throw new \InvalidArgumentException('Resources cannot be cached safely.');
        }
        if ($value instanceof \Closure) {
            throw new \InvalidArgumentException('Closures cannot be cached safely.');
        }
        if (is_object($value) && !$value instanceof \JsonSerializable) {
            throw new \InvalidArgumentException('Only JsonSerializable objects may be cached.');
        }
        if (is_array($value)) {
            foreach ($value as $item) {
                $this->assertSafeValue($item);
            }
        }
    }
}
