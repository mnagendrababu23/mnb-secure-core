<?php
namespace Mnb\SecurityCore\Memory;

use RuntimeException;

class PayloadSizeGuard
{
    public function __construct(private int $maxStringBytes = 1048576, private int $maxArrayItems = 10000) {}
    public static function fromConfig(array $config): self
    {
        $memory = is_array($config['memory'] ?? null) ? $config['memory'] : [];
        $payloads = is_array($memory['payloads'] ?? null) ? $memory['payloads'] : [];
        return new self((int)($payloads['max_string_bytes'] ?? 1048576), (int)($payloads['max_array_items'] ?? 10000));
    }
    public function assertString(string $value): void
    {
        if (strlen($value) > $this->maxStringBytes) { throw new RuntimeException('Payload string byte limit exceeded.'); }
    }
    public function assertArray(array $value): void
    {
        if ($this->countItems($value) > $this->maxArrayItems) { throw new RuntimeException('Payload array item limit exceeded.'); }
    }
    public function countItems(array $value): int
    {
        $count = 0;
        array_walk_recursive($value, function () use (&$count): void { $count++; });
        return $count + count($value);
    }
    public function toArray(): array { return ['max_string_bytes' => $this->maxStringBytes, 'max_array_items' => $this->maxArrayItems]; }
}
