<?php
namespace Mnb\SecurityCore\Queue;

final class BackoffStrategy
{
    public function __construct(private string $type = 'exponential', private int $initial = 5, private int $max = 300, private bool $jitter = true) {}
    public static function fromArray(array $config): self { return new self((string)($config['backoff'] ?? 'exponential'), (int)($config['initial_delay_seconds'] ?? 5), (int)($config['max_delay_seconds'] ?? 300), (bool)($config['jitter'] ?? true)); }
    public function delay(int $attempt): int
    {
        $base = $this->type === 'linear' ? $this->initial * max(1, $attempt) : $this->initial * (2 ** max(0, $attempt - 1));
        $delay = min($this->max, (int)$base);
        return $this->jitter ? min($this->max, $delay + random_int(0, max(1, (int)floor($delay / 4)))) : $delay;
    }
}
