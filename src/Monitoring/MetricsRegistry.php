<?php
namespace Mnb\SecurityCore\Monitoring;

class MetricsRegistry
{
    /** @var array<string,float> */
    private array $counters = [];

    public function __construct(private ?string $file = null)
    {
        if ($file !== null && is_file($file)) {
            $data = json_decode((string)file_get_contents($file), true);
            if (is_array($data)) {
                foreach ($data as $key => $value) {
                    if (is_numeric($value)) { $this->counters[(string)$key] = (float)$value; }
                }
            }
        }
    }

    /** @param array<string,string|int|float|bool|null> $labels */
    public function increment(string $name, array $labels = [], float $by = 1.0): float
    {
        $key = $this->key($name, $labels);
        $this->counters[$key] = ($this->counters[$key] ?? 0.0) + $by;
        $this->persist();
        return $this->counters[$key];
    }

    /** @param array<string,string|int|float|bool|null> $labels */
    public function get(string $name, array $labels = []): float
    {
        return $this->counters[$this->key($name, $labels)] ?? 0.0;
    }

    /** @return array<string,float> */
    public function all(): array { return $this->counters; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return ['passed' => true, 'counters' => $this->counters, 'count' => count($this->counters)];
    }

    /** @param array<string,string|int|float|bool|null> $labels */
    private function key(string $name, array $labels): string
    {
        ksort($labels);
        return $name . ($labels ? ':' . hash('sha256', json_encode($labels, JSON_UNESCAPED_SLASHES)) : '');
    }

    private function persist(): void
    {
        if ($this->file === null) { return; }
        $dir = dirname($this->file);
        if (!is_dir($dir)) { mkdir($dir, 0775, true); }
        file_put_contents($this->file, json_encode($this->counters, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    }
}
