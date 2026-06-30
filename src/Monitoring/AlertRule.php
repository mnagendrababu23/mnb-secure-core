<?php
namespace Mnb\SecurityCore\Monitoring;

class AlertRule
{
    /** @param array<string,mixed> $match */
    public function __construct(
        public readonly string $name,
        public readonly string $event,
        public readonly int $threshold = 1,
        public readonly int $windowSeconds = 300,
        public readonly string $severity = 'warning',
        public readonly array $match = [],
        public readonly bool $enabled = true
    ) {
        if (!preg_match('/^[a-z][a-z0-9_.:-]{1,100}$/', $name)) {
            throw new \InvalidArgumentException('Alert rule name must be safe.');
        }
    }

    /** @param array<string,mixed> $config */
    public static function fromArray(string $name, array $config): self
    {
        return new self(
            $name,
            (string)($config['event'] ?? $name),
            max(1, (int)($config['threshold'] ?? 1)),
            max(1, (int)($config['window_seconds'] ?? 300)),
            (string)($config['severity'] ?? 'warning'),
            is_array($config['match'] ?? null) ? $config['match'] : [],
            !array_key_exists('enabled', $config) || !empty($config['enabled'])
        );
    }

    /** @param array<string,mixed> $event */
    public function matches(array $event): bool
    {
        if (!$this->enabled) { return false; }
        if ((string)($event['event'] ?? '') !== $this->event) { return false; }
        foreach ($this->match as $key => $expected) {
            $actual = $this->arrayGet($event, (string)$key);
            if ($actual !== $expected) { return false; }
        }
        return true;
    }

    /** @param array<string,mixed> $data */
    private function arrayGet(array $data, string $path): mixed
    {
        $current = $data;
        foreach (explode('.', $path) as $part) {
            if (!is_array($current) || !array_key_exists($part, $current)) { return null; }
            $current = $current[$part];
        }
        return $current;
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return ['name' => $this->name, 'event' => $this->event, 'threshold' => $this->threshold, 'window_seconds' => $this->windowSeconds, 'severity' => $this->severity, 'match' => $this->match, 'enabled' => $this->enabled];
    }
}
