<?php
namespace Mnb\SecurityCore\Logging;

class LogRetentionPolicy
{
    /** @param array<string,int> $days */
    public function __construct(private array $days = []) {}

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config): self
    {
        $retention = is_array($config['logging']['retention'] ?? null) ? $config['logging']['retention'] : [];
        return new self([
            'app' => (int)($retention['app_days'] ?? 14),
            'security' => (int)($retention['security_days'] ?? 90),
            'audit' => (int)($retention['audit_days'] ?? 365),
            'debug' => (int)($retention['debug_days'] ?? 7),
        ]);
    }

    public function days(string $channel): int
    {
        return max(0, (int)($this->days[$channel] ?? $this->days['app'] ?? 14));
    }

    /** @return array<string,int> */
    public function all(): array { return $this->days; }
}
