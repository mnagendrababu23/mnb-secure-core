<?php
namespace Mnb\SecurityCore\Web;

class WebSecurityProfile
{
    /** @param array<string,mixed> $config */
    public function __construct(private string $name, private array $config = []) {}

    public static function fromArray(string $name, array $config): self
    {
        return new self($name, $config);
    }

    public function name(): string { return $this->name; }
    public function enabled(string $key): bool { return (bool)($this->config[$key] ?? false); }
    public function cachePolicy(): string { return (string)($this->config['cache_policy'] ?? 'private_user'); }
    public function framePolicy(): string { return (string)($this->config['frame_policy'] ?? 'sameorigin'); }
    public function option(string $key, mixed $default = null): mixed { return $this->config[$key] ?? $default; }
    /** @return array<string,mixed> */ public function toArray(): array { return $this->config; }
}
