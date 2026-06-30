<?php
namespace Mnb\SecurityCore\Env;

class EnvironmentProfile
{
    public function __construct(private string $name) {}

    public static function fromConfig(array $config): self
    {
        return new self((string)($config['app']['env'] ?? 'local'));
    }

    public function name(): string { return $this->name; }
    public function isProduction(): bool { return $this->name === 'production'; }
    public function isCi(): bool { return in_array($this->name, ['ci', 'testing', 'test'], true); }
    public function allowsWeakDemoSecrets(): bool { return !$this->isProduction(); }
}
