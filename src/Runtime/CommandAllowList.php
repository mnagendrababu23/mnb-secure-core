<?php
namespace Mnb\SecurityCore\Runtime;

final class CommandAllowList
{
    /** @param array<string,CommandDefinition> $commands */
    public function __construct(private array $commands = []) {}

    /** @param array<string,mixed> $commands */
    public static function fromConfig(array $commands, int $defaultTimeout = 10, int $defaultMaxOutput = 65536, array $defaultAllowedEnv = []): self
    {
        $items = [];
        foreach ($commands as $name => $config) {
            if (!is_array($config)) {
                continue;
            }
            $definition = CommandDefinition::fromArray((string)$name, $config, $defaultTimeout, $defaultMaxOutput, $defaultAllowedEnv);
            $items[$definition->name()] = $definition;
        }
        return new self($items);
    }

    public function has(string $name): bool
    {
        return isset($this->commands[$name]);
    }

    public function get(string $name): ?CommandDefinition
    {
        return $this->commands[$name] ?? null;
    }

    /** @return array<int,string> */
    public function names(): array
    {
        return array_keys($this->commands);
    }

    /** @return array<string,array<string,mixed>> */
    public function toArray(): array
    {
        $out = [];
        foreach ($this->commands as $name => $definition) {
            $out[$name] = $definition->toArray();
        }
        return $out;
    }
}
