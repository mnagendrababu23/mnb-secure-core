<?php
namespace Mnb\SecurityCore\Web;

final class OutputEncodingPolicy
{
    /** @param array<string,mixed> $config */
    public function __construct(private array $config = []) {}

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config): self
    {
        $web = is_array($config['web_security'] ?? null) ? $config['web_security'] : [];
        $output = is_array($web['output_encoding'] ?? null) ? $web['output_encoding'] : [];
        return new self($output);
    }

    public function enabled(): bool { return (bool)($this->config['enabled'] ?? true); }
    public function enforceByDefault(): bool { return (bool)($this->config['enforce_by_default'] ?? true); }
    public function requireSafeValues(): bool { return (bool)($this->config['require_safe_values'] ?? true); }
    public function failOnRawEchoPatterns(): bool { return (bool)($this->config['fail_on_raw_echo_patterns'] ?? true); }

    /** @return list<string> */
    public function allowedRawVariables(): array
    {
        return array_values(array_filter(array_map('strval', $this->config['allowed_raw_variables'] ?? [])));
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'enabled' => $this->enabled(),
            'enforce_by_default' => $this->enforceByDefault(),
            'require_safe_values' => $this->requireSafeValues(),
            'fail_on_raw_echo_patterns' => $this->failOnRawEchoPatterns(),
            'allowed_raw_variables' => $this->allowedRawVariables(),
            'contexts' => ['html', 'attr', 'url', 'js', 'css'],
        ];
    }
}
