<?php
namespace Mnb\SecurityCore\Runtime;

final class CommandDefinition
{
    /** @param array<int,string> $allowedArgs @param array<int,string> $allowedEnv */
    public function __construct(
        private string $name,
        private string $binary,
        private array $allowedArgs = [],
        private int $timeoutSeconds = 10,
        private int $maxOutputBytes = 65536,
        private ?string $workingDirectory = null,
        private array $allowedEnv = []
    ) {
        self::assertSafeName($name, 'command name');
        self::assertSafeBinary($binary);
        $this->allowedArgs = array_values(array_unique(array_map('strval', $allowedArgs)));
        $this->allowedEnv = array_values(array_unique(array_map('strval', $allowedEnv)));
        $this->timeoutSeconds = max(1, $timeoutSeconds);
        $this->maxOutputBytes = max(1024, $maxOutputBytes);
    }

    /** @param array<string,mixed> $config */
    public static function fromArray(string $name, array $config, int $defaultTimeout = 10, int $defaultMaxOutput = 65536, array $defaultAllowedEnv = []): self
    {
        return new self(
            $name,
            (string)($config['binary'] ?? $name),
            self::stringList($config['allowed_args'] ?? []),
            (int)($config['timeout_seconds'] ?? $defaultTimeout),
            (int)($config['max_output_bytes'] ?? $defaultMaxOutput),
            isset($config['working_directory']) && is_scalar($config['working_directory']) ? (string)$config['working_directory'] : null,
            self::stringList($config['allowed_env'] ?? $defaultAllowedEnv)
        );
    }

    public function name(): string { return $this->name; }
    public function binary(): string { return $this->binary; }
    /** @return array<int,string> */ public function allowedArgs(): array { return $this->allowedArgs; }
    public function timeoutSeconds(): int { return $this->timeoutSeconds; }
    public function maxOutputBytes(): int { return $this->maxOutputBytes; }
    public function workingDirectory(): ?string { return $this->workingDirectory; }
    /** @return array<int,string> */ public function allowedEnv(): array { return $this->allowedEnv; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'binary' => $this->binary,
            'allowed_args' => $this->allowedArgs,
            'timeout_seconds' => $this->timeoutSeconds,
            'max_output_bytes' => $this->maxOutputBytes,
            'working_directory' => $this->workingDirectory,
            'allowed_env' => $this->allowedEnv,
        ];
    }

    private static function assertSafeName(string $value, string $label): void
    {
        if (!preg_match('/^[a-z0-9][a-z0-9_.:-]{0,95}$/', strtolower($value))) {
            throw new \InvalidArgumentException("Runtime {$label} must be a safe identifier.");
        }
    }

    public static function assertSafeBinary(string $binary): void
    {
        $binary = trim($binary);
        if ($binary === '' || preg_match('/[\x00\r\n;&|`$<>]/', $binary)) {
            throw new \InvalidArgumentException('Runtime command binary contains unsafe characters.');
        }
        $base = basename(str_replace('\\', '/', $binary));
        if ($base === '' || in_array(strtolower($base), ['sh', 'bash', 'cmd', 'powershell', 'pwsh'], true)) {
            throw new \InvalidArgumentException('Runtime command binary cannot be a shell interpreter.');
        }
    }

    /** @return array<int,string> */
    private static function stringList(mixed $value): array
    {
        if (is_string($value)) {
            $value = array_filter(array_map('trim', explode(',', $value)));
        }
        if (!is_array($value)) {
            return [];
        }
        $out = [];
        foreach ($value as $item) {
            if (is_scalar($item) && trim((string)$item) !== '') {
                $out[] = trim((string)$item);
            }
        }
        return array_values(array_unique($out));
    }
}
