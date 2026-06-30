<?php
namespace Mnb\SecurityCore\Runtime;

final class ProcessPolicy
{
    public function __construct(
        private bool $enabled = true,
        private bool $denyByDefault = true,
        private int $defaultTimeoutSeconds = 10,
        private int $maxOutputBytes = 65536,
        private array $allowedEnv = ['PATH', 'TMPDIR', 'TEMP'],
        private array $allowedWorkingDirectories = [],
        private ?CommandAllowList $allowList = null
    ) {
        $this->defaultTimeoutSeconds = max(1, $defaultTimeoutSeconds);
        $this->maxOutputBytes = max(1024, $maxOutputBytes);
        $this->allowedEnv = array_values(array_unique(array_map('strval', $allowedEnv)));
        $this->allowedWorkingDirectories = array_values(array_unique(array_filter(array_map('strval', $allowedWorkingDirectories))));
        $this->allowList = $allowList ?: new CommandAllowList();
    }

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config): self
    {
        $runtime = is_array($config['runtime'] ?? null) ? $config['runtime'] : [];
        $defaultTimeout = (int)($runtime['default_timeout_seconds'] ?? 10);
        $maxOutput = (int)($runtime['max_output_bytes'] ?? 65536);
        $allowedEnv = self::stringList($runtime['allowed_env'] ?? ['PATH', 'TMPDIR', 'TEMP']);
        return new self(
            !array_key_exists('enabled', $runtime) || $runtime['enabled'] !== false,
            !array_key_exists('deny_by_default', $runtime) || $runtime['deny_by_default'] !== false,
            $defaultTimeout,
            $maxOutput,
            $allowedEnv,
            self::stringList($runtime['allowed_working_directories'] ?? []),
            CommandAllowList::fromConfig(is_array($runtime['commands'] ?? null) ? $runtime['commands'] : [], $defaultTimeout, $maxOutput, $allowedEnv)
        );
    }

    public function enabled(): bool { return $this->enabled; }
    public function denyByDefault(): bool { return $this->denyByDefault; }
    public function defaultTimeoutSeconds(): int { return $this->defaultTimeoutSeconds; }
    public function maxOutputBytes(): int { return $this->maxOutputBytes; }
    /** @return array<int,string> */ public function allowedEnv(): array { return $this->allowedEnv; }
    /** @return array<int,string> */ public function allowedWorkingDirectories(): array { return $this->allowedWorkingDirectories; }
    public function allowList(): CommandAllowList { return $this->allowList; }

    /** @return array{passed:bool,reason:?string,definition:?CommandDefinition,args:array<int,string>,cwd:?string,env:array<string,string>,timeout:int,max_output_bytes:int} */
    public function validate(ProcessRequest $request): array
    {
        if (!$this->enabled) {
            return $this->deny('runtime_disabled');
        }

        $definition = $this->allowList->get($request->commandName());
        if ($definition === null && $this->denyByDefault) {
            return $this->deny('command_not_allowed');
        }
        if ($definition === null) {
            return $this->deny('command_definition_missing');
        }

        $argResult = SafeArgumentBuilder::build($request->arguments(), $definition->allowedArgs());
        if (!$argResult['passed']) {
            return $this->deny((string)$argResult['reason']);
        }

        $cwd = $request->workingDirectory() ?: $definition->workingDirectory();
        if ($cwd !== null && !$this->isAllowedWorkingDirectory($cwd)) {
            return $this->deny('working_directory_not_allowed');
        }

        $env = $this->filterEnvironment($request->environment(), $definition->allowedEnv() ?: $this->allowedEnv);
        if (count($env) !== count($request->environment())) {
            return $this->deny('environment_key_not_allowed');
        }

        return [
            'passed' => true,
            'reason' => null,
            'definition' => $definition,
            'args' => $argResult['args'],
            'cwd' => $cwd,
            'env' => $env,
            'timeout' => max(1, (int)($request->timeoutSeconds() ?? $definition->timeoutSeconds())),
            'max_output_bytes' => max(1024, $definition->maxOutputBytes()),
        ];
    }

    /** @return array<string,string> */
    public function filterEnvironment(array $environment, array $allowedKeys): array
    {
        $allowed = array_flip(array_map('strval', $allowedKeys));
        $out = [];
        foreach ($environment as $key => $value) {
            $key = (string)$key;
            if (!isset($allowed[$key])) {
                continue;
            }
            if (is_scalar($value) && !preg_match('/[\x00\r\n]/', (string)$value)) {
                $out[$key] = (string)$value;
            }
        }
        return $out;
    }

    public function isAllowedWorkingDirectory(string $directory): bool
    {
        if ($this->allowedWorkingDirectories === []) {
            return true;
        }
        $real = realpath($directory);
        if ($real === false || !is_dir($real)) {
            return false;
        }
        foreach ($this->allowedWorkingDirectories as $allowed) {
            $allowedReal = realpath($allowed);
            if ($allowedReal !== false && ($real === $allowedReal || str_starts_with($real, rtrim($allowedReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR))) {
                return true;
            }
        }
        return false;
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'enabled' => $this->enabled,
            'deny_by_default' => $this->denyByDefault,
            'default_timeout_seconds' => $this->defaultTimeoutSeconds,
            'max_output_bytes' => $this->maxOutputBytes,
            'allowed_env' => $this->allowedEnv,
            'allowed_working_directories' => $this->allowedWorkingDirectories,
            'commands' => $this->allowList->toArray(),
        ];
    }

    /** @return array{passed:bool,reason:string,definition:null,args:array<int,string>,cwd:null,env:array<string,string>,timeout:int,max_output_bytes:int} */
    private function deny(string $reason): array
    {
        return ['passed' => false, 'reason' => $reason, 'definition' => null, 'args' => [], 'cwd' => null, 'env' => [], 'timeout' => $this->defaultTimeoutSeconds, 'max_output_bytes' => $this->maxOutputBytes];
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
