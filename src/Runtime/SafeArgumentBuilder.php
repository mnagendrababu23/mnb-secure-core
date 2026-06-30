<?php
namespace Mnb\SecurityCore\Runtime;

final class SafeArgumentBuilder
{
    /** @param array<int,mixed> $arguments @return array{passed:bool,args:array<int,string>,reason:?string,argument:?string} */
    public static function build(array $arguments, array $allowedOptionArgs = []): array
    {
        $safe = [];
        foreach ($arguments as $argument) {
            if (!is_scalar($argument)) {
                return ['passed' => false, 'args' => [], 'reason' => 'argument_not_scalar', 'argument' => null];
            }
            $value = (string)$argument;
            $validation = self::validate($value, $allowedOptionArgs);
            if (!$validation['passed']) {
                return ['passed' => false, 'args' => [], 'reason' => $validation['reason'], 'argument' => self::fingerprint($value)];
            }
            $safe[] = $value;
        }
        return ['passed' => true, 'args' => $safe, 'reason' => null, 'argument' => null];
    }

    /** @return array{passed:bool,reason:?string} */
    public static function validate(string $argument, array $allowedOptionArgs = []): array
    {
        if ($argument === '') {
            return ['passed' => false, 'reason' => 'empty_argument'];
        }
        if (preg_match('/[\x00\r\n]/', $argument)) {
            return ['passed' => false, 'reason' => 'control_character_blocked'];
        }
        if (preg_match('/(;|&&|\|\||`|\$\(|<|>)/', $argument)) {
            return ['passed' => false, 'reason' => 'shell_metacharacter_blocked'];
        }
        if (str_starts_with($argument, '-') && !in_array($argument, $allowedOptionArgs, true)) {
            return ['passed' => false, 'reason' => 'option_argument_not_allowed'];
        }
        return ['passed' => true, 'reason' => null];
    }

    public static function fingerprint(string $value): string
    {
        return substr(hash('sha256', $value), 0, 16);
    }
}
