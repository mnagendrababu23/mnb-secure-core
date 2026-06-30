<?php
namespace Mnb\SecurityCore\Errors;

final class ErrorEscalationPolicy
{
    /** @param array<string,mixed> $config */
    public function __construct(private array $config = []) {}

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config): self
    {
        return new self($config);
    }

    /** @param array<string,mixed> $event */
    public function shouldEscalate(array $event, int $occurrenceCount = 1): bool
    {
        $errors = is_array($this->config['errors'] ?? null) ? $this->config['errors'] : [];
        $esc = is_array($errors['escalation'] ?? null) ? $errors['escalation'] : [];
        if (($esc['enabled'] ?? true) === false) {
            return false;
        }
        $code = (string)($event['mapped_error_code'] ?? '');
        $status = (int)($event['public_status'] ?? 500);
        if (!empty($esc['alert_on_security_exception']) && $code === 'SECURITY_BLOCKED') {
            return true;
        }
        $threshold = max(1, (int)($esc['critical_error_threshold'] ?? 5));
        if (!empty($esc['alert_on_repeated_500']) && $status >= 500 && $occurrenceCount >= $threshold) {
            return true;
        }
        return false;
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        $errors = is_array($this->config['errors'] ?? null) ? $this->config['errors'] : [];
        $esc = is_array($errors['escalation'] ?? null) ? $errors['escalation'] : [];
        return [
            'enabled' => (bool)($esc['enabled'] ?? true),
            'critical_error_threshold' => (int)($esc['critical_error_threshold'] ?? 5),
            'window_seconds' => (int)($esc['window_seconds'] ?? 300),
            'alert_on_security_exception' => (bool)($esc['alert_on_security_exception'] ?? true),
            'alert_on_repeated_500' => (bool)($esc['alert_on_repeated_500'] ?? true),
        ];
    }
}
