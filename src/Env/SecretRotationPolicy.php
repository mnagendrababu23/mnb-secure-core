<?php
namespace Mnb\SecurityCore\Env;

class SecretRotationPolicy
{
    /** @param array<string,mixed> $config */
    public function __construct(private array $config = []) {}

    /** @return array<string,mixed> */
    public function evaluate(SecretDefinition $definition, ?string $createdAt = null): array
    {
        $created = $createdAt ?: $definition->createdAt();
        $warnAfter = (int)($this->config['warn_after_days'] ?? 180);
        $failAfter = (int)($this->config['fail_after_days'] ?? 365);
        $ageDays = null;
        $status = $definition->rotatable() ? 'rotation_metadata_missing' : 'not_rotatable';
        $severity = $definition->rotatable() ? 'medium' : 'info';
        if ($created) {
            $timestamp = strtotime($created);
            if ($timestamp !== false) {
                $ageDays = (int)floor((time() - $timestamp) / 86400);
                $status = 'ok';
                $severity = 'info';
                if ($ageDays >= $failAfter) {
                    $status = 'rotation_overdue';
                    $severity = 'high';
                } elseif ($ageDays >= $warnAfter) {
                    $status = 'rotation_due_soon';
                    $severity = 'medium';
                }
            }
        }
        return ['name' => $definition->name(), 'rotatable' => $definition->rotatable(), 'age_days' => $ageDays, 'status' => $status, 'severity' => $severity, 'current_key_id' => $definition->currentKeyId(), 'previous_key_ids' => $definition->previousKeyIds()];
    }
}
