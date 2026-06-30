<?php
namespace Mnb\SecurityCore\Database;

final class DatabaseFieldProtection
{
    public function __construct(
        public readonly bool $enabled = true,
        public readonly bool $maskSensitiveColumns = true,
        public readonly bool $denyPasswordColumns = true,
        public readonly array $defaultHiddenColumns = ['password', 'password_hash', 'remember_token', 'api_token', 'secret', 'private_key'],
        public readonly array $defaultMaskedColumns = ['email', 'phone', 'mobile', 'mobile_number']
    ) {}

    public static function fromConfig(array $config): self
    {
        $db = is_array($config['database'] ?? null) ? $config['database'] : [];
        $fp = is_array($db['field_protection'] ?? null) ? $db['field_protection'] : [];
        return new self(
            (bool)($fp['enabled'] ?? true),
            (bool)($fp['mask_sensitive_columns'] ?? true),
            (bool)($fp['deny_password_columns'] ?? true),
            array_values((array)($fp['hidden_columns'] ?? ['password', 'password_hash', 'remember_token', 'api_token', 'secret', 'private_key'])),
            array_values((array)($fp['masked_columns'] ?? ['email', 'phone', 'mobile', 'mobile_number']))
        );
    }

    public function shouldHide(string $column, TableSecurityPolicy $policy): bool
    {
        $column = strtolower($column);
        $hidden = array_map('strtolower', array_merge($this->defaultHiddenColumns, $policy->hiddenColumns));
        if (in_array($column, $hidden, true)) {
            return true;
        }
        if ($this->denyPasswordColumns && str_contains($column, 'password')) {
            return true;
        }
        return false;
    }

    public function shouldMask(string $column, TableSecurityPolicy $policy): bool
    {
        if (!$this->maskSensitiveColumns) {
            return false;
        }
        $column = strtolower($column);
        $masked = array_map('strtolower', array_merge($this->defaultMaskedColumns, $policy->maskedColumns, $policy->sensitiveColumns));
        return in_array($column, $masked, true);
    }
}
