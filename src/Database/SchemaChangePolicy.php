<?php
namespace Mnb\SecurityCore\Database;

final class SchemaChangePolicy
{
    public function __construct(
        public readonly bool $enabled = true,
        public readonly bool $requireSuperAdmin = true,
        public readonly bool $requireBackupBeforeAlter = true,
        public readonly bool $allowDestructiveChanges = false,
        public readonly bool $dryRunDefault = true,
        public readonly array $allowedOperations = ['add_column', 'add_index']
    ) {}

    public static function fromConfig(array $config): self
    {
        $db = is_array($config['database'] ?? null) ? $config['database'] : [];
        $schema = is_array($db['schema_changes'] ?? null) ? $db['schema_changes'] : [];
        return new self(
            (bool)($schema['enabled'] ?? true),
            (bool)($schema['require_super_admin'] ?? true),
            (bool)($schema['require_backup_before_alter'] ?? true),
            (bool)($schema['allow_destructive_changes'] ?? false),
            (bool)($schema['dry_run_default'] ?? true),
            array_values((array)($schema['allowed_operations'] ?? ['add_column', 'add_index']))
        );
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'enabled' => $this->enabled,
            'require_super_admin' => $this->requireSuperAdmin,
            'require_backup_before_alter' => $this->requireBackupBeforeAlter,
            'allow_destructive_changes' => $this->allowDestructiveChanges,
            'dry_run_default' => $this->dryRunDefault,
            'allowed_operations' => $this->allowedOperations,
        ];
    }
}
