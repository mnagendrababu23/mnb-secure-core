<?php
namespace Mnb\SecurityCore\Recovery;

class BackupPolicy
{
    /** @param list<string> $include @param list<string> $exclude @param array<string,mixed> $retention */
    public function __construct(
        private bool $enabled = true,
        private string $path = '',
        private bool $encrypt = true,
        private bool $sign = true,
        private string $key = '',
        private string $signingKey = '',
        private array $include = [],
        private array $exclude = [],
        private array $retention = []
    ) {}

    public static function fromConfig(array $config, array $paths = []): self
    {
        $recovery = is_array($config['recovery'] ?? null) ? $config['recovery'] : [];
        $backups = is_array($recovery['backups'] ?? null) ? $recovery['backups'] : [];
        $backupPath = (string)($backups['path'] ?? ($paths['backups'] ?? ($config['paths']['backups'] ?? dirname(__DIR__, 2) . '/storage/backups')));
        $appKey = (string)($config['app']['key'] ?? '');
        return new self(
            !array_key_exists('enabled', $backups) || !empty($backups['enabled']),
            $backupPath,
            !empty($backups['encrypt']),
            !empty($backups['sign']),
            (string)($backups['key'] ?? ($_ENV['BACKUP_KEY'] ?? $appKey)),
            (string)($backups['signing_key'] ?? ($_ENV['BACKUP_SIGNING_KEY'] ?? $appKey)),
            array_values(array_filter(array_map('strval', (array)($backups['include'] ?? [])))) ,
            array_values(array_filter(array_map('strval', (array)($backups['exclude'] ?? [])))) ,
            is_array($backups['retention'] ?? null) ? $backups['retention'] : []
        );
    }

    public function enabled(): bool { return $this->enabled; }
    public function path(): string { return $this->path; }
    public function encrypt(): bool { return $this->encrypt; }
    public function sign(): bool { return $this->sign; }
    public function key(): string { return $this->key; }
    public function signingKey(): string { return $this->signingKey !== '' ? $this->signingKey : $this->key; }
    /** @return list<string> */ public function include(): array { return $this->include; }
    /** @return list<string> */ public function exclude(): array { return $this->exclude; }
    /** @return array<string,mixed> */ public function retention(): array { return $this->retention; }
}
