<?php
namespace Mnb\SecurityCore\Files;

use InvalidArgumentException;

class FileSecurityPolicy
{
    /** @param list<string> $actions @param list<string> $roles @param list<string> $permissions @param list<string> $scopes @param list<string> $dataClasses @param list<string> $inlineProfiles */
    public function __construct(
        private string $name,
        private array $actions = ['download'],
        private array $roles = [],
        private array $permissions = [],
        private array $scopes = [],
        private bool $tenantRequired = false,
        private array $dataClasses = ['public', 'internal', 'confidential', 'sensitive'],
        private bool $audit = true,
        private bool $requireScanPassed = true,
        private string $disposition = 'attachment',
        private bool $allowInline = false,
        private array $inlineProfiles = ['images'],
        private string $cachePolicy = 'download',
        private bool $signedUrls = false,
        private int $signedUrlTtl = 900
    ) {
        self::assertName($name, 'file security policy');
        foreach ($actions as $action) { self::assertName($action, 'file action'); }
        if (!in_array($disposition, ['attachment', 'inline'], true)) {
            throw new InvalidArgumentException('Download disposition must be attachment or inline.');
        }
    }

    /** @param array<string,mixed> $config */
    public static function fromArray(string $name, array $config): self
    {
        return new self(
            $name,
            self::stringList($config['actions'] ?? ['download']),
            self::stringList($config['roles'] ?? []),
            self::stringList($config['permissions'] ?? []),
            self::stringList($config['scopes'] ?? []),
            (bool)($config['tenant_required'] ?? false),
            self::stringList($config['data_classes'] ?? ['public', 'internal', 'confidential', 'sensitive']),
            (bool)($config['audit'] ?? true),
            (bool)($config['require_scan_passed'] ?? true),
            (string)($config['disposition'] ?? 'attachment'),
            (bool)($config['allow_inline'] ?? false),
            self::stringList($config['inline_profiles'] ?? ['images']),
            (string)($config['cache_policy'] ?? 'download'),
            (bool)($config['signed_urls']['enabled'] ?? $config['signed_urls'] ?? false),
            (int)($config['signed_urls']['ttl'] ?? $config['signed_url_ttl'] ?? 900)
        );
    }

    public function name(): string { return $this->name; }
    /** @return list<string> */ public function actions(): array { return $this->actions; }
    /** @return list<string> */ public function roles(): array { return $this->roles; }
    /** @return list<string> */ public function permissions(): array { return $this->permissions; }
    /** @return list<string> */ public function scopes(): array { return $this->scopes; }
    public function tenantRequired(): bool { return $this->tenantRequired; }
    /** @return list<string> */ public function dataClasses(): array { return $this->dataClasses; }
    public function audit(): bool { return $this->audit; }
    public function requireScanPassed(): bool { return $this->requireScanPassed; }
    public function disposition(): string { return $this->disposition; }
    public function allowInline(): bool { return $this->allowInline; }
    /** @return list<string> */ public function inlineProfiles(): array { return $this->inlineProfiles; }
    public function cachePolicy(): string { return $this->cachePolicy; }
    public function signedUrls(): bool { return $this->signedUrls; }
    public function signedUrlTtl(): int { return $this->signedUrlTtl; }

    public function allowsAction(string $action): bool { return in_array('*', $this->actions, true) || in_array($action, $this->actions, true); }
    public function allowsDataClass(string $class): bool { return in_array('*', $this->dataClasses, true) || in_array($class, $this->dataClasses, true); }
    public function dispositionFor(FileSecurityRecord $record, ?string $requested = null): string
    {
        $wanted = $requested ?: $this->disposition;
        if ($wanted === 'inline' && $this->allowInline && in_array($record->profile(), $this->inlineProfiles, true)) {
            return 'inline';
        }
        return 'attachment';
    }

    private static function assertName(string $value, string $label): void
    {
        if (!preg_match('/^[A-Za-z0-9_.:-]{1,120}$/', $value)) {
            throw new InvalidArgumentException("Invalid {$label} name.");
        }
    }

    /** @return list<string> */
    private static function stringList(mixed $value): array
    {
        if (!is_array($value)) { return []; }
        $out = [];
        foreach ($value as $item) {
            if (is_scalar($item) && trim((string)$item) !== '') {
                $out[] = trim((string)$item);
            }
        }
        return array_values(array_unique($out));
    }
}
