<?php
namespace Mnb\SecurityCore\Files;

class FileUploadPolicy
{
    /** @return list<string> */
    public static function dangerousExtensions(): array
    {
        return ['php', 'phtml', 'phar', 'cgi', 'pl', 'sh', 'exe', 'com', 'bat', 'cmd', 'js', 'html', 'htm', 'svg'];
    }

    public function __construct(
        public readonly array $allowedExtensions,
        public readonly array $allowedMimePrefixes,
        public readonly int $maxBytes,
        public readonly bool $denyDoubleExtensions = true,
        public readonly bool $randomizeNames = true,
        public readonly array $blockedExtensions = ['php', 'phtml', 'phar', 'cgi', 'pl', 'sh', 'exe', 'com', 'bat', 'cmd', 'js', 'html', 'htm', 'svg'],
        public readonly int $maxOriginalNameLength = 180,
        public readonly bool $rejectExecutableContent = true,
        public readonly array $mimeByExtension = [],
        public readonly string $profile = 'custom',
        public readonly bool $strictMode = false,
        public readonly int $maxArchiveEntries = 500,
        public readonly int $maxArchiveUncompressedBytes = 104857600
    ) {}

    public static function fromConfig(array $config, int $maxBytes, ?string $environment = null, ?string $profileName = null): self
    {
        $environment = strtolower((string)($environment ?? 'local'));
        $selectedProfile = UploadSecurityProfile::normalizeName((string)($profileName ?? ($config['profile'] ?? 'custom')));
        $hasLegacyAllowLists = array_key_exists('allowed_extensions', $config) || array_key_exists('allowed_mime_prefixes', $config);
        $customProfiles = is_array($config['profiles'] ?? null) ? $config['profiles'] : [];
        $strictProduction = (bool)($config['strict_production'] ?? false) && $environment === 'production';

        if ($selectedProfile !== 'custom') {
            $profileDefinition = UploadSecurityProfile::definition($selectedProfile, $customProfiles);
            $profileMaxBytes = (int)($profileDefinition['max_bytes'] ?? $maxBytes);
            $policy = UploadSecurityProfile::policy($selectedProfile, min($maxBytes, $profileMaxBytes), self::extractPolicyOverrides($config, false), $customProfiles);
        } elseif (!$hasLegacyAllowLists) {
            $policy = UploadSecurityProfile::policy(UploadSecurityProfile::DEFAULT, $maxBytes, self::extractPolicyOverrides($config, false));
        } else {
            $policy = new self(
                self::normalizeExtensionList($config['allowed_extensions'] ?? []),
                self::normalizeMimeList($config['allowed_mime_prefixes'] ?? []),
                $maxBytes,
                (bool)($config['deny_double_extensions'] ?? true),
                (bool)($config['randomize_names'] ?? true),
                self::normalizeExtensionList($config['blocked_extensions'] ?? self::dangerousExtensions()),
                (int)($config['max_original_name_length'] ?? 180),
                (bool)($config['reject_executable_content'] ?? true),
                is_array($config['mime_by_extension'] ?? null) ? $config['mime_by_extension'] : [],
                'custom',
                false,
                (int)($config['max_archive_entries'] ?? 500),
                (int)($config['max_archive_uncompressed_bytes'] ?? 100 * 1024 * 1024)
            );
        }

        return $strictProduction ? $policy->strictened() : $policy;
    }

    public static function forProfile(string $name, ?int $maxBytes = null, array $overrides = []): self
    {
        return UploadSecurityProfile::policy($name, $maxBytes, $overrides);
    }

    public function strictened(): self
    {
        $blocked = array_values(array_unique(array_merge($this->blockedExtensions, self::dangerousExtensions())));
        $maxNameLength = min($this->maxOriginalNameLength, 180);

        return new self(
            $this->allowedExtensions,
            $this->allowedMimePrefixes,
            $this->maxBytes,
            true,
            true,
            $blocked,
            $maxNameLength,
            true,
            $this->mimeByExtension,
            $this->profile,
            true,
            $this->maxArchiveEntries,
            $this->maxArchiveUncompressedBytes
        );
    }

    public function allowsExtension(string $extension): bool
    {
        return in_array(strtolower(ltrim($extension, '.')), $this->allowedExtensions, true);
    }

    public function allowsMime(string $mime): bool
    {
        foreach ($this->allowedMimePrefixes as $prefix) {
            $prefix = strtolower((string)$prefix);
            $mime = strtolower($mime);
            if ($mime === $prefix || str_starts_with($mime, rtrim($prefix, '*'))) {
                return true;
            }
        }
        return false;
    }

    /** @return array<string,mixed> */
    public function describe(): array
    {
        return [
            'profile' => $this->profile,
            'strict_mode' => $this->strictMode,
            'allowed_extensions' => $this->allowedExtensions,
            'allowed_mime_prefixes' => $this->allowedMimePrefixes,
            'max_bytes' => $this->maxBytes,
            'deny_double_extensions' => $this->denyDoubleExtensions,
            'randomize_names' => $this->randomizeNames,
            'reject_executable_content' => $this->rejectExecutableContent,
            'max_archive_entries' => $this->maxArchiveEntries,
            'max_archive_uncompressed_bytes' => $this->maxArchiveUncompressedBytes,
        ];
    }

    /** @return array<string,mixed> */
    private static function extractPolicyOverrides(array $config, bool $includeAllowLists): array
    {
        $keys = [
            'deny_double_extensions',
            'randomize_names',
            'blocked_extensions',
            'max_original_name_length',
            'reject_executable_content',
            'mime_by_extension',
            'max_archive_entries',
            'max_archive_uncompressed_bytes',
        ];
        if ($includeAllowLists) {
            $keys[] = 'allowed_extensions';
            $keys[] = 'allowed_mime_prefixes';
            $keys[] = 'max_bytes';
        }

        $overrides = [];
        foreach ($keys as $key) {
            if (array_key_exists($key, $config)) {
                $overrides[$key] = $config[$key];
            }
        }
        return $overrides;
    }

    /** @return list<string> */
    private static function normalizeExtensionList(mixed $value): array
    {
        if (is_string($value)) {
            $value = array_map('trim', explode(',', $value));
        }
        if (!is_array($value)) {
            return [];
        }
        $out = [];
        foreach ($value as $item) {
            if (!is_scalar($item)) {
                continue;
            }
            $item = strtolower(ltrim(trim((string)$item), '.'));
            if ($item !== '') {
                $out[] = $item;
            }
        }
        return array_values(array_unique($out));
    }

    /** @return list<string> */
    private static function normalizeMimeList(mixed $value): array
    {
        if (is_string($value)) {
            $value = array_map('trim', explode(',', $value));
        }
        if (!is_array($value)) {
            return [];
        }
        $out = [];
        foreach ($value as $item) {
            if (!is_scalar($item)) {
                continue;
            }
            $item = strtolower(trim((string)$item));
            if ($item !== '') {
                $out[] = $item;
            }
        }
        return array_values(array_unique($out));
    }
}
