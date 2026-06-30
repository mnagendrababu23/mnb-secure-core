<?php
namespace Mnb\SecurityCore\Files;

use InvalidArgumentException;

class UploadSecurityProfile
{
    public const DEFAULT = 'default';
    public const IMAGES = 'images';
    public const DOCUMENTS = 'documents';
    public const VIDEOS = 'videos';
    public const ARCHIVES = 'archives';
    public const STRICT = 'strict';

    /** @return array<string,array<string,mixed>> */
    public static function all(): array
    {
        return [
            self::DEFAULT => [
                'description' => 'General safe public default for common images and office/document uploads.',
                'allowed_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'txt', 'csv', 'json', 'doc', 'docx', 'xls', 'xlsx'],
                'allowed_mime_prefixes' => ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf', 'text/plain', 'text/csv', 'application/json', 'application/msword', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.'],
                'max_bytes' => 10 * 1024 * 1024,
            ],
            self::IMAGES => [
                'description' => 'Images only: safe web image types with image signature verification.',
                'allowed_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'webp'],
                'allowed_mime_prefixes' => ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
                'max_bytes' => 5 * 1024 * 1024,
            ],
            self::DOCUMENTS => [
                'description' => 'Documents only: PDF, plain text, CSV, JSON, and common Office formats.',
                'allowed_extensions' => ['pdf', 'txt', 'csv', 'json', 'doc', 'docx', 'xls', 'xlsx'],
                'allowed_mime_prefixes' => ['application/pdf', 'text/plain', 'text/csv', 'application/json', 'application/msword', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.'],
                'max_bytes' => 15 * 1024 * 1024,
            ],
            self::VIDEOS => [
                'description' => 'Videos only: common browser/mobile video formats. Store privately and stream through authorization checks.',
                'allowed_extensions' => ['mp4', 'webm', 'mov', 'm4v'],
                'allowed_mime_prefixes' => ['video/mp4', 'video/webm', 'video/quicktime', 'video/x-m4v'],
                'max_bytes' => 100 * 1024 * 1024,
            ],
            self::ARCHIVES => [
                'description' => 'Archives only: higher-risk profile for private workflows. Avoid public unauthenticated archive uploads.',
                'allowed_extensions' => ['zip', 'tar', 'gz', 'tgz'],
                'allowed_mime_prefixes' => ['application/zip', 'application/x-zip-compressed', 'application/x-tar', 'application/gzip', 'application/x-gzip', 'application/octet-stream'],
                'max_bytes' => 25 * 1024 * 1024,
                'max_archive_entries' => 500,
                'max_archive_uncompressed_bytes' => 100 * 1024 * 1024,
            ],
            self::STRICT => [
                'description' => 'Strict production preset: conservative images plus PDF/text/CSV only.',
                'allowed_extensions' => ['jpg', 'jpeg', 'png', 'webp', 'pdf', 'txt', 'csv'],
                'allowed_mime_prefixes' => ['image/jpeg', 'image/png', 'image/webp', 'application/pdf', 'text/plain', 'text/csv'],
                'max_bytes' => 5 * 1024 * 1024,
            ],
        ];
    }

    /** @return list<string> */
    public static function names(): array
    {
        return array_keys(self::all());
    }

    public static function exists(string $name, array $customProfiles = []): bool
    {
        $name = self::normalizeName($name);
        return isset(self::all()[$name]) || isset($customProfiles[$name]);
    }

    /** @param array<string,mixed> $customProfiles @return array<string,mixed> */
    public static function definition(string $name, array $customProfiles = []): array
    {
        $name = self::normalizeName($name);
        if (isset($customProfiles[$name]) && is_array($customProfiles[$name])) {
            return self::mergeProfile(self::all()[$name] ?? [], $customProfiles[$name]);
        }
        $profiles = self::all();
        if (!isset($profiles[$name])) {
            throw new InvalidArgumentException("Unknown upload security profile '{$name}'.");
        }
        return $profiles[$name];
    }

    /** @param array<string,mixed> $overrides */
    public static function policy(string $name, ?int $maxBytes = null, array $overrides = [], array $customProfiles = []): FileUploadPolicy
    {
        $name = self::normalizeName($name);
        $definition = self::mergeProfile(self::definition($name, $customProfiles), $overrides);

        return new FileUploadPolicy(
            self::normalizeList($definition['allowed_extensions'] ?? []),
            self::normalizeList($definition['allowed_mime_prefixes'] ?? []),
            $maxBytes ?? (int)($definition['max_bytes'] ?? 10 * 1024 * 1024),
            (bool)($definition['deny_double_extensions'] ?? true),
            (bool)($definition['randomize_names'] ?? true),
            self::normalizeList($definition['blocked_extensions'] ?? FileUploadPolicy::dangerousExtensions()),
            (int)($definition['max_original_name_length'] ?? 180),
            (bool)($definition['reject_executable_content'] ?? true),
            is_array($definition['mime_by_extension'] ?? null) ? $definition['mime_by_extension'] : [],
            $name,
            (bool)($definition['strict_mode'] ?? false),
            (int)($definition['max_archive_entries'] ?? 500),
            (int)($definition['max_archive_uncompressed_bytes'] ?? 100 * 1024 * 1024)
        );
    }

    public static function normalizeName(string $name): string
    {
        $name = strtolower(trim($name));
        return $name === '' ? self::DEFAULT : $name;
    }

    /** @param array<string,mixed> $base @param array<string,mixed> $overrides @return array<string,mixed> */
    private static function mergeProfile(array $base, array $overrides): array
    {
        foreach ($overrides as $key => $value) {
            if ($value === null) {
                continue;
            }
            $base[$key] = $value;
        }
        return $base;
    }

    /** @return list<string> */
    private static function normalizeList(mixed $value): array
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
                $out[] = ltrim($item, '.');
            }
        }
        return array_values(array_unique($out));
    }
}
