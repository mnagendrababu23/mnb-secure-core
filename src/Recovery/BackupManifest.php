<?php
namespace Mnb\SecurityCore\Recovery;

class BackupManifest
{
    /** @param array<string,mixed> $metadata @param list<array<string,mixed>> $items */
    public function __construct(private array $metadata, private array $items = []) {}

    /** @param list<string> $sources */
    public static function create(string $backupId, string $type, array $sources, string $archivePath, bool $encrypted, bool $signed): self
    {
        return new self([
            'backup_id' => $backupId,
            'type' => $type,
            'created_at' => date('c'),
            'archive' => basename($archivePath),
            'archive_path' => $archivePath,
            'archive_sha256' => is_file($archivePath) ? hash_file('sha256', $archivePath) : null,
            'archive_bytes' => is_file($archivePath) ? filesize($archivePath) : 0,
            'encrypted' => $encrypted,
            'signed' => $signed,
            'app_version' => 'v1.0.1',
        ], self::itemsFromSources($sources));
    }

    /** @param list<string> $sources @return list<array<string,mixed>> */
    private static function itemsFromSources(array $sources): array
    {
        $items = [];
        foreach ($sources as $source) {
            if (!file_exists($source)) { continue; }
            if (is_file($source)) {
                $items[] = self::item($source, basename($source));
                continue;
            }
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($source, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $file) {
                if ($file instanceof \SplFileInfo && $file->isFile()) {
                    $items[] = self::item($file->getPathname(), basename($source) . '/' . substr($file->getPathname(), strlen($source) + 1));
                }
            }
        }
        return $items;
    }

    /** @return array<string,mixed> */
    private static function item(string $path, string $relative): array
    {
        return [
            'path' => $relative,
            'bytes' => filesize($path),
            'sha256' => hash_file('sha256', $path),
            'mtime' => filemtime($path),
        ];
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return $this->metadata + ['items' => $this->items, 'item_count' => count($this->items)];
    }

    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) ?: '{}';
    }

    public function save(string $path): string
    {
        $dir = dirname($path);
        if (!is_dir($dir)) { mkdir($dir, 0775, true); }
        file_put_contents($path, $this->toJson());
        return $path;
    }

    public static function load(string $path): ?self
    {
        if (!is_file($path)) { return null; }
        $data = json_decode((string)file_get_contents($path), true);
        if (!is_array($data)) { return null; }
        $items = is_array($data['items'] ?? null) ? $data['items'] : [];
        unset($data['items']);
        return new self($data, $items);
    }
}
