<?php
namespace Mnb\SecurityCore\Files;

class ArchiveInspector implements DocumentInspectorInterface
{
    /** @param list<string> $blockedExtensions */
    public function __construct(
        private int $maxEntries = 500,
        private int $maxUncompressedBytes = 104857600,
        private array $blockedExtensions = ['php','phtml','phar','cgi','pl','sh','exe','com','bat','cmd','js','html','htm','svg']
    ) {}

    public function inspect(string $path, string $mime, string $extension): DocumentInspectionResult
    {
        $extension = strtolower($extension);
        if ($extension !== 'zip') {
            if (in_array($extension, ['tar', 'gz', 'tgz'], true)) {
                return DocumentInspectionResult::fail(['unsupported_archive_deep_inspection'], 'Only ZIP archives are deeply inspected by the built-in inspector.');
            }
            return DocumentInspectionResult::pass('not an archive handled by this inspector');
        }
        if (!class_exists('ZipArchive')) {
            return DocumentInspectionResult::fail(['zip_extension_missing'], 'ZIP archive inspection requires the zip extension.');
        }
        $zip = new \ZipArchive();
        if ($zip->open($path) !== true) {
            return DocumentInspectionResult::fail(['zip_open_failed'], 'ZIP archive could not be opened.');
        }
        $findings = [];
        $total = 0;
        try {
            if ($zip->numFiles > $this->maxEntries) {
                $findings[] = 'too_many_entries';
            }
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                if (!is_array($stat)) { $findings[] = 'unreadable_entry_metadata'; continue; }
                $name = str_replace('\\', '/', (string)($stat['name'] ?? ''));
                if ($name === '' || str_contains($name, '../') || str_starts_with($name, '/') || preg_match('/^[A-Za-z]:\//', $name)) {
                    $findings[] = 'unsafe_entry_path';
                }
                $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
                if ($ext !== '' && in_array($ext, $this->blockedExtensions, true)) {
                    $findings[] = 'blocked_entry_extension:' . $ext;
                }
                $total += (int)($stat['size'] ?? 0);
                if ($total > $this->maxUncompressedBytes) {
                    $findings[] = 'uncompressed_size_limit_exceeded';
                    break;
                }
            }
        } finally {
            $zip->close();
        }
        return $findings === [] ? DocumentInspectionResult::pass('archive inspection passed') : DocumentInspectionResult::fail(array_values(array_unique($findings)));
    }
}
