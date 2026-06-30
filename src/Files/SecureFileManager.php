<?php
namespace Mnb\SecurityCore\Files;

use Mnb\SecurityCore\Contracts\MalwareScannerInterface;
use Mnb\SecurityCore\Contracts\StorageInterface;
use Mnb\SecurityCore\Exceptions\SecurityException;
use Mnb\SecurityCore\Support\Str;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class SecureFileManager
{
    public function __construct(
        private StorageInterface $storage,
        private FileUploadPolicy $policy,
        private string $quarantinePath,
        private MalwareScannerInterface $scanner = new NullMalwareScanner(),
        private ?SecurityAuditTrail $audit = null,
        private ?DocumentInspectorInterface $inspector = null,
        private ?DocumentSanitizerInterface $sanitizer = null
    ) {
        if (!is_dir($quarantinePath)) {
            mkdir($quarantinePath, 0775, true);
        }
    }

    public function storeFromPath(string $sourcePath, string $originalName, string $module = 'documents', array $actor = [], array $context = []): array
    {
        $target = [
            'original_name' => basename(str_replace('\\', '/', $originalName)),
            'module' => $module,
            'profile' => $this->policy->profile,
        ];

        try {
            if (!is_file($sourcePath)) {
                throw new SecurityException('Upload source file does not exist');
            }
            $this->validateName($originalName);
            $size = filesize($sourcePath) ?: 0;
            if ($size <= 0 || $size > $this->policy->maxBytes) {
                throw new SecurityException('Invalid upload size');
            }
            $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
            if (!$this->policy->allowsExtension($extension)) {
                throw new SecurityException('File extension is not allowed');
            }
            $mime = $this->detectMime($sourcePath);
            if (!$this->policy->allowsMime($mime)) {
                throw new SecurityException('File MIME type is not allowed: ' . $mime);
            }
            $this->validateMimeExtensionPair($extension, $mime);
            $this->validateFileContent($sourcePath, $extension, $mime);
            $inspection = $this->inspector?->inspect($sourcePath, $mime, $extension);
            if ($inspection && $inspection->failed()) {
                throw new SecurityException('Document inspection failed: ' . $inspection->message());
            }
            $sanitization = $this->sanitizer?->sanitize($sourcePath, $mime, $extension);
            if ($sanitization && $sanitization->failed()) {
                throw new SecurityException('Document sanitization failed: ' . $sanitization->message());
            }

            $quarantine = rtrim($this->quarantinePath, '/') . '/' . Str::random(12) . '.' . $extension;
            copy($sourcePath, $quarantine);
            if (!$this->scanner->scan($quarantine)) {
                @unlink($quarantine);
                throw new SecurityException('Malware scan failed: ' . $this->scanner->lastMessage());
            }
            $safeName = $this->policy->randomizeNames ? Str::random(16) . '.' . $extension : basename($originalName);
            $storagePath = trim($module, '/') . '/' . date('Y/m') . '/' . $safeName;
            $contents = file_get_contents($quarantine) ?: '';
            $checksum = FileChecksum::contentsSha256($contents);
            $this->storage->put($storagePath, $contents);
            @unlink($quarantine);
            $record = [
                'file_id' => 'file_' . substr($checksum, 0, 16),
                'original_name' => $originalName,
                'storage_path' => $storagePath,
                'mime' => $mime,
                'size' => $size,
                'extension' => $extension,
                'profile' => $this->policy->profile,
                'scan_status' => 'passed',
                'scan_driver' => get_debug_type($this->scanner),
                'scan_message' => $this->scanner->lastMessage(),
                'checksum_sha256' => $checksum,
                'data_class' => (string)($context['data_class'] ?? 'internal'),
                'owner_user_id' => $actor['user_id'] ?? $context['owner_user_id'] ?? null,
                'school_id' => $context['school_id'] ?? null,
                'branch_id' => $context['branch_id'] ?? null,
                'academic_year_id' => $context['academic_year_id'] ?? null,
                'created_at' => gmdate('c'),
            ];
            $this->audit?->uploadAccepted($actor, $target + ['storage_path' => $storagePath], $context, [
                'mime' => $mime,
                'size' => $size,
                'extension' => $extension,
                'randomized_name' => $this->policy->randomizeNames,
            ]);
            return $record;
        } catch (SecurityException $e) {
            $this->audit?->uploadRejected($actor, $target, $context, ['reason' => $e->getMessage()]);
            throw $e;
        }
    }

    public function readForDownload(array $fileRecord): string
    {
        if (empty($fileRecord['storage_path'])) {
            throw new SecurityException('Missing file storage path');
        }
        return $this->storage->read($fileRecord['storage_path']);
    }

    private function validateName(string $name): void
    {
        if (str_contains($name, "\0")) {
            throw new SecurityException('Upload filename contains a null byte');
        }
        $base = basename(str_replace('\\', '/', $name));
        if ($base === '' || $base === '.' || $base === '..') {
            throw new SecurityException('Upload filename is invalid');
        }
        if (strlen($base) > $this->policy->maxOriginalNameLength) {
            throw new SecurityException('Upload filename is too long');
        }

        $parts = array_values(array_filter(array_map('strtolower', explode('.', $base)), fn($part) => $part !== ''));
        if (!$parts) {
            throw new SecurityException('Upload filename has no extension');
        }
        $finalExtension = end($parts);
        if (in_array($finalExtension, $this->policy->blockedExtensions, true)) {
            throw new SecurityException('Executable upload extension is not allowed');
        }
        if ($this->policy->denyDoubleExtensions) {
            array_pop($parts);
            foreach ($parts as $part) {
                if (in_array($part, $this->policy->blockedExtensions, true)) {
                    throw new SecurityException('Double extension is not allowed');
                }
            }
        }
    }


    private function validateMimeExtensionPair(string $extension, string $mime): void
    {
        $map = $this->policy->mimeByExtension ?: [
            'jpg' => ['image/jpeg'],
            'jpeg' => ['image/jpeg'],
            'png' => ['image/png'],
            'gif' => ['image/gif'],
            'webp' => ['image/webp'],
            'pdf' => ['application/pdf'],
            'txt' => ['text/plain'],
            'csv' => ['text/plain', 'text/csv', 'application/csv', 'application/vnd.ms-excel'],
            'json' => ['application/json', 'text/plain'],
            'xml' => ['application/xml', 'text/xml', 'text/plain'],
            'doc' => ['application/msword', 'application/octet-stream'],
            'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
            'xls' => ['application/vnd.ms-excel', 'application/octet-stream'],
            'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
        ];
        if (!isset($map[$extension])) {
            return;
        }
        if (!in_array($mime, $map[$extension], true)) {
            throw new SecurityException('File MIME type does not match extension');
        }
    }

    private function validateFileContent(string $path, string $extension, string $mime): void
    {
        if (!$this->policy->rejectExecutableContent) {
            return;
        }
        $sample = file_get_contents($path, false, null, 0, 2097152) ?: '';
        $textLike = str_starts_with($mime, 'text/') || in_array($extension, ['txt', 'csv', 'json', 'xml'], true);
        if ($textLike && preg_match('/<\?(php|=)?|<\s*script\b|\b(eval|shell_exec|passthru|system|exec|proc_open|popen)\s*\(/i', $sample)) {
            throw new SecurityException('Upload content contains executable code patterns');
        }
        if ($extension === 'pdf' && !str_starts_with($sample, '%PDF-')) {
            throw new SecurityException('PDF signature is invalid');
        }
        if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'], true) && @getimagesize($path) === false) {
            throw new SecurityException('Image signature is invalid');
        }
        if (in_array($extension, ['zip'], true)) {
            $this->validateZipArchive($path);
        }
    }

    private function validateZipArchive(string $path): void
    {
        if (!class_exists('ZipArchive')) {
            if ($this->policy->strictMode) {
                throw new SecurityException('ZIP archive validation requires the zip extension in strict mode');
            }
            return;
        }

        $zip = new \ZipArchive();
        if ($zip->open($path) !== true) {
            throw new SecurityException('ZIP archive could not be opened for validation');
        }

        try {
            if ($zip->numFiles > $this->policy->maxArchiveEntries) {
                throw new SecurityException('ZIP archive contains too many entries');
            }

            $totalUncompressedBytes = 0;
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                if (!is_array($stat)) {
                    throw new SecurityException('ZIP archive entry metadata could not be read');
                }

                $name = (string)($stat['name'] ?? '');
                $normalized = str_replace('\\', '/', $name);
                if ($normalized === '' || str_contains($normalized, '../') || str_starts_with($normalized, '/') || preg_match('/^[A-Za-z]:\\//', $normalized)) {
                    throw new SecurityException('ZIP archive contains an unsafe file path');
                }

                $entryExtension = strtolower(pathinfo($normalized, PATHINFO_EXTENSION));
                if ($entryExtension !== '' && in_array($entryExtension, $this->policy->blockedExtensions, true)) {
                    throw new SecurityException('ZIP archive contains a blocked executable entry');
                }

                $totalUncompressedBytes += (int)($stat['size'] ?? 0);
                if ($totalUncompressedBytes > $this->policy->maxArchiveUncompressedBytes) {
                    throw new SecurityException('ZIP archive uncompressed size is too large');
                }
            }
        } finally {
            $zip->close();
        }
    }

    private function detectMime(string $path): string
    {
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        return $finfo->file($path) ?: 'application/octet-stream';
    }

    private function mimeAllowed(string $mime): bool
    {
        foreach ($this->policy->allowedMimePrefixes as $prefix) {
            if ($mime === $prefix || str_starts_with($mime, rtrim($prefix, '*'))) {
                return true;
            }
        }
        return false;
    }
}
