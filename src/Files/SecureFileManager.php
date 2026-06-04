<?php
namespace Mnb\SecurityCore\Files;

use Mnb\SecurityCore\Contracts\MalwareScannerInterface;
use Mnb\SecurityCore\Contracts\StorageInterface;
use Mnb\SecurityCore\Exceptions\SecurityException;
use Mnb\SecurityCore\Support\Str;

class SecureFileManager
{
    public function __construct(
        private StorageInterface $storage,
        private FileUploadPolicy $policy,
        private string $quarantinePath,
        private MalwareScannerInterface $scanner = new NullMalwareScanner()
    ) {
        if (!is_dir($quarantinePath)) {
            mkdir($quarantinePath, 0775, true);
        }
    }

    public function storeFromPath(string $sourcePath, string $originalName, string $module = 'documents'): array
    {
        if (!is_file($sourcePath)) {
            throw new SecurityException('Upload source file does not exist');
        }
        $this->validateName($originalName);
        $size = filesize($sourcePath) ?: 0;
        if ($size <= 0 || $size > $this->policy->maxBytes) {
            throw new SecurityException('Invalid upload size');
        }
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        if (!in_array($extension, $this->policy->allowedExtensions, true)) {
            throw new SecurityException('File extension is not allowed');
        }
        $mime = $this->detectMime($sourcePath);
        if (!$this->mimeAllowed($mime)) {
            throw new SecurityException('File MIME type is not allowed: ' . $mime);
        }

        $quarantine = rtrim($this->quarantinePath, '/') . '/' . Str::random(12) . '.' . $extension;
        copy($sourcePath, $quarantine);
        if (!$this->scanner->scan($quarantine)) {
            @unlink($quarantine);
            throw new SecurityException('Malware scan failed: ' . $this->scanner->lastMessage());
        }
        $safeName = $this->policy->randomizeNames ? Str::random(16) . '.' . $extension : basename($originalName);
        $storagePath = trim($module, '/') . '/' . date('Y/m') . '/' . $safeName;
        $this->storage->put($storagePath, file_get_contents($quarantine));
        @unlink($quarantine);
        return [
            'original_name' => $originalName,
            'storage_path' => $storagePath,
            'mime' => $mime,
            'size' => $size,
            'extension' => $extension,
        ];
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
        $base = basename($name);
        if ($this->policy->denyDoubleExtensions) {
            $dangerous = ['php', 'phtml', 'phar', 'cgi', 'pl', 'sh', 'exe', 'js', 'html'];
            $parts = array_map('strtolower', explode('.', $base));
            array_pop($parts);
            foreach ($parts as $part) {
                if (in_array($part, $dangerous, true)) {
                    throw new SecurityException('Double extension is not allowed');
                }
            }
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
