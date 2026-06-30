<?php
namespace Mnb\SecurityCore\Memory;

use RuntimeException;

class TemporaryFileManager
{
    public function __construct(private string $directory, private TemporaryFileBudget $budget)
    {
        if (!is_dir($this->directory)) { mkdir($this->directory, 0777, true); }
    }
    public static function fromConfig(array $config): self
    {
        $memory = is_array($config['memory'] ?? null) ? $config['memory'] : [];
        $paths = is_array($config['paths'] ?? null) ? $config['paths'] : [];
        $dir = (string)($paths['cache'] ?? sys_get_temp_dir()) . '/mnb-temp';
        return new self($dir, TemporaryFileBudget::fromArray(is_array($memory['temporary_files'] ?? null) ? $memory['temporary_files'] : []));
    }
    public function create(string $prefix = 'tmp_', string $content = ''): string
    {
        $this->assertWithinBudget(strlen($content), 1);
        $path = tempnam($this->directory, preg_replace('/[^A-Za-z0-9_\-]/', '_', $prefix));
        if ($path === false) { throw new RuntimeException('Unable to create temporary file.'); }
        file_put_contents($path, $content);
        return $path;
    }
    public function usage(): array
    {
        $files = 0; $bytes = 0; $old = 0; $now = time();
        foreach (glob(rtrim($this->directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
            if (is_file($file)) { $files++; $bytes += filesize($file) ?: 0; if ($now - (filemtime($file) ?: $now) > $this->budget->maxAgeSeconds()) { $old++; } }
        }
        return ['directory' => $this->directory, 'files' => $files, 'bytes' => $bytes, 'old_files' => $old, 'budget' => $this->budget->toArray(), 'passed' => $files <= $this->budget->maxFiles() && $bytes <= $this->budget->maxTotalBytes()];
    }
    public function assertWithinBudget(int $additionalBytes = 0, int $additionalFiles = 0): void
    {
        $usage = $this->usage();
        if ($usage['files'] + $additionalFiles > $this->budget->maxFiles() || $usage['bytes'] + $additionalBytes > $this->budget->maxTotalBytes()) { throw new RuntimeException('Temporary file budget exceeded.'); }
    }
    public function cleanupOld(bool $dryRun = true): array
    {
        $now = time(); $candidates = [];
        foreach (glob(rtrim($this->directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
            if (is_file($file) && $now - (filemtime($file) ?: $now) > $this->budget->maxAgeSeconds()) {
                $candidates[] = ['path' => $file, 'bytes' => filesize($file) ?: 0];
                if (!$dryRun) { @unlink($file); }
            }
        }
        return ['passed' => true, 'dry_run' => $dryRun, 'candidates' => $candidates, 'count' => count($candidates)];
    }
}
