<?php
namespace Mnb\SecurityCore\Files;

class FileRetentionManager
{
    public function __construct(private int $quarantineTtlHours = 24, private int $rejectedTtlDays = 7, private int $temporaryExportsTtlHours = 24) {}

    /** @return array{deleted:int,checked:int} */
    public function purgeDirectory(string $path, int $ttlSeconds): array
    {
        $checked = 0; $deleted = 0;
        if (!is_dir($path)) { return ['deleted' => 0, 'checked' => 0]; }
        $now = time();
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $file) {
            if (!$file instanceof \SplFileInfo || !$file->isFile()) { continue; }
            $checked++;
            if ($now - $file->getMTime() > $ttlSeconds && @unlink($file->getPathname())) { $deleted++; }
        }
        return ['deleted' => $deleted, 'checked' => $checked];
    }

    /** @return array{deleted:int,checked:int} */ public function purgeQuarantine(string $path): array { return $this->purgeDirectory($path, $this->quarantineTtlHours * 3600); }
    /** @return array{deleted:int,checked:int} */ public function purgeRejected(string $path): array { return $this->purgeDirectory($path, $this->rejectedTtlDays * 86400); }
    /** @return array{deleted:int,checked:int} */ public function purgeTemporaryExports(string $path): array { return $this->purgeDirectory($path, $this->temporaryExportsTtlHours * 3600); }
}
