<?php
namespace Mnb\SecurityCore\Recovery;

class BackupRetentionManager
{
    public function __construct(private BackupRetentionPolicy $policy, private string $backupPath) {}
    /** @return array<string,mixed> */
    public function purge(): array
    {
        $checked = 0; $deleted = 0; $now = time(); $ttl = $this->policy->keepSeconds();
        if (!is_dir($this->backupPath)) { return ['passed'=>true,'checked'=>0,'deleted'=>0,'path'=>$this->backupPath]; }
        foreach (new \DirectoryIterator($this->backupPath) as $file) {
            if (!$file->isFile()) { continue; }
            $name = $file->getFilename();
            if (!preg_match('/\.(zip|enc|json|sig)$/', $name)) { continue; }
            $checked++;
            if ($now - $file->getMTime() > $ttl && @unlink($file->getPathname())) { $deleted++; }
        }
        return ['passed'=>true,'checked'=>$checked,'deleted'=>$deleted,'path'=>$this->backupPath];
    }
}
