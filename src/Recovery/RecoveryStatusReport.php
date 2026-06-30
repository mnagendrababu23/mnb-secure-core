<?php
namespace Mnb\SecurityCore\Recovery;

class RecoveryStatusReport
{
    public function __construct(private string $backupPath, private BackupIntegrityVerifier $verifier, private BackupRetentionPolicy $retention) {}
    /** @return array<string,mixed> */
    public function toArray(): array
    {
        $latest = null;
        if (is_dir($this->backupPath)) {
            foreach (new \DirectoryIterator($this->backupPath) as $file) {
                if ($file->isFile() && preg_match('/\.(zip|enc)$/', $file->getFilename())) {
                    if ($latest === null || $file->getMTime() > $latest['mtime']) { $latest = ['path'=>$file->getPathname(),'mtime'=>$file->getMTime(),'bytes'=>$file->getSize()]; }
                }
            }
        }
        $verify = $latest ? $this->verifier->verify($latest['path']) : ['passed'=>false,'issues'=>[['level'=>'medium','key'=>'no_backups','message'=>'No backup files found.']]];
        return ['passed'=>!empty($verify['passed']),'backup_path'=>$this->backupPath,'latest_backup'=>$latest ? $latest + ['age_seconds'=>time()-$latest['mtime']] : null,'latest_verification'=>$verify,'retention_seconds'=>$this->retention->keepSeconds()];
    }
}
