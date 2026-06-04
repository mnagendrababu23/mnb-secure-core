<?php
namespace Mnb\SecurityCore\Recovery;

class BackupManager
{
    public function __construct(private string $backupPath)
    {
        if (!is_dir($backupPath)) {
            mkdir($backupPath, 0775, true);
        }
    }

    public function createArchive(string $sourcePath, string $name): string
    {
        if (!file_exists($sourcePath)) {
            throw new \RuntimeException('Backup source path does not exist');
        }

        $safeName = preg_replace('/[^a-zA-Z0-9_.-]+/', '-', $name) . '-' . date('Ymd-His');

        if (class_exists(\ZipArchive::class)) {
            return $this->createZipArchive($sourcePath, $safeName);
        }

        if (class_exists(\PharData::class)) {
            return $this->createTarArchive($sourcePath, $safeName);
        }

        throw new \RuntimeException('No archive engine available. Enable ext-zip or PharData.');
    }

    public function verifyArchive(string $archivePath): bool
    {
        if (!is_file($archivePath)) {
            return false;
        }

        if (str_ends_with(strtolower($archivePath), '.zip') && class_exists(\ZipArchive::class)) {
            $zip = new \ZipArchive();
            $result = $zip->open($archivePath, \ZipArchive::CHECKCONS);
            if ($result === true) {
                $zip->close();
                return true;
            }
            return false;
        }

        if (str_ends_with(strtolower($archivePath), '.tar') && class_exists(\PharData::class)) {
            try {
                $phar = new \PharData($archivePath);
                foreach (new \RecursiveIteratorIterator($phar) as $_) {
                    // Iteration forces PharData to read the archive index.
                }
                return true;
            } catch (\Throwable) {
                return false;
            }
        }

        return filesize($archivePath) > 0;
    }

    private function createZipArchive(string $sourcePath, string $safeName): string
    {
        $target = rtrim($this->backupPath, '/') . '/' . $safeName . '.zip';
        $zip = new \ZipArchive();
        if ($zip->open($target, \ZipArchive::CREATE) !== true) {
            throw new \RuntimeException('Cannot create backup archive');
        }
        $this->addToZip($zip, $sourcePath);
        $zip->close();
        return $target;
    }

    private function createTarArchive(string $sourcePath, string $safeName): string
    {
        $target = rtrim($this->backupPath, '/') . '/' . $safeName . '.tar';
        @unlink($target);
        $tar = new \PharData($target);
        if (is_file($sourcePath)) {
            $tar->addFile($sourcePath, basename($sourcePath));
        } else {
            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($sourcePath, \FilesystemIterator::SKIP_DOTS));
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $localName = substr($file->getPathname(), strlen($sourcePath) + 1);
                    $tar->addFile($file->getPathname(), $localName);
                }
            }
        }
        return $target;
    }

    private function addToZip(\ZipArchive $zip, string $sourcePath): void
    {
        if (is_file($sourcePath)) {
            $zip->addFile($sourcePath, basename($sourcePath));
            return;
        }

        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($sourcePath, \FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $zip->addFile($file->getPathname(), substr($file->getPathname(), strlen($sourcePath) + 1));
            }
        }
    }
}
