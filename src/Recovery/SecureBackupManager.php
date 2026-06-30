<?php
namespace Mnb\SecurityCore\Recovery;

use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class SecureBackupManager
{
    public function __construct(private BackupPolicy $policy, private BackupSigner $signer, private ?SecurityAuditTrail $audit = null) {
        if (!is_dir($policy->path())) { mkdir($policy->path(), 0775, true); }
    }

    /** @return array<string,mixed> */
    public function create(string $type = 'manual', array $overrideSources = []): array
    {
        if (!$this->policy->enabled()) { throw new \RuntimeException('Secure backups are disabled.'); }
        $sources = $overrideSources !== [] ? array_values(array_map('strval', $overrideSources)) : $this->policy->include();
        if ($sources === []) { $sources = [dirname(__DIR__, 2) . '/config']; }
        $backupId = 'backup_' . date('Ymd_His') . '_' . substr(bin2hex(random_bytes(6)), 0, 12);
        $base = rtrim($this->policy->path(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $backupId;
        $archive = $this->createArchive($sources, $base . '.zip');
        $encrypted = false;
        if ($this->policy->encrypt()) {
            $encryptedPath = $archive . '.enc';
            $this->encryptFile($archive, $encryptedPath);
            @unlink($archive);
            $archive = $encryptedPath;
            $encrypted = true;
        }
        $manifest = BackupManifest::create($backupId, $type, $sources, $archive, $encrypted, $this->policy->sign());
        $manifestPath = $archive . '.manifest.json';
        $manifest->save($manifestPath);
        $signaturePath = null;
        if ($this->policy->sign()) {
            $signaturePath = $archive . '.sig';
            $payload = (string)file_get_contents($archive) . "\n" . (string)file_get_contents($manifestPath);
            file_put_contents($signaturePath, $this->signer->sign($payload));
        }
        $result = [
            'passed' => true,
            'backup_id' => $backupId,
            'type' => $type,
            'path' => $archive,
            'manifest' => $manifestPath,
            'signature' => $signaturePath,
            'encrypted' => $encrypted,
            'signed' => $signaturePath !== null,
            'bytes' => filesize($archive),
            'sha256' => hash_file('sha256', $archive),
        ];
        $this->audit?->record(SecurityAuditEvent::make('recovery', 'backup.created', SecurityAuditEvent::OUTCOME_SUCCESS, SecurityAuditEvent::SEVERITY_NOTICE, [], ['backup_id' => $backupId], [], ['encrypted' => $encrypted, 'signed' => $signaturePath !== null]));
        return $result;
    }

    /** @param list<string> $sources */
    private function createArchive(array $sources, string $target): string
    {
        if (class_exists(\ZipArchive::class)) {
            $zip = new \ZipArchive();
            if ($zip->open($target, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) { throw new \RuntimeException('Cannot create secure backup archive.'); }
            foreach ($sources as $source) { $this->addToZip($zip, $source); }
            $zip->close();
            return $target;
        }
        $payload = ['created_at' => date('c'), 'sources' => []];
        foreach ($sources as $source) {
            if (is_file($source)) { $payload['sources'][] = ['path' => basename($source), 'body' => base64_encode((string)file_get_contents($source))]; }
        }
        file_put_contents($target, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        return $target;
    }

    private function addToZip(\ZipArchive $zip, string $source): void
    {
        if (!file_exists($source) || $this->isExcluded($source)) { return; }
        if (is_file($source)) { $zip->addFile($source, basename($source)); return; }
        $base = rtrim($source, DIRECTORY_SEPARATOR);
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($base, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            if (!$file instanceof \SplFileInfo || !$file->isFile()) { continue; }
            $path = $file->getPathname();
            if ($this->isExcluded($path)) { continue; }
            $zip->addFile($path, basename($base) . '/' . substr($path, strlen($base) + 1));
        }
    }

    private function isExcluded(string $path): bool
    {
        foreach ($this->policy->exclude() as $exclude) {
            if ($exclude !== '' && str_starts_with($path, $exclude)) { return true; }
        }
        return false;
    }

    private function encryptFile(string $source, string $target): void
    {
        $plain = (string)file_get_contents($source);
        $iv = random_bytes(12); $tag = '';
        $key = hash('sha256', $this->policy->key() !== '' ? $this->policy->key() : 'mnb-secure-core-backup-key', true);
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, 'mnb-secure-core-backup');
        if ($cipher === false) { throw new \RuntimeException('Backup encryption failed.'); }
        file_put_contents($target, json_encode(['v'=>1,'alg'=>'AES-256-GCM','iv'=>base64_encode($iv),'tag'=>base64_encode($tag),'ct'=>base64_encode($cipher)], JSON_UNESCAPED_SLASHES));
    }

    public function decryptToTemp(string $encryptedPath): string
    {
        $data = json_decode((string)file_get_contents($encryptedPath), true);
        if (!is_array($data) || empty($data['ct'])) { return $encryptedPath; }
        $key = hash('sha256', $this->policy->key() !== '' ? $this->policy->key() : 'mnb-secure-core-backup-key', true);
        $plain = openssl_decrypt(base64_decode((string)$data['ct']), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, base64_decode((string)$data['iv']), base64_decode((string)$data['tag']), 'mnb-secure-core-backup');
        if ($plain === false) { throw new \RuntimeException('Backup decryption failed.'); }
        $tmp = tempnam(sys_get_temp_dir(), 'mnb_restore_') . '.zip';
        file_put_contents($tmp, $plain);
        return $tmp;
    }
}
