<?php
namespace Mnb\SecurityCore\Recovery;

class BackupIntegrityVerifier
{
    public function __construct(private BackupSigner $signer, private bool $requireSignature = false) {}

    /** @return array<string,mixed> */
    public function verify(string $backupPath, ?string $manifestPath = null, ?string $signaturePath = null): array
    {
        $manifestPath ??= $backupPath . '.manifest.json';
        $signaturePath ??= $backupPath . '.sig';
        $issues = [];
        if (!is_file($backupPath)) {
            return ['passed' => false, 'backup' => $backupPath, 'issues' => [['level' => 'critical', 'key' => 'backup_missing', 'message' => 'Backup file does not exist.']]];
        }
        $manifest = BackupManifest::load($manifestPath);
        if (!$manifest) {
            $issues[] = ['level' => 'high', 'key' => 'manifest_missing', 'message' => 'Backup manifest is missing or invalid.'];
        } else {
            $data = $manifest->toArray();
            $expected = (string)($data['archive_sha256'] ?? '');
            $actual = hash_file('sha256', $backupPath);
            if ($expected !== '' && !hash_equals($expected, $actual)) {
                $issues[] = ['level' => 'critical', 'key' => 'backup_checksum_mismatch', 'message' => 'Backup archive checksum does not match manifest.'];
            }
        }
        if (is_file($signaturePath)) {
            $payload = (string)file_get_contents($backupPath) . "\n" . (is_file($manifestPath) ? (string)file_get_contents($manifestPath) : '');
            $signature = trim((string)file_get_contents($signaturePath));
            if (!$this->signer->verify($payload, $signature)) {
                $issues[] = ['level' => 'critical', 'key' => 'backup_signature_invalid', 'message' => 'Backup signature is invalid.'];
            }
        } elseif ($this->requireSignature) {
            $issues[] = ['level' => 'high', 'key' => 'backup_signature_missing', 'message' => 'Backup signature is required but missing.'];
        }
        return [
            'passed' => count(array_filter($issues, fn(array $i): bool => in_array($i['level'], ['critical','high'], true))) === 0,
            'backup' => $backupPath,
            'manifest' => $manifestPath,
            'signature' => $signaturePath,
            'bytes' => filesize($backupPath),
            'sha256' => hash_file('sha256', $backupPath),
            'issues' => $issues,
        ];
    }
}
