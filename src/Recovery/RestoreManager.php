<?php
namespace Mnb\SecurityCore\Recovery;

use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class RestoreManager
{
    public function __construct(private BackupIntegrityVerifier $verifier, private SecureBackupManager $backups, private array $config = [], private ?SecurityAuditTrail $audit = null) {}
    public function dryRun(string $backupPath, ?string $targetPath = null): RestoreResult
    {
        $targetPath ??= sys_get_temp_dir() . '/mnb_restore_dry_run_' . substr(hash('sha256', $backupPath), 0, 10);
        $plan = new RestorePlan($backupPath, $targetPath, true, ['verify_only'=>true]);
        $verify = $this->verifier->verify($backupPath);
        $issues = is_array($verify['issues'] ?? null) ? $verify['issues'] : [];
        $passed = !empty($verify['passed']);
        $this->audit?->record(SecurityAuditEvent::make('recovery', 'restore.dry_run', $passed ? SecurityAuditEvent::OUTCOME_SUCCESS : SecurityAuditEvent::OUTCOME_FAILURE, $passed ? SecurityAuditEvent::SEVERITY_NOTICE : SecurityAuditEvent::SEVERITY_WARNING, [], ['backup' => basename($backupPath)], [], ['issues' => count($issues)]));
        return new RestoreResult($passed, $plan, $issues, ['verification'=>$verify]);
    }
}
