<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;

$base = sys_get_temp_dir() . '/mnb_demo_recovery';
@mkdir($base . '/source', 0777, true);
file_put_contents($base . '/source/app-config.txt', 'safe demo config');

$config = array_replace_recursive(require __DIR__ . '/../config/security.php', [
    'app' => ['env' => 'testing', 'key' => str_repeat('R', 40)],
    'secrets' => ['definitions' => ['app.key' => ['env' => 'APP_KEY', 'required' => false, 'min_length' => 32, 'purpose' => 'demo']]],
    'paths' => [
        'backups' => $base . '/backups',
        'logs' => $base . '/logs',
        'audit' => $base . '/audit',
        'cache' => $base . '/cache',
    ],
    'audit' => ['enabled' => true, 'file' => $base . '/audit/security-audit.log'],
    'recovery' => [
        'enabled' => true,
        'backups' => [
            'enabled' => true,
            'path' => $base . '/backups',
            'encrypt' => true,
            'sign' => true,
            'key' => str_repeat('B', 40),
            'signing_key' => str_repeat('S', 40),
            'include' => [$base . '/source'],
            'exclude' => [],
            'retention' => ['daily_days' => 7, 'weekly_weeks' => 4, 'monthly_months' => 12],
        ],
        'restore' => ['require_signature' => true, 'require_encryption' => true, 'allow_overwrite' => false],
    ],
    'incident_response' => [
        'enabled' => true,
        'file' => $base . '/logs/incidents.jsonl',
        'playbooks' => [
            'malware_upload_detected' => [
                'severity' => 'critical',
                'actions' => ['record_incident', 'quarantine_file', 'collect_evidence', 'alert_security'],
            ],
        ],
    ],
]);

$kernel = new SecurityKernel($config);
$backup = $kernel->secureBackupManager()->create('demo');
$verify = $kernel->backupIntegrityVerifier()->verify($backup['path']);
$restore = $kernel->restoreManager()->dryRun($backup['path'])->toArray();
$incident = $kernel->incidentResponse()->runPlaybook('malware_upload_detected', ['file_id' => 'demo-file'])->toArray();
$status = $kernel->recoveryStatusReport()->toArray();

echo json_encode([
    'backup_created' => $backup['passed'],
    'backup_encrypted' => $backup['encrypted'],
    'backup_signed' => $backup['signed'],
    'backup_verified' => $verify['passed'],
    'restore_dry_run' => $restore['passed'],
    'incident_id' => $incident['incident']['incident_id'] ?? null,
    'incident_severity' => $incident['incident']['severity'] ?? null,
    'recovery_status_passed' => $status['passed'],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
