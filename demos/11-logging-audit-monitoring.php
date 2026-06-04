<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Logging\FileLogger;
use Mnb\SecurityCore\Logging\SecurityMonitor;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;

demo_title('11. Logging, Audit, and Monitoring');

$logFile = demo_storage_path('logs/app.log');
$auditFile = demo_storage_path('audit/audit.log');
@unlink($logFile);
@unlink($auditFile);

$logger = new FileLogger($logFile);
$monitor = new SecurityMonitor($logger);
$monitor->suspicious('multiple_failed_logins', ['user_id' => 12, 'token' => 'secret-token-should-redact']);
$monitor->incident('fee_edit_after_lock', ['admin_id' => 1, 'secret' => 'should-redact']);

$audit = new TamperEvidentAuditLogger($auditFile);
$audit->record('fee.receipt.created', ['user_id' => 1, 'role' => 'accountant'], ['receipt_id' => 501], ['amount' => 2500, 'token' => 'redacted']);
$audit->record('marks.updated', ['user_id' => 2, 'role' => 'teacher'], ['student_id' => 301], ['subject' => 'Math']);

$logContent = file_get_contents($logFile);
$verified = $audit->verify();

demo_step('Application log sample', array_slice(file($logFile, FILE_IGNORE_NEW_LINES), 0, 2));
demo_step('Audit chain verifies', $verified);
demo_step('Secrets redacted in logs', str_contains($logContent, '[redacted]'));
demo_result($verified && str_contains($logContent, '[redacted]'), 'Security monitor logs are redacted and audit logs are tamper-evident.');
