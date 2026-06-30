<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;

$baseConfig = require __DIR__ . '/../config/security.php';
$config = array_replace_recursive($baseConfig, [
    'app' => ['env' => 'testing', 'key' => str_repeat('L', 40)],
    'secrets' => ['definitions' => ['app.key' => ['env' => 'APP_KEY', 'required' => false, 'min_length' => 32, 'purpose' => 'demo']]],
    'paths' => [
        'logs' => sys_get_temp_dir() . '/mnb_demo_logging/logs',
        'audit' => sys_get_temp_dir() . '/mnb_demo_logging/audit',
    ],
    'audit' => [
        'enabled' => true,
        'file' => sys_get_temp_dir() . '/mnb_demo_logging/audit/security-audit.log',
        'mirror_to_log' => false,
    ],
]);

$kernel = new SecurityKernel($config);
$kernel->logger('security')->warning('Demo suspicious login password=secret', ['api_key' => 'demo-secret-key', 'ip' => '127.0.0.1']);
$kernel->auditTrail()->record(SecurityAuditEvent::login(SecurityAuditEvent::OUTCOME_FAILURE, ['user_id' => 10], ['ip' => '127.0.0.1']));
$kernel->metricsRegistry()->increment('auth_failures_total', ['source' => 'demo']);
$alerts = $kernel->alertManager()->recordEvent('auth.login.failure', ['user_id' => 10, 'ip' => '127.0.0.1']);

$summary = $kernel->monitoringSummary()->toArray();
echo json_encode([
    'logger' => 'security log written with redaction',
    'audit_integrity' => $kernel->auditIntegrityVerifier()->verify(),
    'alerts_created' => count($alerts),
    'summary_passed' => $summary['passed'],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
