<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Data\DataProtectionRegistry;
use Mnb\SecurityCore\Data\ExportPolicy;
use Mnb\SecurityCore\Data\KeyRing;
use Mnb\SecurityCore\Data\SafeCsvExporter;
use Mnb\SecurityCore\Files\EncryptedStorage;
use Mnb\SecurityCore\Files\LocalPrivateStorage;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;

function demo23_pass(bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException('[FAIL] ' . $message);
    }
    echo "[PASS] {$message}\n";
}

echo "\n" . str_repeat('=', 72) . "\n";
echo "23. Data Protection Strategy Engine\n";
echo str_repeat('=', 72) . "\n";

$base = sys_get_temp_dir() . '/mnb_secure_core_v1_0_1_demos/data-protection-engine';
@mkdir($base, 0777, true);

$config = [
    'app' => ['env' => 'local', 'key' => str_repeat('D', 40)],
    'data_protection' => [
        'enabled' => true,
        'default_class' => 'internal',
        'audit' => true,
        'encryption' => [
            'enabled' => true,
            'current_key_id' => 'demo-v1',
            'keys' => ['demo-v1' => str_repeat('K', 40)],
            'aad' => true,
        ],
        'search_hash' => [
            'enabled' => true,
            'key' => str_repeat('H', 40),
            'prefix' => 'mnb:demo',
        ],
        'resources' => [
            'students' => [
                'default_class' => 'sensitive',
                'tenant_scoped' => true,
                'fields' => [
                    'id' => ['class' => 'internal'],
                    'name' => ['class' => 'internal'],
                    'email' => ['class' => 'confidential', 'encrypt' => true, 'search_hash' => true, 'mask' => 'email', 'export' => 'masked', 'log' => false],
                    'parent_phone' => ['class' => 'sensitive', 'encrypt' => true, 'search_hash' => true, 'mask' => 'last4', 'export' => 'masked', 'log' => false],
                    'password_hash' => ['class' => 'highly_sensitive', 'read' => false, 'write' => false, 'export' => false, 'log' => false],
                ],
            ],
        ],
        'exports' => ['csv_injection_protection' => true, 'max_rows' => 100, 'audit' => true],
    ],
];

$audit = new SecurityAuditTrail(new TamperEvidentAuditLogger($base . '/audit.log'));
$registry = DataProtectionRegistry::fromConfig($config, $audit);

$student = [
    'id' => 44,
    'name' => '=Ravi Kumar',
    'email' => 'ravi@example.com',
    'parent_phone' => '9876543210',
    'password_hash' => 'hash',
];

$stored = $registry->protectForStorage('students', $student);
$response = $registry->protectForResponse('students', $stored);
$logSafe = $registry->protectForLog('students', $stored);
$csv = (new SafeCsvExporter($registry, new ExportPolicy(['csv_injection_protection' => true])))->export('students', [$student]);

$storage = new EncryptedStorage(new LocalPrivateStorage($base . '/private'), new KeyRing('demo-v1', ['demo-v1' => str_repeat('S', 40)]));
$storage->put('exports/students.txt', 'private export body');
$raw = file_get_contents($storage->absolutePath('exports/students.txt')) ?: '';

echo '- Stored protected record: ' . json_encode($stored, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
echo '- Safe response: ' . json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
echo '- Safe log record: ' . json_encode($logSafe, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
echo '- CSV sample: ' . trim($csv) . "\n";

demo23_pass(str_starts_with((string)$stored['email'], KeyRing::PREFIX) && isset($stored['email_hash']), 'field encryption and search hash are applied before storage');
demo23_pass(isset($response['email']) && $response['email'] !== 'ravi@example.com' && !isset($response['password_hash']), 'responses are masked and highly sensitive fields are removed');
demo23_pass(($logSafe['email'] ?? null) === '[redacted]' && !str_contains(json_encode($logSafe), '9876543210'), 'logs are redacted before writing sensitive data');
demo23_pass(str_contains($csv, "'=Ravi") && !str_contains($csv, '9876543210') && !str_contains($csv, 'password_hash'), 'CSV export masks sensitive fields and blocks formula injection');
demo23_pass($storage->read('exports/students.txt') === 'private export body' && !str_contains($raw, 'private export body'), 'encrypted private storage protects file contents at rest');

echo "Data Protection Strategy Engine demo passed\n";
