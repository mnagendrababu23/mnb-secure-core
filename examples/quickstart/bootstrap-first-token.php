<?php
require __DIR__ . '/../../autoload.php';

use Mnb\SecurityCore\Quickstart\FirstTokenBootstrapper;

$config = require __DIR__ . '/../../config/security.php';

$report = (new FirstTokenBootstrapper($config, dirname(__DIR__, 2)))->issue([
    'user_id' => 'demo-admin',
    'name' => 'Demo Admin',
    'email' => 'demo-admin@example.test',
    'role' => 'admin',
    'scopes' => ['admin:*', 'profile.read', 'uploads.write'],
    'ttl_seconds' => 86400,
    'write_demo_user' => true,
]);

echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
