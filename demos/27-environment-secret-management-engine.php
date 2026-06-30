<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Env\ArraySecretProvider;
use Mnb\SecurityCore\Env\SecretManager;
use Mnb\SecurityCore\Env\SecretRedactor;

$config = require __DIR__ . '/../config/security.php';
$config['app']['env'] = 'testing';
$config['app']['key'] = str_repeat('A', 40);

$provider = new ArraySecretProvider([
    'APP_KEY' => str_repeat('A', 40),
    'WEBHOOK_SECRET' => str_repeat('W', 40),
]);

$manager = SecretManager::fromConfig($config, $provider);
$kernel = new SecurityKernel($config);

echo "Secret inventory\n";
echo json_encode($manager->inventory()->report()->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n\n";

echo "Derived data key length: " . strlen((string)$manager->get('data.key')) . "\n";
echo "Purpose key sample length: " . strlen($manager->derive('demo.purpose')) . "\n";

$redactor = new SecretRedactor('[redacted]', 4);
print_r($redactor->redactArray([
    'api_key' => 'abcdefghijklmnopqrstuvwxyz',
    'public' => 'visible',
]));

echo "Kernel environment check\n";
echo json_encode($kernel->environmentValidator()->validate(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
