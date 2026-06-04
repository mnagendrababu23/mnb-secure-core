<?php
// Update this path after copying the template into your application.
require_once __DIR__ . '/../../autoload.php';

use Mnb\SecurityCore\Env\EnvLoader;
use Mnb\SecurityCore\Core\SecurityKernel;

$root = dirname(__DIR__);
EnvLoader::load($root . '/.env');
$config = require $root . '/config/security.php';

return [
    'config' => $config,
    'security' => new SecurityKernel($config),
];
