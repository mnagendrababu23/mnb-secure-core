<?php
/**
 * Application/CI doctor workflow example for mnb-secure-core v1.0.1.
 *
 * CLI equivalent:
 *
 *   php bin/mnb-secure doctor
 */

require __DIR__ . '/../../autoload.php';

use Mnb\SecurityCore\Env\EnvLoader;
use Mnb\SecurityCore\Security\SecurityDoctor;

EnvLoader::load(__DIR__ . '/../../.env');
$config = require __DIR__ . '/../../config/security.php';

$doctor = new SecurityDoctor($config, dirname(__DIR__, 2));
$report = $doctor->check();

header('Content-Type: application/json; charset=UTF-8');
echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;

// Useful for CI: fail only when blocking issues are present.
exit($report['passed'] ? 0 : 1);
