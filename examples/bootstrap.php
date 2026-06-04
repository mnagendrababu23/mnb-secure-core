<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Env\EnvLoader;

EnvLoader::load(__DIR__ . '/../.env');
$config = require __DIR__ . '/../config/security.php';
return $config;
