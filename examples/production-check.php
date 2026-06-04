<?php
$config = require __DIR__ . '/bootstrap.php';

use Mnb\SecurityCore\Security\ProductionSecurityChecker;

print_r((new ProductionSecurityChecker($config, dirname(__DIR__)))->check());
