<?php
$config = require __DIR__ . '/bootstrap.php';

use Mnb\SecurityCore\Core\SecurityKernel;

$kernel = new SecurityKernel($config);
$files = $kernel->secureFileManager();

// Example for tests/local scripts. In real app, pass uploaded tmp_name and original name after user permission check.
$result = $files->storeFromPath(__DIR__ . '/sample.txt', 'sample.txt', 'homework');
print_r($result);
