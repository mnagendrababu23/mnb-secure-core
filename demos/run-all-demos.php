<?php
$demoDir = __DIR__;
$files = glob($demoDir . '/[0-9][0-9]-*.php') ?: [];
sort($files);
$php = PHP_BINARY;
$failed = 0;

echo "MNB Secure Core v1.0 - Running all demos\n";
echo str_repeat('=', 72) . "\n";

foreach ($files as $file) {
    $cmd = escapeshellarg($php) . ' ' . escapeshellarg($file) . ' 2>&1';
    echo "\n>>> " . basename($file) . "\n";
    $output = [];
    $code = 0;
    exec($cmd, $output, $code);
    echo implode("\n", $output) . "\n";
    if ($code !== 0 || str_contains(implode("\n", $output), '[FAIL]')) {
        $failed++;
    }
}

echo "\n" . str_repeat('=', 72) . "\n";
echo $failed === 0 ? "All demos passed.\n" : "{$failed} demo(s) failed.\n";
exit($failed === 0 ? 0 : 1);
