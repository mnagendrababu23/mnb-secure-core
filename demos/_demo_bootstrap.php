<?php
require_once __DIR__ . '/../autoload.php';

function demo_storage_path(string $name = ''): string
{
    $base = sys_get_temp_dir() . '/mnb_secure_core_v1_0_demos';
    if (!is_dir($base)) {
        mkdir($base, 0777, true);
    }
    $path = $name ? $base . '/' . trim($name, '/') : $base;
    $dir = pathinfo($path, PATHINFO_EXTENSION) ? dirname($path) : $path;
    if (!is_dir($dir)) {
        mkdir($dir, 0777, true);
    }
    return $path;
}

function demo_title(string $title): void
{
    echo "\n" . str_repeat('=', 72) . "\n";
    echo $title . "\n";
    echo str_repeat('=', 72) . "\n";
}

function demo_step(string $label, mixed $value = null): void
{
    echo "- {$label}";
    if ($value !== null) {
        echo ': ';
        if (is_bool($value)) {
            echo $value ? 'YES' : 'NO';
        } elseif (is_array($value) || is_object($value)) {
            echo json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        } else {
            echo (string)$value;
        }
    }
    echo "\n";
}

function demo_result(bool $condition, string $pass, string $fail = 'Failed'): void
{
    echo ($condition ? '[PASS] ' . $pass : '[FAIL] ' . $fail) . "\n";
}
