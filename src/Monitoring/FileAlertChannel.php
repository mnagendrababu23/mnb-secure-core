<?php
namespace Mnb\SecurityCore\Monitoring;

class FileAlertChannel implements AlertChannelInterface
{
    public function __construct(private string $file)
    {
        $dir = dirname($file);
        if (!is_dir($dir)) { mkdir($dir, 0775, true); }
        if (!is_file($file)) { file_put_contents($file, ''); }
    }

    public function send(array $alert): void
    {
        file_put_contents($this->file, json_encode($alert, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND | LOCK_EX);
    }
}
