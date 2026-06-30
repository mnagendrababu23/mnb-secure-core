<?php
namespace Mnb\SecurityCore\Logging;

class FileLogHandler implements LogHandlerInterface
{
    public function __construct(private string $file, private ?LogDataProtector $protector = null)
    {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }
        if (!is_file($file)) {
            file_put_contents($file, '');
        }
    }

    public function handle(LogRecord $record): void
    {
        $data = $this->protector ? $this->protector->protectRecord($record) : $record->toArray();
        file_put_contents($this->file, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    public function file(): string { return $this->file; }
}
