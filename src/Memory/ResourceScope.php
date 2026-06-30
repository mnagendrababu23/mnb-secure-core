<?php
namespace Mnb\SecurityCore\Memory;

class ResourceScope
{
    private CleanupStack $cleanup;
    private array $temporaryFiles = [];
    private array $handles = [];
    private bool $cleaned = false;
    public function __construct(private string $name)
    {
        $this->cleanup = new CleanupStack();
    }
    public function name(): string { return $this->name; }
    public function trackHandle(mixed $handle): mixed
    {
        if (is_resource($handle)) {
            $this->handles[] = $handle;
            $this->cleanup->push(function () use ($handle): void { if (is_resource($handle)) { @fclose($handle); } });
        }
        return $handle;
    }
    public function trackTemporaryFile(string $path): string
    {
        $this->temporaryFiles[] = $path;
        $this->cleanup->push(function () use ($path): void { if (is_file($path)) { @unlink($path); } });
        return $path;
    }
    public function cleanup(): array
    {
        if ($this->cleaned) { return ['scope' => $this->name, 'cleaned' => true, 'callbacks' => 0, 'idempotent' => true]; }
        $callbacks = $this->cleanup->run();
        $this->cleaned = true;
        return ['scope' => $this->name, 'cleaned' => true, 'callbacks' => $callbacks, 'temporary_files' => count($this->temporaryFiles), 'handles' => count($this->handles)];
    }
    public function __destruct() { $this->cleanup(); }
}
