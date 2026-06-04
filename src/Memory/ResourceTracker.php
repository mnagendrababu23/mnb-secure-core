<?php
namespace Mnb\SecurityCore\Memory;

class ResourceTracker
{
    /** @var resource[] */
    private array $handles = [];
    private array $temporaryFiles = [];

    public function trackHandle(mixed $handle): mixed
    {
        if (is_resource($handle)) {
            $this->handles[] = $handle;
        }
        return $handle;
    }

    public function trackTemporaryFile(string $path): string
    {
        $this->temporaryFiles[] = $path;
        return $path;
    }

    public function cleanup(): void
    {
        foreach ($this->handles as $handle) {
            if (is_resource($handle)) {
                @fclose($handle);
            }
        }
        $this->handles = [];

        foreach ($this->temporaryFiles as $file) {
            if (is_file($file)) {
                @unlink($file);
            }
        }
        $this->temporaryFiles = [];
    }

    public function count(): array
    {
        return [
            'handles' => count($this->handles),
            'temporary_files' => count($this->temporaryFiles),
        ];
    }

    public function __destruct()
    {
        $this->cleanup();
    }
}
