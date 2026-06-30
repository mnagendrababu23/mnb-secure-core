<?php
namespace Mnb\SecurityCore\Memory;

use RuntimeException;

class SafeStreamWriter
{
    public function __construct(private StreamGuard $guard) {}

    public function writeChunks(string $path, iterable $chunks, ?int $maxBytes = null): array
    {
        $budget = $this->guard->budget();
        $limit = $maxBytes !== null ? max(1, $maxBytes) : $budget->maxWriteBytes();
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        $handle = fopen($path, 'wb');
        if (!is_resource($handle)) {
            throw new RuntimeException('Unable to open stream destination.');
        }
        $written = 0;
        $count = 0;
        try {
            foreach ($chunks as $chunk) {
                $chunk = (string)$chunk;
                $next = $written + strlen($chunk);
                if ($next > $limit) {
                    throw new RuntimeException('Stream write budget exceeded.');
                }
                $this->guard->assertCanWrite(0, $next);
                fwrite($handle, $chunk);
                $written = $next;
                $count++;
            }
        } finally {
            fclose($handle);
        }
        return ['path' => $path, 'bytes_written' => $written, 'chunks' => $count, 'limit_bytes' => $limit];
    }
}
