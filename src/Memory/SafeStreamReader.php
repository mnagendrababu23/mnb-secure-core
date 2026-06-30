<?php
namespace Mnb\SecurityCore\Memory;

use RuntimeException;

class SafeStreamReader
{
    public function __construct(private StreamGuard $guard) {}

    public function chunks(string $path, ?int $maxBytes = null, ?int $bufferSize = null): iterable
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new RuntimeException('Readable stream source not found.');
        }
        $budget = $this->guard->budget();
        $limit = $maxBytes !== null ? max(1, $maxBytes) : $budget->maxReadBytes();
        $buffer = $bufferSize !== null ? max(1, $bufferSize) : $budget->bufferSize();
        $handle = fopen($path, 'rb');
        if (!is_resource($handle)) {
            throw new RuntimeException('Unable to open stream source.');
        }
        $read = 0;
        try {
            while (!feof($handle)) {
                $remaining = $limit - $read;
                if ($remaining <= 0) {
                    throw new RuntimeException('Stream read budget exceeded.');
                }
                $chunk = fread($handle, min($buffer, $remaining));
                if ($chunk === false) {
                    throw new RuntimeException('Unable to read stream chunk.');
                }
                if ($chunk === '') {
                    break;
                }
                $read += strlen($chunk);
                $this->guard->assertCanRead(0, $read);
                yield $chunk;
            }
        } finally {
            fclose($handle);
        }
    }

    public function read(string $path, ?int $maxBytes = null): string
    {
        $data = '';
        foreach ($this->chunks($path, $maxBytes) as $chunk) {
            $data .= $chunk;
        }
        return $data;
    }
}
