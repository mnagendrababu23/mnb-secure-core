<?php
namespace Mnb\SecurityCore\Errors;

use Throwable;

final class StackTraceSanitizer
{
    public function __construct(private ErrorPolicy $policy, private ?ErrorLogSanitizer $sanitizer = null) {
        $this->sanitizer ??= new ErrorLogSanitizer($policy);
    }

    /** @return array<int,array<string,mixed>> */
    public function sanitize(Throwable $throwable): array
    {
        $frames = [];
        foreach (array_slice($throwable->getTrace(), 0, $this->policy->maxStackFrames()) as $frame) {
            $frames[] = [
                'file' => isset($frame['file']) ? $this->sanitizePath((string)$frame['file']) : null,
                'line' => $frame['line'] ?? null,
                'function' => $this->sanitizer->sanitizeString((string)($frame['function'] ?? '')),
                'class' => isset($frame['class']) ? $this->sanitizer->sanitizeString((string)$frame['class']) : null,
            ];
        }
        return $frames;
    }

    public function sanitizePath(string $path): string
    {
        if (!$this->policy->redactPaths()) {
            return $path;
        }
        $path = str_replace('\\', '/', $path);
        $parts = explode('/vendor/', $path, 2);
        if (count($parts) === 2) {
            return 'vendor/' . $parts[1];
        }
        $src = explode('/src/', $path, 2);
        if (count($src) === 2) {
            return 'src/' . $src[1];
        }
        return basename($path);
    }
}
