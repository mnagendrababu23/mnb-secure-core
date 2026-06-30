<?php
namespace Mnb\SecurityCore\Logging;

class AuditExporter
{
    public function __construct(private string $auditFile) {}

    /** @return array<string,mixed> */
    public function export(?string $category = null, ?int $limit = null): array
    {
        $entries = [];
        if (is_file($this->auditFile)) {
            foreach (file($this->auditFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
                $entry = json_decode($line, true);
                if (!is_array($entry)) { continue; }
                if ($category !== null && ($entry['category'] ?? null) !== $category) { continue; }
                $entries[] = $entry;
            }
        }
        if ($limit !== null && $limit > 0) {
            $entries = array_slice($entries, -$limit);
        }
        return ['passed' => true, 'file' => $this->auditFile, 'count' => count($entries), 'entries' => $entries];
    }

    public function toJsonLines(?string $category = null, ?int $limit = null): string
    {
        $lines = [];
        foreach ($this->export($category, $limit)['entries'] as $entry) {
            $lines[] = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        return implode(PHP_EOL, $lines) . ($lines ? PHP_EOL : '');
    }
}
