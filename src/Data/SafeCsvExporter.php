<?php
namespace Mnb\SecurityCore\Data;

class SafeCsvExporter
{
    public function __construct(private DataProtectionRegistry $registry, private ExportPolicy $policy = new ExportPolicy()) {}

    /** @param iterable<array<string,mixed>> $rows */
    public function export(string $resource, iterable $rows, ?array $headers = null): string
    {
        $buffer = fopen('php://temp', 'r+');
        if ($buffer === false) {
            throw new \RuntimeException('Unable to open CSV buffer.');
        }
        $count = 0;
        $wroteHeaders = false;
        foreach ($rows as $row) {
            if (++$count > $this->policy->maxRows()) {
                throw new \RuntimeException('CSV export row limit exceeded.');
            }
            $safe = $this->registry->protectForExport($resource, $row);
            if (!$wroteHeaders) {
                $headerRow = $headers ?: array_keys($safe);
                fputcsv($buffer, $headerRow);
                $wroteHeaders = true;
            }
            $ordered = [];
            foreach (($headers ?: array_keys($safe)) as $header) {
                $ordered[] = $this->csvSafe($safe[(string)$header] ?? '');
            }
            fputcsv($buffer, $ordered);
        }
        if (!$wroteHeaders) {
            fputcsv($buffer, $headers ?: []);
        }
        rewind($buffer);
        $csv = stream_get_contents($buffer);
        fclose($buffer);
        return $csv === false ? '' : $csv;
    }

    private function csvSafe(mixed $value): string
    {
        if (is_array($value) || is_object($value)) {
            $value = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '';
        }
        $string = (string)$value;
        if ($this->policy->csvInjectionProtection() && $string !== '' && preg_match('/^[=+\-@\t\r]/', $string)) {
            return "'" . $string;
        }
        return $string;
    }
}
