<?php
namespace Mnb\SecurityCore\Throughput;

class SlowOperationClassifier
{
    public function classify(string $label, array $metadata = []): string
    {
        $haystack = strtolower($label . ' ' . implode(' ', array_map('strval', $metadata)));
        return match (true) {
            str_contains($haystack, 'db') || str_contains($haystack, 'query') => 'slow_database_query',
            str_contains($haystack, 'file') || str_contains($haystack, 'scan') => 'slow_file_scan',
            str_contains($haystack, 'http') || str_contains($haystack, 'webhook') || str_contains($haystack, 'network') => 'slow_network_call',
            str_contains($haystack, 'process') || str_contains($haystack, 'runtime') => 'slow_runtime_process',
            str_contains($haystack, 'cache') => 'slow_cache_miss',
            str_contains($haystack, 'queue') || str_contains($haystack, 'job') => 'slow_queue_job',
            default => 'slow_operation',
        };
    }
}
