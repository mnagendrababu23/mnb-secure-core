<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Memory\ChunkProcessor;
use Mnb\SecurityCore\Memory\MemoryConfig;
use Mnb\SecurityCore\Memory\MemoryGuard;
use Mnb\SecurityCore\Memory\ResourceTracker;

$config = MemoryConfig::fromArray([
    'max_bytes' => '128M',
    'warning_ratio' => 0.75,
    'critical_ratio' => 0.90,
    'default_chunk_size' => 500,
]);

$guard = new MemoryGuard($config);
$processor = new ChunkProcessor($guard);
$tracker = new ResourceTracker();

$tempFile = $tracker->trackTemporaryFile(sys_get_temp_dir() . '/mnb-memory-demo-' . getmypid() . '.txt');
file_put_contents($tempFile, 'temporary export content');

$rows = ChunkProcessor::lazyRange(1, 2500);
$summary = $processor->process($rows, function (array $chunk): void {
    // Store/export/send this chunk only. Do not keep all chunks in memory.
}, 500, 'example-large-export');

$guard->assertWithinBudget('example-complete');
$tracker->cleanup();

print_r([
    'summary' => $summary,
    'snapshot' => $guard->snapshot('after-example')->toArray(),
]);
