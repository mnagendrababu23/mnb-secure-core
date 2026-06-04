<?php
require __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Http\Middleware\MemoryLimitMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Memory\ChunkProcessor;
use Mnb\SecurityCore\Memory\MemoryConfig;
use Mnb\SecurityCore\Memory\MemoryGuard;
use Mnb\SecurityCore\Memory\ResourceTracker;

demo_title('Concept 17: Memory Management and Resource Safety');

$config = MemoryConfig::fromArray([
    'max_bytes' => '64M',
    'warning_ratio' => 0.75,
    'critical_ratio' => 0.90,
    'default_chunk_size' => 500,
    'min_chunk_size' => 25,
    'max_chunk_size' => 1000,
]);
$guard = new MemoryGuard($config);

demo_step('Configured memory limit', MemoryGuard::bytesToHuman($config->maxBytes()));
demo_step('Warning threshold', MemoryGuard::bytesToHuman($config->warningBytes()));
demo_step('Critical threshold', MemoryGuard::bytesToHuman($config->criticalBytes()));

$snapshot = $guard->snapshot('demo-start');
demo_step('Initial snapshot', $snapshot->toArray());

$processor = new ChunkProcessor($guard);
$sum = 0;
$summary = $processor->process(ChunkProcessor::lazyRange(1, 1234), function (array $chunk) use (&$sum): void {
    $sum += array_sum($chunk);
}, 250, 'demo-chunked-import');
demo_step('Chunked processing summary', $summary);
demo_result($summary['processed'] === 1234 && $summary['chunks'] === 5 && $sum === array_sum(range(1, 1234)), 'large operation processed in bounded chunks');

$recommended = $guard->recommendedChunkSize(2048);
demo_step('Recommended chunk size for 2KB average rows', $recommended);
demo_result($recommended >= $config->minChunkSize() && $recommended <= $config->maxChunkSize(), 'recommended chunk size is within configured bounds');

$tracker = new ResourceTracker();
$tmp = $tracker->trackTemporaryFile(demo_storage_path('memory/temp-file.txt'));
file_put_contents($tmp, 'temporary file');
demo_step('Tracked resources before cleanup', $tracker->count());
$tracker->cleanup();
demo_result(!is_file($tmp), 'temporary resources cleaned safely');

$pipeline = new MiddlewarePipeline([new MemoryLimitMiddleware($guard, 'demo-request')]);
$response = $pipeline->handle(new Request('GET', '/memory-demo'), fn() => Response::json(['status' => true, 'message' => 'memory guarded']));
demo_step('Middleware response headers', $response->headers());
demo_result(isset($response->headers()['X-Memory-Peak-MB']), 'memory middleware adds memory usage headers');
