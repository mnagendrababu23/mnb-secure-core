<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Memory\BoundedBuffer;
use Mnb\SecurityCore\Memory\ChunkProcessor;

demo_title('35. Memory Governance and Resource Safety Engine');

$config = require __DIR__ . '/../config/security.php';
$config['paths']['cache'] = demo_storage_path('cache');
$kernel = new SecurityKernel($config);

$policy = $kernel->memoryPolicy();
demo_step('Memory policy loaded', array_keys($policy->profiles()));

$requestProfile = $policy->profile('request');
demo_step('Request memory profile resolved', $requestProfile->toArray());

$snapshot = $kernel->memoryGuard('request')->snapshot('demo35-request');
demo_step('Memory snapshot captured', $snapshot->toArray());

$allowedDecision = $policy->decideAllocation('request', 1024, 1024 * 1024);
$blockedDecision = $policy->decideAllocation('request', 100 * 1024 * 1024, 60 * 1024 * 1024);
demo_step('Safe allocation allowed', $allowedDecision->toArray());
demo_step('Unsafe allocation blocked', $blockedDecision->toArray());

$chunked = [];
$chunkSummary = (new ChunkProcessor($kernel->memoryGuard('request')))->process(range(1, 55), function (array $chunk) use (&$chunked): void {
    $chunked[] = count($chunk);
}, 20, 'request');
demo_step('Chunk processor runs within budget', $chunkSummary);

$streamFile = demo_storage_path('memory/demo35-stream.txt');
file_put_contents($streamFile, str_repeat('A', 4096));
$readBytes = 0;
foreach ($kernel->safeStreamReader()->chunks($streamFile, 8192, 1024) as $chunk) {
    $readBytes += strlen($chunk);
}
demo_step('Safe stream reader limits read bytes', ['read_bytes' => $readBytes]);

$flushed = [];
$buffer = new BoundedBuffer(3, function (array $items) use (&$flushed): void { $flushed[] = $items; });
foreach ([1, 2, 3, 4] as $item) { $buffer->push($item); }
$remaining = $buffer->flush();
demo_step('Bounded buffer flushes safely', ['flushes' => count($flushed), 'remaining' => $remaining]);

$deepBlocked = false;
try {
    $tooDeep = ['a' => ['b' => ['c' => ['d' => ['e' => true]]]]];
    (new \Mnb\SecurityCore\Memory\ArrayDepthGuard(3))->assertWithinDepth($tooDeep);
} catch (Throwable $e) {
    $deepBlocked = true;
}
demo_step('Deep payload blocked', $deepBlocked);

$outputBlocked = false;
try {
    $kernel->outputBufferGuard()->assertSafe(str_repeat('x', 2 * 1024 * 1024));
} catch (Throwable $e) {
    $outputBlocked = true;
}
demo_step('Output buffer limit enforced', $outputBlocked);

$scope = $kernel->resourceScopeManager()->start('demo35-resource-scope');
$tmp = demo_storage_path('memory/demo35-temp.txt');
file_put_contents($tmp, 'temporary');
$scope->trackTemporaryFile($tmp);
$scopeReport = $scope->cleanup();
demo_step('Resource scope cleans handles and temp files', $scopeReport);

$tempUsage = $kernel->temporaryFileManager()->usage();
demo_step('Temporary file budget checked', $tempUsage);

$workerReport = $kernel->workerMemorySupervisor()->check(501, memory_get_usage(true), memory_get_usage(true));
demo_step('Worker memory supervisor recommends restart when job threshold reached', $workerReport);

$matrix = $kernel->vulnerabilityMatrix()->find('memory_exhaustion');
demo_step('Vulnerability matrix coverage improved', $matrix?->toArray());

demo_result(
    $allowedDecision->allowed()
    && $blockedDecision->blocked()
    && $chunkSummary['processed'] === 55
    && $readBytes === 4096
    && count($flushed) >= 1
    && $deepBlocked
    && $outputBlocked
    && !is_file($tmp)
    && $tempUsage['passed'] === true
    && $workerReport['restart_recommended'] === true
    && $matrix !== null,
    'Memory profiles, streaming guards, bounded buffers, payload/output limits, scoped cleanup, temp budgets, worker supervision, and matrix coverage are working.'
);
