# Memory Management and Resource Safety

**Package:** `mnb/mnb-secure-core`  
**Version line:** `MNB Secure Core v1.0.1`  
**Feature area:** Memory governance, streaming safety, bounded buffers, payload limits, output-buffer protection, scoped cleanup, temporary-file safety, and worker memory supervision.

---

## 1. Purpose

The **Memory Management and Resource Safety** module protects PHP applications from resource exhaustion, memory leaks, unsafe buffering, oversized payloads, unbounded bulk processing, temporary-file buildup, and long-running worker memory growth.

A secure application must not assume that every request, file, export, JSON body, queue job, or report can safely fit in memory.

Unsafe patterns include:

```php
$rows = $statement->fetchAll();
$body = file_get_contents($largeFilePath);
$data = json_decode($hugeJson, true);
$items[] = $row; // unbounded growth
ob_start();
// generate huge response into memory
```

The safer strategy is to use memory budgets, chunk processing, streaming, bounded buffers, payload-depth checks, output-buffer limits, and scoped resource cleanup:

```php
$reader = $kernel->safeStreamReader();

foreach ($reader->chunks($path, 'upload_scan') as $chunk) {
    // inspect or process a safe chunk
}
```

---

## 2. What this module protects

This module helps prevent:

```text
Memory exhaustion
Large payload DoS
Deep JSON / nested array DoS
Unbounded buffering
Unsafe bulk exports
Resource leaks
Temporary-file exhaustion
Worker memory leaks
Unsafe stream reads
Unsafe stream writes
Unbounded collection growth
Output buffer explosion
Leaked file handles
Forgotten temporary files
```

It is designed for:

```text
API requests
File uploads
Document inspection
Malware scanning
CSV imports
Database exports
Audit exports
Backup jobs
Queue workers
Security verification runs
Webhook jobs
Admin reports
CLI workers
```

---

## 3. Composer installation

Install the package from Packagist:

```bash
composer require mnb/mnb-secure-core
```

Load Composer autoload:

```php
require __DIR__ . '/vendor/autoload.php';
```

Typical kernel bootstrap:

```php
use Mnb\SecureCore\Core\SecurityKernel;

$config = require __DIR__ . '/vendor/mnb/mnb-secure-core/config/security.php';

$kernel = new SecurityKernel($config);
```

---

## 4. Core classes

The memory/resource safety engine includes the original memory tools plus the expanded governance layer.

```text
src/Memory/MemoryConfig.php
src/Memory/MemoryGuard.php
src/Memory/MemoryMonitor.php
src/Memory/MemorySnapshot.php
src/Memory/ChunkProcessor.php
src/Memory/ResourceTracker.php

src/Memory/MemoryPolicy.php
src/Memory/MemoryBudget.php
src/Memory/OperationMemoryProfile.php
src/Memory/MemoryBudgetDecision.php
src/Memory/StreamBudget.php
src/Memory/StreamGuard.php
src/Memory/SafeStreamReader.php
src/Memory/SafeStreamWriter.php
src/Memory/BoundedBuffer.php
src/Memory/BoundedCollection.php
src/Memory/PayloadSizeGuard.php
src/Memory/DecodedPayloadGuard.php
src/Memory/JsonDepthGuard.php
src/Memory/ArrayDepthGuard.php
src/Memory/OutputBufferGuard.php
src/Memory/ResponseSizeBudget.php
src/Memory/MemoryLeakDetector.php
src/Memory/WorkerMemorySupervisor.php
src/Memory/ResourceScope.php
src/Memory/ResourceScopeManager.php
src/Memory/CleanupStack.php
src/Memory/TemporaryFileBudget.php
src/Memory/TemporaryFileManager.php
src/Memory/TempStorageSweeper.php
src/Memory/MemoryAuditEvents.php
```

Related exception:

```text
src/Exceptions/MemoryLimitExceededException.php
```

---

## 5. Configuration

The memory configuration lives in `config/security.php` and `config/security.production.php`.

Example:

```php
'memory' => [
    'enabled' => true,

    // 0 means resolve from PHP memory_limit when possible.
    'max_bytes' => 0,
    'warning_ratio' => 0.75,
    'critical_ratio' => 0.90,

    'default_chunk_size' => 500,
    'min_chunk_size' => 25,
    'max_chunk_size' => 5000,

    'guard_requests' => true,
    'log_snapshots' => false,

    'profiles' => [
        'request' => [
            'enabled' => true,
            'max_bytes' => '64M',
            'critical_ratio' => 0.90,
        ],
        'upload_scan' => [
            'enabled' => true,
            'max_bytes' => '128M',
            'require_streaming' => true,
            'max_read_bytes' => 10485760,
        ],
        'database_export' => [
            'enabled' => true,
            'max_bytes' => '128M',
            'require_streaming' => true,
            'chunk_size' => 1000,
            'max_rows' => 100000,
        ],
        'audit_export' => [
            'enabled' => true,
            'max_bytes' => '96M',
            'require_streaming' => true,
            'chunk_size' => 1000,
        ],
        'queue_worker' => [
            'enabled' => true,
            'max_bytes' => '256M',
            'restart_after_growth_mb' => 64,
            'restart_after_jobs' => 500,
        ],
    ],

    'payloads' => [
        'max_decoded_depth' => 32,
        'max_array_items' => 10000,
        'max_string_bytes' => 1048576,
        'block_deep_json' => true,
    ],

    'streams' => [
        'max_read_bytes' => 10485760,
        'max_write_bytes' => 52428800,
        'buffer_size' => 8192,
        'fail_closed' => true,
    ],

    'temporary_files' => [
        'max_files' => 100,
        'max_total_bytes' => 104857600,
        'max_age_seconds' => 3600,
        'cleanup_on_shutdown' => true,
    ],

    'output_buffers' => [
        'enabled' => true,
        'max_buffer_bytes' => 1048576,
        'fail_closed' => true,
    ],
],
```

---

## 6. Operation memory profiles

A profile describes the memory rules for a specific operation type.

Recommended default profiles:

| Profile | Purpose |
|---|---|
| `request` | Normal web/API request memory budget. |
| `upload_scan` | File upload inspection and malware scanning. |
| `database_export` | Large database export or report generation. |
| `audit_export` | Security/audit log exports. |
| `queue_worker` | Long-running background worker memory control. |

Resolve a profile:

```php
$profile = $kernel->memoryPolicy()->profile('database_export');

if ($profile->requiresStreaming()) {
    // Use stream/chunk-based processing instead of fetchAll or full buffering.
}
```

Evaluate a budget decision:

```php
$decision = $kernel->memoryPolicy()->canAllocate('upload_scan', 2 * 1024 * 1024);

if (!$decision->allowed()) {
    throw new RuntimeException($decision->reason());
}
```

---

## 7. Memory guard usage

The `MemoryGuard` checks current memory usage, peak memory, warning thresholds, and critical thresholds.

```php
$guard = $kernel->memoryGuard();

$snapshot = $guard->snapshot('before_export');

$guard->check('before processing export');

// process work safely

$guard->check('after processing export');
```

Example snapshot shape:

```php
[
    'label' => 'before_export',
    'current_bytes' => 10485760,
    'peak_bytes' => 12582912,
    'limit_bytes' => 134217728,
    'usage_ratio' => 0.078,
    'peak_ratio' => 0.093,
]
```

When usage crosses the critical ratio, the guard can throw:

```php
use Mnb\SecureCore\Exceptions\MemoryLimitExceededException;

try {
    $kernel->memoryGuard()->check('large import');
} catch (MemoryLimitExceededException $e) {
    // Return safe response, defer to queue, or stop processing.
}
```

---

## 8. Recommended chunk size

The guard can recommend safe chunk sizes based on the current budget.

```php
$chunkSize = $kernel->memoryGuard()->recommendedChunkSize(
    requestedChunkSize: 2000,
    estimatedBytesPerItem: 2048
);
```

Use the recommended chunk size for:

```text
CSV imports
Database exports
Audit exports
Bulk security scans
Bulk notification jobs
Large report generation
```

---

## 9. ChunkProcessor usage

The `ChunkProcessor` processes an iterable in safe chunks.

```php
$processor = $kernel->chunkProcessor();

$result = $processor->process($rows, function (array $chunk): void {
    foreach ($chunk as $row) {
        // process row safely
    }
}, chunkSize: 500);
```

Safer export pattern:

```php
$processor->process($dbRows, function (array $chunk) use ($writer): void {
    foreach ($chunk as $row) {
        $writer->writeRow($row);
    }
});
```

Avoid:

```php
$rows = $statement->fetchAll();
```

Prefer:

```php
while ($row = $statement->fetch(PDO::FETCH_ASSOC)) {
    // stream row into chunk processor or writer
}
```

---

## 10. Stream safety

The stream guard prevents large file/response reads and writes from exceeding configured budgets.

### Safe reading

```php
$reader = $kernel->safeStreamReader();

foreach ($reader->chunks($filePath, 'upload_scan') as $chunk) {
    // inspect chunk
}
```

Example for hashing a large file without loading it fully:

```php
$hash = hash_init('sha256');

foreach ($kernel->safeStreamReader()->chunks($filePath, 'upload_scan') as $chunk) {
    hash_update($hash, $chunk);
}

$fileHash = hash_final($hash);
```

### Safe writing

```php
$writer = $kernel->safeStreamWriter();

$writer->write($outputPath, function ($handle): void {
    fwrite($handle, "id,name,status\n");
    fwrite($handle, "1,Demo,active\n");
}, 'database_export');
```

The writer enforces:

```text
maximum write bytes
safe buffer size
profile-specific write budget
fail-closed behavior
```

---

## 11. Bounded buffers

A bounded buffer prevents accidental unbounded array growth.

```php
$buffer = $kernel->boundedBuffer(maxItems: 500);

foreach ($rows as $row) {
    $buffer->push($row);

    if ($buffer->isFull()) {
        $exporter->writeRows($buffer->flush());
    }
}

if (!$buffer->isEmpty()) {
    $exporter->writeRows($buffer->flush());
}
```

Use bounded buffers for:

```text
Export rows
Import validation results
Audit records
Queue batch dispatch
Webhook batch delivery
Search result streaming
```

Avoid:

```php
$allRows[] = $row;
```

when the number of rows is not tightly bounded.

---

## 12. Bounded collections

A bounded collection protects internal arrays used by services.

```php
$collection = $kernel->boundedCollection(maxItems: 1000);

foreach ($items as $item) {
    $collection->add($item);
}
```

If the limit is exceeded, the collection should fail safely rather than silently consuming memory.

---

## 13. Payload size guard

The payload guard blocks oversized strings, arrays, and decoded payloads.

```php
$guard = $kernel->payloadSizeGuard();

$guard->assertStringWithinLimit($jsonBody);
$guard->assertArrayWithinLimit($decodedPayload);
```

Useful places:

```text
API JSON bodies
Webhook bodies
Queue payloads
Cache payloads
Database JSON fields
Import payloads
```

---

## 14. JSON depth guard

Deep JSON can cause memory and CPU pressure during decoding or validation.

```php
$jsonGuard = $kernel->jsonDepthGuard();

$jsonGuard->assertSafe($jsonBody);

$data = json_decode($jsonBody, true, 32, JSON_THROW_ON_ERROR);
```

Unsafe example:

```json
{"a":{"a":{"a":{"a":{"a":{"a":"too deep"}}}}}}
```

The guard should block payloads above the configured depth.

---

## 15. Array depth guard

The array depth guard validates decoded PHP arrays.

```php
$arrayGuard = $kernel->arrayDepthGuard();

$arrayGuard->assertSafe($decodedPayload);
```

This is useful after:

```text
json_decode
unserialized trusted internal structures
parsed CSV batches
parsed webhook payloads
queue payload normalization
```

Do not use PHP `unserialize()` on untrusted data. Use JSON or explicit safe serialization formats.

---

## 16. Decoded payload guard

The decoded payload guard combines size, item count, string length, and depth checks.

```php
$payload = json_decode($requestBody, true, 32, JSON_THROW_ON_ERROR);

$kernel->decodedPayloadGuard()->assertSafe($payload);
```

This helps protect against:

```text
huge arrays
deep arrays
large strings
nested API payload abuse
memory amplification payloads
```

---

## 17. Output buffer guard

Output buffering can silently consume a lot of memory.

Unsafe:

```php
ob_start();
renderHugeReport();
$html = ob_get_clean();
```

Safer pattern:

```php
$bufferGuard = $kernel->outputBufferGuard();

$result = $bufferGuard->capture(function (): void {
    echo '<p>Safe small output</p>';
});

echo $result->content();
```

If generated output exceeds `max_buffer_bytes`, the guard blocks or fails closed depending on policy.

For large responses, prefer streaming:

```text
CSV download
large audit export
large report export
large backup download
```

---

## 18. Resource scope

Resource scopes guarantee cleanup for temporary files, handles, and cleanup callbacks.

```php
$scope = $kernel->resourceScopeManager()->start('upload_scan');

try {
    $tmp = $scope->temporaryFile('scan_', '.tmp');

    $handle = fopen($tmp, 'wb');
    $scope->trackHandle($handle);

    fwrite($handle, 'temporary content');

    // process safely
} finally {
    $scope->cleanup();
}
```

The scope cleanup should be idempotent, so repeated cleanup calls are safe.

---

## 19. Cleanup stack

A cleanup stack runs cleanup callbacks in reverse order.

```php
$stack = $kernel->cleanupStack();

$stack->push(function (): void {
    // cleanup first resource
});

$stack->push(function (): void {
    // cleanup second resource
});

$stack->cleanup();
```

Use it when a workflow creates multiple temporary resources.

---

## 20. Temporary file safety

Temporary files can become a disk-exhaustion problem.

The temporary file manager enforces:

```text
maximum file count
maximum total temporary bytes
maximum file age
safe cleanup on shutdown
```

Create a managed temporary file:

```php
$tmp = $kernel->temporaryFileManager()->create('upload_', '.tmp');
```

Generate a cleanup plan:

```php
$plan = $kernel->tempStorageSweeper()->cleanupPlan();

foreach ($plan->expiredFiles() as $file) {
    // review or remove according to policy
}
```

Production recommendation:

```text
Use a dedicated temp directory for application-managed files.
Do not mix app temporary files with system-wide unrelated temp files.
Do not expose temp directories through public web root.
```

---

## 21. Worker memory supervision

Long-running workers can grow memory over time even when each job is small.

The worker supervisor tracks:

```text
memory before job
memory after job
peak memory
jobs processed
growth trend
restart recommendation
```

Example:

```php
$supervisor = $kernel->workerMemorySupervisor();

$supervisor->beforeJob('queue_worker');

try {
    $worker->processOneJob();
} finally {
    $report = $supervisor->afterJob('queue_worker');

    if ($report->restartRecommended()) {
        // stop worker gracefully and let process manager restart it
    }
}
```

Restart recommendations may happen when:

```text
worker processed max jobs
memory growth exceeded threshold
peak memory crossed critical ratio
resource leaks were detected
runtime exceeded policy
```

---

## 22. Memory leak detector

The memory leak detector compares memory snapshots over time.

```php
$detector = $kernel->memoryLeakDetector();

$detector->record('before_job');

// run job

$report = $detector->record('after_job')->analyze();

if ($report->growthExceeded()) {
    // log, alert, or restart worker
}
```

Use this in:

```text
queue workers
CLI daemons
bulk import loops
background verification runners
long backup jobs
```

---

## 23. Integration with file security

File workflows should use streaming and memory budgets.

Secure upload inspection flow:

```php
$profile = 'upload_scan';

foreach ($kernel->safeStreamReader()->chunks($uploadedPath, $profile) as $chunk) {
    // inspect chunk, hash chunk, or pass to scanner logic
}
```

For large files:

```text
Do not load full file into a string.
Do not read full archive contents into memory.
Do not generate previews synchronously without a budget.
Queue expensive document processing.
```

---

## 24. Integration with protected downloads

Protected downloads should stream response bodies instead of buffering them.

Recommended strategy:

```text
Authorize download
Open private file handle
Set safe response headers
Stream chunks
Check stream budget
Close handle in resource scope
```

Pseudo-code:

```php
$scope = $kernel->resourceScopeManager()->start('download');

try {
    $handle = fopen($privatePath, 'rb');
    $scope->trackHandle($handle);

    while (!feof($handle)) {
        echo fread($handle, 8192);
        flush();
    }
} finally {
    $scope->cleanup();
}
```

---

## 25. Integration with database exports

Large database exports should never use `fetchAll()`.

Unsafe:

```php
$rows = $pdo->query('SELECT * FROM audit_logs')->fetchAll();
```

Safe:

```php
$statement = $pdo->query('SELECT id, event_type, created_at FROM audit_logs');
$buffer = $kernel->boundedBuffer(1000);

while ($row = $statement->fetch(PDO::FETCH_ASSOC)) {
    $buffer->push($row);

    if ($buffer->isFull()) {
        $csvWriter->writeRows($buffer->flush());
    }
}

$csvWriter->writeRows($buffer->flush());
```

For expensive exports, combine with the queue engine:

```php
$kernel->jobDispatcher()->dispatch(
    name: 'database_export',
    payload: ['export_id' => $exportId],
    queue: 'exports',
    idempotencyKey: 'database_export:' . $exportId
);
```

---

## 26. Integration with queue workers

Queue jobs should use memory profiles and worker supervision.

```php
$worker = $kernel->queueWorker();
$supervisor = $kernel->workerMemorySupervisor();

while (true) {
    $supervisor->beforeJob('queue_worker');

    $worker->processOne('default');

    $report = $supervisor->afterJob('queue_worker');

    if ($report->restartRecommended()) {
        break;
    }
}
```

This keeps workers stable over long runtimes.

---

## 27. Integration with safe error handling

Memory failures should return safe responses.

Unsafe public response:

```text
Fatal error: Allowed memory size of 134217728 bytes exhausted in /var/www/app/Export.php
```

Safe response:

```json
{
  "status": false,
  "message": "The request could not be completed safely.",
  "error": {
    "code": "RESOURCE_LIMIT_EXCEEDED",
    "request_id": "req_..."
  }
}
```

Internal logs should include sanitized memory context:

```json
{
  "event": "memory.critical",
  "profile": "database_export",
  "current_bytes": 123000000,
  "limit_bytes": 134217728,
  "request_id": "req_..."
}
```

---

## 28. Integration with throughput and capacity

Memory and throughput should work together.

Example policy decisions:

```text
If memory is near critical, throttle expensive requests.
If export requires streaming, force async queue.
If queue worker memory grows too much, restart worker.
If output buffering exceeds budget, fail closed.
```

Use throughput profiles with memory profiles:

```text
memory profile: database_export
throughput profile: database_export
queue: exports
```

---

## 29. SecurityKernel accessors

Typical accessors for this module:

```php
$kernel->memoryPolicy();
$kernel->memoryGuard();
$kernel->memoryGuardFor('database_export');
$kernel->chunkProcessor();
$kernel->streamGuard();
$kernel->safeStreamReader();
$kernel->safeStreamWriter();
$kernel->boundedBuffer(500);
$kernel->boundedCollection(1000);
$kernel->payloadSizeGuard();
$kernel->decodedPayloadGuard();
$kernel->jsonDepthGuard();
$kernel->arrayDepthGuard();
$kernel->outputBufferGuard();
$kernel->resourceScopeManager();
$kernel->temporaryFileManager();
$kernel->tempStorageSweeper();
$kernel->memoryLeakDetector();
$kernel->workerMemorySupervisor();
```

Names may vary slightly by implementation, but these represent the intended service surface.

---

## 30. CLI usage

Existing commands:

```bash
php bin/mnb-secure memory:check
php bin/mnb-secure memory:sample-plan
```

Additional memory/resource diagnostics:

```bash
php bin/mnb-secure memory:policy
php bin/mnb-secure memory:profile request
php bin/mnb-secure memory:profile database_export
php bin/mnb-secure memory:simulate-allocation 10485760 request
php bin/mnb-secure memory:stream-plan 52428800 read
php bin/mnb-secure memory:payload-check
php bin/mnb-secure memory:worker-check
php bin/mnb-secure resources:check
php bin/mnb-secure resources:cleanup-plan
```

Example profile output:

```json
{
  "profile": "database_export",
  "enabled": true,
  "max_bytes": 134217728,
  "require_streaming": true,
  "chunk_size": 1000,
  "max_rows": 100000
}
```

Example allocation decision:

```json
{
  "profile": "request",
  "requested_bytes": 10485760,
  "allowed": true,
  "status": "ok"
}
```

Example stream plan:

```json
{
  "direction": "read",
  "requested_bytes": 52428800,
  "allowed": false,
  "reason": "max_read_bytes_exceeded"
}
```

---

## 31. Demo

Run the demo:

```bash
php demos/35-memory-governance-resource-safety-engine.php
```

Or run all demos:

```bash
php demos/run-all-demos.php
```

The demo should show:

```text
Memory policy loaded
Request memory profile resolved
Memory snapshot captured
Safe allocation allowed
Unsafe allocation blocked
Recommended chunk size calculated
Chunk processor runs within budget
Safe stream reader limits read bytes
Bounded buffer flushes safely
Deep JSON payload blocked
Output buffer limit enforced
Resource scope cleans handles and temp files
Temporary file budget checked
Worker memory leak detected
Vulnerability matrix coverage improved
```

---

## 32. Testing examples

Run the full package tests:

```bash
php tests/run-tests.php
```

Recommended test cases:

```text
Memory Policy
- profile resolves
- missing profile falls back safely
- invalid memory size rejected
- production profile cannot be unlimited unless explicitly allowed

Memory Guard
- warning threshold detected
- critical threshold throws MemoryLimitExceededException
- canAllocate returns false near critical budget
- recommended chunk size respects min/max

Stream Guard
- read within max bytes passes
- read exceeding max bytes blocks
- write exceeding max bytes blocks
- stream chunk size respected
- missing file handled safely

Payload Guard
- large string blocked
- large array blocked
- deep nested array blocked
- deep JSON blocked
- safe payload passes

Bounded Buffer
- max item count enforced
- flush clears buffer
- callback flush works

Output Buffer
- oversized buffer blocked
- safe buffer passes

Resource Scope
- file handle closed
- temp file deleted
- cleanup is idempotent
- destructor cleanup works

Temporary Files
- max temp file count enforced
- max total bytes enforced
- old temp file cleanup plan generated

Worker Supervision
- memory growth detected
- restart recommended after job threshold
- restart recommended after memory growth threshold

Integration
- upload/document processing uses stream policy
- protected downloads stream safely
- database export profile uses chunk limits
- vulnerability matrix maps memory exhaustion and resource leaks
```

---

## 33. Vulnerability matrix coverage

This module maps to vulnerabilities such as:

```text
memory_exhaustion
large_payload_dos
deep_json_dos
unbounded_buffering
unsafe_bulk_export
resource_leak
temporary_file_exhaustion
worker_memory_leak
unsafe_stream_read
unsafe_stream_write
```

Expected controls:

```text
MemoryPolicy
MemoryGuard
OperationMemoryProfile
StreamGuard
SafeStreamReader
SafeStreamWriter
PayloadSizeGuard
JsonDepthGuard
ArrayDepthGuard
DecodedPayloadGuard
BoundedBuffer
OutputBufferGuard
ResourceScope
TemporaryFileManager
MemoryLeakDetector
WorkerMemorySupervisor
```

Check the vulnerability report:

```bash
php bin/mnb-secure vulnerabilities:report
```

Check specific risks:

```bash
php bin/mnb-secure vulnerabilities:check memory_exhaustion
php bin/mnb-secure vulnerabilities:check resource_leak
php bin/mnb-secure vulnerabilities:check large_payload_dos
```

---

## 34. Audit events

Recommended memory/resource audit events:

```text
memory.snapshot.captured
memory.warning
memory.critical
memory.allocation.allowed
memory.allocation.blocked
memory.profile.resolved
memory.stream.read_allowed
memory.stream.read_blocked
memory.stream.write_allowed
memory.stream.write_blocked
memory.payload.blocked
memory.json_depth.blocked
memory.output_buffer.blocked
resource.scope.started
resource.scope.cleaned
resource.temp.created
resource.temp.cleaned
resource.temp_budget.warning
worker.memory_growth.detected
worker.restart_recommended
```

Audit event example:

```json
{
  "event": "memory.allocation.blocked",
  "profile": "database_export",
  "requested_bytes": 104857600,
  "reason": "critical_budget_exceeded",
  "request_id": "req_..."
}
```

---

## 35. Production checklist

Before production, verify:

```text
[ ] PHP memory_limit is known and intentionally configured.
[ ] memory.max_bytes is set or safely resolves from PHP memory_limit.
[ ] warning_ratio and critical_ratio are set.
[ ] Expensive operations have memory profiles.
[ ] Upload scanning uses streaming or chunking.
[ ] Protected downloads stream files.
[ ] Database exports do not use fetchAll for large result sets.
[ ] Large exports are queued.
[ ] JSON payload depth and size limits are enabled.
[ ] Output buffer guard is enabled.
[ ] Temporary files are outside public web root.
[ ] Temporary file cleanup policy is enabled.
[ ] Queue workers have memory restart limits.
[ ] Worker process manager can restart workers safely.
[ ] Memory events are logged safely.
[ ] Vulnerability matrix includes memory/resource risks.
```

---

## 36. Common mistakes

### Mistake 1: Loading full files into memory

Avoid:

```php
$content = file_get_contents($largeFile);
```

Prefer:

```php
foreach ($kernel->safeStreamReader()->chunks($largeFile, 'upload_scan') as $chunk) {
    // process chunk
}
```

### Mistake 2: Using `fetchAll()` for exports

Avoid:

```php
$rows = $stmt->fetchAll();
```

Prefer row streaming and bounded buffers.

### Mistake 3: Trusting JSON body size only before decoding

A JSON body can be small but deeply nested. Check both raw size and decoded depth.

### Mistake 4: Forgetting temporary-file cleanup

Always use `ResourceScope` or `TemporaryFileManager` for temp files.

### Mistake 5: Running workers forever without restart rules

Long-running workers should restart after job count, runtime, or memory growth thresholds.

### Mistake 6: Buffering large responses

Do not generate large CSV/PDF/backup responses inside output buffers. Stream them.

---

## 37. Recommended workflow

For normal API requests:

```text
Request received
Memory profile: request
Payload guard checks raw and decoded payload
Business logic runs
Memory guard checks usage
Safe response returned
```

For large file uploads:

```text
Request accepted
Upload size checked
File stored privately
Upload scan profile resolved
File scanned/inspected by stream or queued job
Quarantine or accept result stored
```

For database exports:

```text
Export request accepted
Throughput policy decides async queue
Memory profile: database_export
Rows streamed/chunked
Output streamed to private file
Protected download issued
```

For workers:

```text
Worker starts
Memory supervisor baseline recorded
Job runs inside resource scope
Payload/stream/buffer guards protect work
Cleanup runs
Supervisor decides continue or graceful restart
```

---

## 38. Quick reference

| Need | Use |
|---|---|
| Check current memory | `MemoryGuard` |
| Define operation budget | `MemoryPolicy`, `OperationMemoryProfile` |
| Process large iterable | `ChunkProcessor` |
| Read large file safely | `SafeStreamReader` |
| Write large file safely | `SafeStreamWriter` |
| Prevent array growth | `BoundedBuffer`, `BoundedCollection` |
| Block huge payload | `PayloadSizeGuard` |
| Block deep JSON | `JsonDepthGuard`, `ArrayDepthGuard` |
| Limit output buffering | `OutputBufferGuard` |
| Cleanup handles/files | `ResourceScope`, `CleanupStack` |
| Manage temp files | `TemporaryFileManager`, `TempStorageSweeper` |
| Detect worker leaks | `MemoryLeakDetector`, `WorkerMemorySupervisor` |
```
