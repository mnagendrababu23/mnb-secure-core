# Queue and Background Job Strategy

**Package:** `mnb/mnb-secure-core`  
**Version line:** `MNB Secure Core v1.0.1`  
**Feature area:** Async Request, Response Queue, and Background Job Orchestration Engine  
**Primary namespace:** `Mnb\SecureCore\Queue`

---

## 1. Purpose

The Queue and Background Job Strategy helps applications move expensive, slow, retryable, or unsafe-to-run-inline work out of the HTTP request lifecycle and into controlled background workers.

This feature is designed for jobs such as:

- file scanning
- document processing
- database exports
- audit exports
- backups
- webhook delivery
- email/OTP sending
- incident response actions
- security verification runs
- cache warmups
- report generation
- bulk imports

Without a queue strategy, these operations can cause request timeouts, memory pressure, duplicate execution, retry storms, lost jobs, and unstable user experience.

The queue engine provides a controlled lifecycle:

```text
request received
    ↓
policy decision
    ↓
synchronous response or async 202 response
    ↓
job stored safely
    ↓
worker reserves job
    ↓
handler executes job
    ↓
success, retry, fail, or dead-letter
    ↓
status and audit trail available
```

---

## 2. What this feature protects against

The queue engine helps reduce these risks:

| Risk | Protection |
|---|---|
| Long-running HTTP requests | Async `202 Accepted` response pattern |
| Duplicate execution | Idempotency keys and duplicate job guard |
| Retry storms | Bounded retry policy and backoff strategy |
| Lost jobs | Durable queue stores and job status records |
| Queue overload | Queue policy, queue pressure guard, release gate |
| Worker instability | Worker supervisor, heartbeat, memory checks |
| Unsafe job payloads | Payload protector and redactor |
| Secret leakage in jobs | Redaction and blocked sensitive fields |
| Unknown job execution | Handler registry allow-list |
| Permanent failures | Dead-letter queue |
| Background privilege confusion | Job context, audit events, and handler restrictions |

---

## 3. Main components

The queue feature is made of several groups of classes.

### 3.1 Job model

```php
use Mnb\SecureCore\Queue\Job;
use Mnb\SecureCore\Queue\JobId;
use Mnb\SecureCore\Queue\JobStatus;
use Mnb\SecureCore\Queue\JobPriority;
use Mnb\SecureCore\Queue\JobPayload;
use Mnb\SecureCore\Queue\JobContext;
use Mnb\SecureCore\Queue\JobResult;
```

The job model represents a unit of background work.

A job contains:

- job ID
- job name
- queue name
- payload
- status
- priority
- attempts
- timestamps
- context
- failure reason
- safe metadata

Common statuses:

```text
queued
reserved
running
succeeded
failed
retrying
dead_lettered
cancelled
expired
```

---

### 3.2 Queue policy

```php
use Mnb\SecureCore\Queue\QueueConfig;
use Mnb\SecureCore\Queue\QueuePolicy;
use Mnb\SecureCore\Queue\QueueDecision;
use Mnb\SecureCore\Queue\QueueNamePolicy;
```

The queue policy decides whether a job can be dispatched and where it should go.

It controls:

- enabled queues
- queue max depth
- max payload size
- default priority
- forced async jobs
- sync/async decision
- visibility timeout
- queue naming rules

---

### 3.3 Queue stores

```php
use Mnb\SecureCore\Queue\QueueStoreInterface;
use Mnb\SecureCore\Queue\FileQueueStore;
use Mnb\SecureCore\Queue\InMemoryQueueStore;
use Mnb\SecureCore\Queue\DatabaseQueueStore;
```

Supported queue stores:

| Store | Purpose |
|---|---|
| `FileQueueStore` | Local/shared-hosting compatible durable queue |
| `InMemoryQueueStore` | Tests and demos only |
| `DatabaseQueueStore` | Safe adapter/stub for database-backed queue implementation |

For production, use file or database-backed storage. Avoid in-memory storage outside tests.

---

### 3.4 Job handlers

```php
use Mnb\SecureCore\Queue\JobHandlerInterface;
use Mnb\SecureCore\Queue\JobHandlerRegistry;
use Mnb\SecureCore\Queue\JobMiddlewareInterface;
```

Only registered handlers can run jobs.

This protects the worker from executing arbitrary job names.

Example handler:

```php
use Mnb\SecureCore\Queue\Job;
use Mnb\SecureCore\Queue\JobHandlerInterface;
use Mnb\SecureCore\Queue\JobResult;

final class SendWebhookJobHandler implements JobHandlerInterface
{
    public function handle(Job $job): JobResult
    {
        $payload = $job->payload()->toArray();

        // Use OutboundHttpClient, not raw file_get_contents/curl.
        // $this->outboundHttpClient->postJson($payload['url'], $payload['body']);

        return JobResult::success([
            'delivered' => true,
        ]);
    }
}
```

Register the handler:

```php
$registry = $kernel->jobHandlerRegistry();
$registry->register('webhook_dispatch', new SendWebhookJobHandler());
```

Unknown job names should be rejected.

---

### 3.5 Dispatching

```php
use Mnb\SecureCore\Queue\JobDispatcher;
```

The dispatcher safely creates jobs and stores them.

It applies:

- queue policy
- queue depth limits
- payload size limits
- payload safety checks
- idempotency checks
- job name restrictions
- audit events

Example:

```php
$result = $kernel->jobDispatcher()->dispatch(
    name: 'file_scan',
    payload: [
        'file_id' => $fileId,
    ],
    queue: 'files',
    idempotencyKey: 'file_scan:' . $fileId
);

if ($result->accepted()) {
    return $kernel->asyncResponseFactory()->accepted($result);
}
```

---

## 4. Configuration

Add or review the `queue` block in `config/security.php`.

```php
'queue' => [
    'enabled' => true,

    'default_connection' => 'file',
    'default_queue' => 'default',

    'connections' => [
        'file' => [
            'driver' => 'file',
            'path' => __DIR__ . '/../storage/queue',
            'lock_path' => __DIR__ . '/../storage/cache/queue-locks',
        ],
        'database' => [
            'driver' => 'database',
            'table' => 'mnb_jobs',
            'failed_table' => 'mnb_failed_jobs',
        ],
        'memory' => [
            'driver' => 'memory',
        ],
    ],

    'queues' => [
        'default' => [
            'enabled' => true,
            'max_depth' => 10000,
            'max_payload_bytes' => 65536,
            'default_priority' => 'normal',
            'visibility_timeout_seconds' => 300,
        ],
        'files' => [
            'enabled' => true,
            'max_depth' => 5000,
            'max_payload_bytes' => 131072,
            'default_priority' => 'normal',
            'visibility_timeout_seconds' => 900,
        ],
        'exports' => [
            'enabled' => true,
            'max_depth' => 1000,
            'max_payload_bytes' => 65536,
            'default_priority' => 'low',
            'visibility_timeout_seconds' => 1800,
        ],
        'webhooks' => [
            'enabled' => true,
            'max_depth' => 10000,
            'max_payload_bytes' => 65536,
            'default_priority' => 'normal',
            'visibility_timeout_seconds' => 120,
        ],
    ],

    'dispatch' => [
        'allow_sync' => false,
        'force_async_for' => [
            'file_scan',
            'database_export',
            'backup_create',
            'security_verification',
            'audit_export',
        ],
        'return_accepted_response' => true,
        'accepted_status_code' => 202,
        'include_job_id' => true,
        'include_status_url' => true,
    ],

    'retry' => [
        'enabled' => true,
        'max_attempts' => 3,
        'backoff' => 'exponential',
        'initial_delay_seconds' => 5,
        'max_delay_seconds' => 300,
        'jitter' => true,
    ],

    'dead_letter' => [
        'enabled' => true,
        'queue' => 'failed',
        'store_payload' => true,
        'redact_payload' => true,
    ],

    'idempotency' => [
        'enabled' => true,
        'ttl_seconds' => 86400,
        'dedupe_window_seconds' => 300,
        'require_for_critical_jobs' => true,
    ],

    'workers' => [
        'max_jobs_per_worker' => 500,
        'max_runtime_seconds' => 3600,
        'sleep_seconds' => 1,
        'memory_profile' => 'queue_worker',
        'throughput_profile' => 'queue_worker',
        'heartbeat_seconds' => 30,
        'stop_on_memory_growth' => true,
    ],

    'payload_security' => [
        'redact_secrets' => true,
        'deny_raw_filesystem_paths' => true,
        'deny_password_fields' => true,
        'deny_tokens' => true,
        'max_depth' => 16,
        'max_string_bytes' => 8192,
    ],

    'release_gate' => [
        'enabled' => true,
        'block_on_failed_jobs' => false,
        'block_on_dead_letter_growth' => true,
        'block_on_queue_overload' => true,
        'block_on_missing_handlers' => true,
    ],
],
```

---

## 5. SecurityKernel usage

Create the kernel from your security config:

```php
use Mnb\SecureCore\Core\SecurityKernel;

$config = require __DIR__ . '/../config/security.php';
$kernel = new SecurityKernel($config);
```

Common accessors:

```php
$policy = $kernel->queuePolicy();
$dispatcher = $kernel->jobDispatcher();
$registry = $kernel->jobHandlerRegistry();
$worker = $kernel->queueWorker();
$asyncResponses = $kernel->asyncResponseFactory();
$statusResponses = $kernel->jobStatusResponseFactory();
```

---

## 6. Async request/response pattern

Long-running operations should return a `202 Accepted` response instead of blocking the HTTP request.

Example controller:

```php
public function exportUsers(Request $request): Response
{
    $userId = $request->user()->id;

    $dispatch = $this->security->jobDispatcher()->dispatch(
        name: 'database_export',
        payload: [
            'export_type' => 'users',
            'requested_by' => $userId,
        ],
        queue: 'exports',
        idempotencyKey: 'export:users:' . $userId . ':' . date('Y-m-d')
    );

    return $this->security->asyncResponseFactory()->accepted($dispatch);
}
```

Example response:

```json
{
  "status": true,
  "message": "Job accepted.",
  "job_id": "job_abc123",
  "job_status": "queued",
  "status_url": "/jobs/job_abc123"
}
```

Use this approach for:

- file scans
- exports
- backup creation
- report generation
- large document processing
- security verification runs

---

## 7. Job status endpoint

Expose a safe job status endpoint to let the frontend poll.

```php
public function jobStatus(string $jobId): Response
{
    $response = $this->security
        ->jobStatusResponseFactory()
        ->forJobId($jobId);

    return $response;
}
```

Safe status responses should not expose:

- raw payload secrets
- private filesystem paths
- exception stack traces
- internal worker hostnames
- raw user PII

Recommended public fields:

```json
{
  "job_id": "job_abc123",
  "status": "running",
  "queue": "exports",
  "attempts": 1,
  "created_at": "2026-07-01T10:00:00+05:30",
  "updated_at": "2026-07-01T10:00:15+05:30"
}
```

---

## 8. Idempotency and duplicate job protection

Use idempotency keys for operations that users may submit multiple times.

Examples:

```php
'idempotencyKey' => 'file_scan:' . $fileId
'idempotencyKey' => 'backup:create:' . date('Y-m-d')
'idempotencyKey' => 'webhook:' . $eventId
'idempotencyKey' => 'export:' . $userId . ':' . $exportType
```

Duplicate job guard behavior:

```text
same idempotency key within dedupe window
    ↓
return existing queued/running job
    ↓
do not create duplicate job
```

This prevents:

- double-click duplicate exports
- browser retry duplicate dispatch
- duplicate webhook delivery
- repeated file scan requests

---

## 9. Payload security

Queue payloads should be small and reference-based.

Good payload:

```php
[
    'file_id' => 'file_123',
    'requested_by' => 'user_456',
]
```

Bad payload:

```php
[
    'file_contents' => $largeBinaryFile,
    'password' => 'plain-text-password',
    'api_token' => 'secret-token',
    'path' => '/var/private/uploads/raw/document.pdf',
]
```

The queue engine can redact or block unsafe payload fields using:

```php
use Mnb\SecureCore\Queue\JobPayloadProtector;
use Mnb\SecureCore\Queue\JobPayloadRedactor;
```

Example:

```php
$payload = [
    'user_id' => 42,
    'password' => 'secret',
    'file_id' => 'file_abc',
];

$protected = $kernel->jobPayloadProtector()->protect($payload);
```

Expected result:

```php
[
    'user_id' => 42,
    'password' => '[redacted]',
    'file_id' => 'file_abc',
]
```

Depending on policy, unsafe fields can be blocked instead of redacted.

---

## 10. Retry policy

The retry system controls how failed jobs are retried.

```php
use Mnb\SecureCore\Queue\RetryPolicy;
use Mnb\SecureCore\Queue\BackoffStrategy;
use Mnb\SecureCore\Queue\RetryDecision;
```

Recommended behavior:

```text
attempt 1 failed → retry after 5 seconds
attempt 2 failed → retry after 20 seconds
attempt 3 failed → move to dead-letter queue
```

Do not retry non-retryable failures such as:

- authorization failure
- validation failure
- unknown job handler
- payload security failure
- blocked outbound URL
- blocked runtime command
- schema policy violation

Example:

```php
$decision = $kernel->retryPolicy()->decide(
    attempts: 2,
    errorCode: 'NETWORK_TIMEOUT'
);

if ($decision->shouldRetry()) {
    $delay = $decision->delaySeconds();
}
```

---

## 11. Dead-letter queue

Jobs that permanently fail should move to a dead-letter queue.

Dead-letter records should include:

- job ID
- job name
- queue
- attempts
- safe failure reason
- redacted payload
- failed timestamp
- safe exception class

They should not include:

- raw secrets
- tokens
- passwords
- private file contents
- stack traces in public output

Example CLI:

```bash
php bin/mnb-secure queue:dead-letter
```

Retry from dead-letter only after fixing the cause:

```bash
php bin/mnb-secure queue:retry job_abc123
```

---

## 12. Worker strategy

Workers process queued jobs.

```php
use Mnb\SecureCore\Queue\Worker;
use Mnb\SecureCore\Queue\WorkerConfig;
use Mnb\SecureCore\Queue\WorkerSupervisor;
use Mnb\SecureCore\Queue\WorkerHeartbeat;
```

Run one job:

```bash
php bin/mnb-secure queue:work default --once
```

Run a limited batch:

```bash
php bin/mnb-secure queue:work files --max-jobs=10
```

Recommended worker controls:

- max jobs per worker
- max runtime seconds
- heartbeat interval
- memory profile
- throughput profile
- stop on memory growth
- controlled retry handling
- resource cleanup after each job

Worker code pattern:

```php
$worker = $kernel->queueWorker();
$worker->work(queue: 'files', maxJobs: 10);
```

---

## 13. Worker supervision

The queue engine integrates with memory and throughput protection.

Worker supervision should check:

- memory growth
- peak memory
- job count
- stale heartbeat
- job timeout
- queue pressure
- resource cleanup

Example:

```php
$report = $kernel->workerSupervisor()->check();

if ($report->restartRecommended()) {
    // Stop the worker gracefully and let process manager restart it.
}
```

Recommended production process managers:

- Supervisor
- systemd
- Docker restart policy
- Kubernetes worker deployment
- hosting cron for simple shared-hosting workflows

---

## 14. Queue pressure and release gate

The queue engine can detect overloaded queues.

```php
$report = $kernel->queuePressureGuard()->check('exports');

if ($report->isCritical()) {
    // Block new exports, return 429/503, or defer lower-priority jobs.
}
```

Release gate should block production release when:

- required handlers are missing
- dead-letter queue is growing
- queue depth is critical
- workers are stale
- failed job rate is too high

CLI:

```bash
php bin/mnb-secure queue:release-gate
```

---

## 15. Integration with other MNB Secure Core engines

### 15.1 File security

File scanning should be queued for larger uploads.

```php
$kernel->jobDispatcher()->dispatch(
    name: 'file_scan',
    payload: ['file_id' => $fileId],
    queue: 'files',
    idempotencyKey: 'file_scan:' . $fileId
);
```

### 15.2 Database exports

Large exports should not run synchronously.

```php
$kernel->jobDispatcher()->dispatch(
    name: 'database_export',
    payload: ['export_id' => $exportId],
    queue: 'exports',
    idempotencyKey: 'export:' . $exportId
);
```

### 15.3 Webhooks

Webhook dispatch should use the queue plus `OutboundHttpClient`.

```php
$kernel->jobDispatcher()->dispatch(
    name: 'webhook_dispatch',
    payload: ['webhook_id' => $webhookId],
    queue: 'webhooks',
    idempotencyKey: 'webhook:' . $eventId
);
```

### 15.4 Incident response

Incident workflows may dispatch background containment tasks.

Examples:

- revoke user sessions
- move file to quarantine
- run verification profile
- notify security team
- export evidence bundle

### 15.5 Token/session security

Queue workers should not trust stale user/session context blindly.

Store minimal job context and re-check permissions when needed.

---

## 16. CLI reference

Show queue policy:

```bash
php bin/mnb-secure queue:policy
```

Dispatch test job:

```bash
php bin/mnb-secure queue:dispatch test_job
```

Run one job:

```bash
php bin/mnb-secure queue:work default --once
```

Run a batch:

```bash
php bin/mnb-secure queue:work files --max-jobs=10
```

Check job status:

```bash
php bin/mnb-secure queue:status job_abc123
```

List failed jobs:

```bash
php bin/mnb-secure queue:failed
```

Retry failed job:

```bash
php bin/mnb-secure queue:retry job_abc123
```

Show dead-letter queue:

```bash
php bin/mnb-secure queue:dead-letter
```

Show metrics:

```bash
php bin/mnb-secure queue:metrics
```

Check queue pressure:

```bash
php bin/mnb-secure queue:pressure
```

List registered handlers:

```bash
php bin/mnb-secure queue:handlers
```

Run release gate:

```bash
php bin/mnb-secure queue:release-gate
```

---

## 17. Demo

Run the queue demo:

```bash
php demos/38-async-request-response-queue-background-job-engine.php
```

Or run all demos:

```bash
php demos/run-all-demos.php
```

The demo covers:

- queue policy loading
- safe job dispatch
- async response creation
- duplicate job blocking
- unknown handler rejection
- payload redaction/blocking
- worker one-job processing
- retry policy
- dead-letter handling
- queue pressure report
- worker supervision
- release gate

---

## 18. Testing examples

Run full tests:

```bash
php tests/run-tests.php
```

Recommended tests for queue integration:

```php
public function testDuplicateDispatchReturnsExistingJob(): void
{
    $first = $this->kernel->jobDispatcher()->dispatch(
        name: 'file_scan',
        payload: ['file_id' => 'file_1'],
        queue: 'files',
        idempotencyKey: 'file_scan:file_1'
    );

    $second = $this->kernel->jobDispatcher()->dispatch(
        name: 'file_scan',
        payload: ['file_id' => 'file_1'],
        queue: 'files',
        idempotencyKey: 'file_scan:file_1'
    );

    $this->assertSame($first->jobId(), $second->jobId());
}
```

```php
public function testPayloadSecretsAreRedacted(): void
{
    $payload = [
        'user_id' => 1,
        'api_token' => 'secret-token',
    ];

    $safe = $this->kernel->jobPayloadRedactor()->redact($payload);

    $this->assertSame('[redacted]', $safe['api_token']);
}
```

```php
public function testUnknownHandlerIsRejected(): void
{
    $result = $this->kernel->jobDispatcher()->dispatch(
        name: 'unknown_job',
        payload: [],
        queue: 'default'
    );

    $this->assertFalse($result->accepted());
}
```

---

## 19. Production checklist

Before production, verify:

- [ ] Queue storage is durable enough for your app.
- [ ] In-memory queue is not used in production.
- [ ] Queue directories are outside public web root.
- [ ] Queue directories are writable by the application user only.
- [ ] Payload max size is configured.
- [ ] Secrets/tokens/passwords are blocked or redacted in payloads.
- [ ] Critical jobs require idempotency keys.
- [ ] Retry attempts are bounded.
- [ ] Exponential backoff or safe delay is enabled.
- [ ] Dead-letter queue is enabled.
- [ ] Dead-letter payloads are redacted.
- [ ] Worker memory profile is configured.
- [ ] Worker throughput profile is configured.
- [ ] Worker heartbeat is enabled.
- [ ] Queue release gate is enabled.
- [ ] Expensive operations are forced async.
- [ ] Unknown job handlers are blocked.
- [ ] Job status endpoint hides payload and internal exceptions.
- [ ] Queue runtime files are excluded from release ZIPs.

---

## 20. Common mistakes

### Mistake: Running exports during HTTP request

Bad:

```php
$csv = $exporter->generateHugeExport();
return new Response($csv);
```

Better:

```php
$dispatch = $kernel->jobDispatcher()->dispatch(
    name: 'database_export',
    payload: ['export_id' => $exportId],
    queue: 'exports',
    idempotencyKey: 'export:' . $exportId
);

return $kernel->asyncResponseFactory()->accepted($dispatch);
```

---

### Mistake: Storing full file content in queue payload

Bad:

```php
$dispatcher->dispatch('file_scan', [
    'contents' => file_get_contents($path),
]);
```

Better:

```php
$dispatcher->dispatch('file_scan', [
    'file_id' => $fileId,
]);
```

---

### Mistake: Infinite retries

Bad:

```text
retry forever every second
```

Better:

```text
3 attempts + exponential backoff + dead-letter queue
```

---

### Mistake: Trusting job context forever

Bad:

```php
// user had permission when job was queued, so always allow
```

Better:

```php
// re-check authorization for sensitive execution when the worker runs
```

---

### Mistake: Public job status leaks payload

Bad:

```json
{
  "payload": {
    "api_token": "secret"
  }
}
```

Better:

```json
{
  "job_id": "job_abc123",
  "status": "running"
}
```

---

## 21. Recommended architecture

A production app should use this pattern:

```text
HTTP controller
    ↓
validate/authenticate/authorize request
    ↓
dispatch background job with idempotency key
    ↓
return 202 Accepted + job_id
    ↓
worker reserves job
    ↓
handler re-checks sensitive authorization if needed
    ↓
handler uses safe subsystems
    ↓
job succeeds, retries, or dead-letters
    ↓
status endpoint reports safe progress
```

Safe subsystems include:

- `SafeProcessRunner` for runtime commands
- `OutboundHttpClient` for webhooks/API calls
- `SecureDatabase` for database operations
- `MemoryGuard` for large processing
- `ThroughputPolicy` for capacity checks
- `SafeErrorHandler` for failures
- `AuditTrail` for security records

---

## 22. Related documentation

Read these docs with this feature:

- `docs/throughput-and-performance-capacity-management.md`
- `docs/memory-management-and-resource-safety.md`
- `docs/error-handling-safe-error-responses-and-hidden-technical-logs.md`
- `docs/token-revocation-and-session-control.md`
- `docs/logging-audit-and-monitoring.md`
- `docs/backup-recovery-and-incident-response.md`
- `docs/vulnerability-blocking-matrix.md`

---

## 23. Summary

The Queue and Background Job Strategy gives MNB Secure Core a safe async execution model.

It helps applications:

- avoid long-running requests
- dispatch work safely
- prevent duplicate jobs
- control retries
- handle permanent failures
- supervise workers
- protect job payloads
- monitor queue pressure
- block risky releases

Use it whenever work is slow, expensive, retryable, or unsafe to run directly inside the HTTP request.
