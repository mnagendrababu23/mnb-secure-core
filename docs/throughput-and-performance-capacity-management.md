# Throughput and Performance Capacity Management

**Package:** `mnb/mnb-secure-core`  
**Version line:** `MNB Secure Core v1.0.1`  
**Document type:** Detailed feature documentation and code usage  
**Feature area:** Throughput governance, latency budgets, concurrency limiting, adaptive throttling, queue pressure monitoring, SLO evaluation, degradation policy, safe load simulation, performance release gates, and capacity risk reporting.

---

## 1. Overview

The **Throughput and Performance Capacity Management** layer protects applications from performance denial-of-service, uncontrolled concurrency, queue overload, slow expensive operations, worker saturation, and unsafe production releases without capacity proof.

This feature answers practical production questions:

```text
How many requests per second should this route handle?
How slow is too slow for this operation?
Should this operation run now, be throttled, be queued, or be degraded?
How many concurrent file scans or exports are allowed?
Is the queue overloaded?
Are performance SLOs passing?
Can this version safely go to production?
```

This module works together with:

```text
Memory Governance and Resource Safety
Async Request, Response Queue, and Background Job Orchestration
API Security and Rate Limiting
Secure Database Governance
Runtime Execution and Outbound Network Security
Safe Error Responses and Hidden Technical Logs
Security Verification and Release Gates
```

The goal is not to make slow code fast by magic. The goal is to **detect overload early, enforce operation-specific budgets, apply backpressure, protect critical features, and keep the application stable under real traffic**.

---

## 2. What this module protects against

This module helps reduce risk from:

```text
Performance DoS
Capacity exhaustion
Concurrency exhaustion
Queue overload
Worker saturation
Slowloris-style capacity abuse
Expensive operation abuse
Large export/report abuse
Backup job overload
Webhook dispatch backlog
File scan saturation
Database export overload
Cache miss storms
Failed SLO production releases
Missing capacity gates
```

It is useful for:

```text
API requests
Login requests
File uploads and malware scans
Database exports
Audit exports
Backup jobs
Webhook dispatch
Queue workers
Security verification runs
Admin reports
Bulk operations
Public APIs
Mobile APIs
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

If you publish or copy the default config, the main configuration file is usually:

```text
vendor/mnb/mnb-secure-core/config/security.php
```

In a real application, copy it into your app config area and load it from there.

---

## 4. Main classes

Core throughput classes:

```text
Mnb\SecurityCore\Throughput\ThroughputConfig
Mnb\SecurityCore\Throughput\ThroughputMeter
Mnb\SecurityCore\Throughput\ThroughputMonitor
Mnb\SecurityCore\Throughput\ThroughputPlanner
Mnb\SecurityCore\Throughput\ThroughputSample
```

Governance classes:

```text
Mnb\SecurityCore\Throughput\ThroughputPolicy
Mnb\SecurityCore\Throughput\OperationThroughputProfile
Mnb\SecurityCore\Throughput\ThroughputBudget
Mnb\SecurityCore\Throughput\ThroughputBudgetDecision
Mnb\SecurityCore\Throughput\LatencyBudget
Mnb\SecurityCore\Throughput\LatencyBudgetRegistry
```

Concurrency and throttling:

```text
Mnb\SecurityCore\Throughput\ConcurrencyLimiter
Mnb\SecurityCore\Throughput\ConcurrencyToken
Mnb\SecurityCore\Throughput\InMemoryConcurrencyStore
Mnb\SecurityCore\Throughput\FileConcurrencyStore
Mnb\SecurityCore\Throughput\AdaptiveThrottle
Mnb\SecurityCore\Throughput\ThrottleDecision
Mnb\SecurityCore\Throughput\BackpressureController
```

Queue pressure and capacity:

```text
Mnb\SecurityCore\Throughput\QueueBacklogPolicy
Mnb\SecurityCore\Throughput\QueuePressureMonitor
Mnb\SecurityCore\Throughput\QueueCapacityPlanner
```

Metrics and SLOs:

```text
Mnb\SecurityCore\Throughput\PerformanceSampleStore
Mnb\SecurityCore\Throughput\RollingWindowMetrics
Mnb\SecurityCore\Throughput\PercentileCalculator
Mnb\SecurityCore\Throughput\PerformanceSlo
Mnb\SecurityCore\Throughput\SloEvaluator
Mnb\SecurityCore\Throughput\SloReport
```

Degradation and release safety:

```text
Mnb\SecurityCore\Throughput\DegradationPolicy
Mnb\SecurityCore\Throughput\DegradationDecision
Mnb\SecurityCore\Throughput\FeatureLoadShedder
Mnb\SecurityCore\Throughput\CapacityRiskAnalyzer
Mnb\SecurityCore\Throughput\CapacityReport
Mnb\SecurityCore\Throughput\BottleneckDetector
Mnb\SecurityCore\Throughput\SafeLoadSimulator
Mnb\SecurityCore\Throughput\PerformanceReleaseGate
```

HTTP integration:

```text
Mnb\SecurityCore\Http\Middleware\ThroughputMiddleware
```

---

## 5. Recommended configuration

The default `throughput` config provides global limits and operation-specific profiles.

```php
return [
    'throughput' => [
        'enabled' => true,

        'target_rps' => (float)(getenv('THROUGHPUT_TARGET_RPS') ?: 50),
        'warning_latency_ms' => (int)(getenv('THROUGHPUT_WARNING_LATENCY_MS') ?: 750),
        'critical_latency_ms' => (int)(getenv('THROUGHPUT_CRITICAL_LATENCY_MS') ?: 2000),
        'max_concurrency' => (int)(getenv('THROUGHPUT_MAX_CONCURRENCY') ?: 25),
        'queue_warning_depth' => (int)(getenv('THROUGHPUT_QUEUE_WARNING_DEPTH') ?: 1000),
        'sample_window_seconds' => (int)(getenv('THROUGHPUT_SAMPLE_WINDOW_SECONDS') ?: 60),
        'emit_headers' => true,
        'block_critical_latency' => false,

        'profiles' => [
            'api_request' => [
                'enabled' => true,
                'target_rps' => 100,
                'warning_latency_ms' => 500,
                'critical_latency_ms' => 1500,
                'max_concurrency' => 50,
                'degrade_on_overload' => true,
            ],

            'login' => [
                'enabled' => true,
                'target_rps' => 25,
                'warning_latency_ms' => 500,
                'critical_latency_ms' => 1200,
                'max_concurrency' => 10,
                'degrade_on_overload' => false,
            ],

            'file_scan' => [
                'enabled' => true,
                'target_rps' => 10,
                'warning_latency_ms' => 5000,
                'critical_latency_ms' => 15000,
                'max_concurrency' => 3,
                'require_queue_above_ms' => 5000,
            ],

            'database_export' => [
                'enabled' => true,
                'target_rps' => 5,
                'warning_latency_ms' => 3000,
                'critical_latency_ms' => 10000,
                'max_concurrency' => 2,
                'require_queue' => true,
            ],

            'webhook_dispatch' => [
                'enabled' => true,
                'target_rps' => 20,
                'warning_latency_ms' => 1000,
                'critical_latency_ms' => 3000,
                'max_concurrency' => 5,
            ],

            'backup_create' => [
                'enabled' => true,
                'target_rps' => 1,
                'warning_latency_ms' => 10000,
                'critical_latency_ms' => 60000,
                'max_concurrency' => 1,
                'require_queue' => true,
            ],
        ],

        'concurrency' => [
            'enabled' => true,
            'store' => getenv('THROUGHPUT_CONCURRENCY_STORE') ?: 'file',
            'lock_path' => getenv('THROUGHPUT_CONCURRENCY_LOCK_PATH') ?: __DIR__ . '/../storage/cache/concurrency',
            'token_ttl_seconds' => (int)(getenv('THROUGHPUT_CONCURRENCY_TOKEN_TTL') ?: 120),
            'fail_closed' => true,
        ],

        'adaptive_throttle' => [
            'enabled' => true,
            'overload_p95_ratio' => 1.0,
            'queue_depth_ratio' => 1.0,
            'return_status' => 429,
            'retry_after_seconds' => 30,
        ],

        'queue_pressure' => [
            'enabled' => true,
            'warning_depth' => 1000,
            'critical_depth' => 5000,
            'warning_oldest_job_seconds' => 300,
            'critical_oldest_job_seconds' => 1800,
        ],

        'slo' => [
            'enabled' => true,
            'minimum_pass_percent' => 95,
            'objectives' => [
                'api_request' => [
                    'p95_ms' => 750,
                    'p99_ms' => 2000,
                    'error_rate_percent' => 1,
                ],
                'database_export' => [
                    'queue_drain_seconds' => 600,
                    'sync_execution_allowed' => false,
                ],
            ],
        ],

        'degradation' => [
            'enabled' => true,
            'allow_cache_fallback' => true,
            'allow_queue_deferral' => true,
            'disable_non_critical_features' => true,
            'protected_features' => [
                'login',
                'csrf',
                'audit',
                'security_alerts',
                'authorization',
                'rate_limiting',
            ],
        ],

        'release_gate' => [
            'enabled' => true,
            'block_on_critical_capacity' => true,
            'block_on_failed_slo' => true,
            'block_on_missing_profiles' => false,
        ],
    ],
];
```

---

## 6. Operation profiles

A throughput profile defines the performance and concurrency budget for a type of work.

Examples:

| Profile | Typical use | Important rule |
|---|---|---|
| `api_request` | Normal API request | Low latency, larger concurrency |
| `login` | Authentication route | Strict latency, low concurrency |
| `file_scan` | Malware/document scanning | Low concurrency, longer latency |
| `database_export` | Large export | Queue required |
| `webhook_dispatch` | External callback delivery | Moderate concurrency, timeout-aware |
| `backup_create` | Backup creation | Queue required, one at a time |

Use stricter profiles for risky operations. A database export should not share the same budget as a lightweight health check.

---

## 7. Basic kernel setup

```php
use Mnb\SecurityCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

Access throughput services:

```php
$policy = $kernel->throughputPolicy();
$limiter = $kernel->concurrencyLimiter();
$throttle = $kernel->adaptiveThrottle();
$queueMonitor = $kernel->queuePressureMonitor();
$sloEvaluator = $kernel->sloEvaluator();
$releaseGate = $kernel->performanceReleaseGate();
```

---

## 8. Measuring operation throughput

Use `ThroughputMeter` when you want to measure the runtime of a block of code.

```php
use Mnb\SecurityCore\Throughput\ThroughputConfig;
use Mnb\SecurityCore\Throughput\ThroughputMeter;

$config = ThroughputConfig::fromArray([
    'target_rps' => 50,
    'warning_latency_ms' => 750,
    'critical_latency_ms' => 2000,
    'emit_headers' => true,
]);

$meter = new ThroughputMeter($config);

$result = $meter->measure('api_request:list_students', function () {
    // Run controller/service/database work here.
    return ['students' => []];
});

print_r($result);
```

The result contains the operation output and a sample with useful metrics:

```text
label
duration_ms
units
throughput_per_second
status
metadata
started_at
finished_at
```

---

## 9. Creating a throughput sample manually

```php
use Mnb\SecurityCore\Throughput\ThroughputSample;

$sample = ThroughputSample::fromDuration(
    label: 'database_export',
    durationMs: 4200,
    units: 1,
    status: 'ok',
    metadata: [
        'rows' => 25000,
        'queued' => true,
    ]
);

print_r($sample->toArray());
```

Manual samples are useful for workers, CLI jobs, queues, exports, and background operations.

---

## 10. Evaluating a profile budget

Use `ThroughputPolicy` to check whether an operation is within its budget.

```php
$policy = $kernel->throughputPolicy();

$decision = $policy->evaluate(
    profile: 'api_request',
    sampleOrDuration: 620.0,
    queued: false
);

print_r($decision->toArray());
```

Possible decision statuses:

```text
ok
warning
critical
queued
degraded
```

Possible actions:

```text
allow
warn
throttle
queue
degrade
reject
```

Example handling:

```php
if (!$decision->allowed()) {
    if ($decision->action() === 'queue') {
        // Dispatch to queue instead of running synchronously.
    }

    if ($decision->action() === 'throttle') {
        // Return 429 or 503 with Retry-After.
    }
}
```

---

## 11. Latency budget usage

Use `LatencyBudget` when you want to evaluate only the runtime of one operation.

```php
use Mnb\SecurityCore\Throughput\LatencyBudget;

$profile = $kernel->throughputPolicy()->profile('login');
$budget = LatencyBudget::fromProfile($profile);

$decision = $budget->evaluate(900, [
    'route' => 'POST /login',
]);

print_r($decision->toArray());
```

For a `login` profile with a warning threshold of `500ms` and a critical threshold of `1200ms`, a `900ms` request should produce a warning-level decision.

---

## 12. Concurrency limiting

Concurrency limits prevent too many expensive operations from running at once.

```php
$limiter = $kernel->concurrencyLimiter();
$token = $limiter->acquire('file_scan');

try {
    // Run the file scan here.
} finally {
    $token->release();
}
```

For a non-throwing style:

```php
$result = $kernel->concurrencyLimiter()->tryAcquire('database_export');

if (!$result['allowed']) {
    // Return 429, 503, or dispatch to queue.
    return [
        'status' => false,
        'message' => 'Too many exports are already running.',
    ];
}

$token = $result['token'];

try {
    // Export work here.
} finally {
    $token->release();
}
```

Use concurrency limits for:

```text
file_scan
database_export
backup_create
webhook_dispatch
security_verification
audit_export
large_report
```

---

## 13. Adaptive throttling

Adaptive throttling converts current capacity signals into decisions.

```php
$decision = $kernel->adaptiveThrottle()->decide('api_request', [
    'p95_ms' => 1800,
    'queue_depth' => 1200,
    'error_rate_percent' => 1.5,
]);

print_r($decision->toArray());
```

A high p95 latency or queue depth can return a decision such as:

```json
{
  "status": "critical",
  "allowed": false,
  "action": "throttle",
  "reason": "p95_latency_over_budget",
  "retry_after_seconds": 30
}
```

Use this decision before expensive operations:

```php
$decision = $kernel->adaptiveThrottle()->decide('database_export', $metrics);

if (!$decision->allowed()) {
    return [
        'status' => false,
        'message' => 'The system is busy. Please try again later.',
        'retry_after_seconds' => $decision->retryAfterSeconds(),
    ];
}
```

---

## 14. Backpressure controller

The backpressure controller combines throttling and degradation rules.

```php
$controller = $kernel->backpressureController();

$decision = $controller->decide('api_request', 'report_generation', [
    'p95_ms' => 1800,
    'queue_depth' => 1500,
]);

print_r($decision->toArray());
```

Common backpressure responses:

```text
allow request
warn but continue
serve cached result
queue the work
throttle with Retry-After
disable a non-critical feature temporarily
reject safely
```

Protected features should not be disabled:

```text
login
csrf
audit
security_alerts
authorization
rate_limiting
```

---

## 15. Queue pressure monitoring

Queue pressure monitoring tells you whether workers can keep up.

```php
$report = $kernel->queuePressureMonitor()->report(
    queueDepth: 1200,
    workerCount: 10,
    averageJobMs: 250,
    oldestJobSeconds: 420
);

print_r($report);
```

Typical report fields:

```text
status
queue_depth
worker_count
average_job_ms
oldest_job_seconds
estimated_drain_seconds
recommended_workers
reason
```

Use queue pressure in:

```text
queue dashboards
admin health checks
release gates
worker scaling decisions
security verification batches
backup/export scheduling
```

---

## 16. Queue capacity planning

Use `QueueCapacityPlanner` to estimate worker requirements.

```php
$planner = $kernel->queueCapacityPlanner();

$plan = $planner->plan(
    targetRps: 20,
    averageJobMs: 300,
    queueDepth: 500
);

print_r($plan);
```

Use this to answer:

```text
How many workers do we need?
How long will the current backlog take to drain?
Is the queue approaching danger?
Should new jobs be delayed?
```

---

## 17. Rolling window metrics

Use the sample store and rolling metrics for p95/p99 style calculations.

```php
use Mnb\SecurityCore\Throughput\ThroughputSample;

$store = $kernel->performanceSampleStore();

$store->record(ThroughputSample::fromDuration('api_request', 120));
$store->record(ThroughputSample::fromDuration('api_request', 480));
$store->record(ThroughputSample::fromDuration('api_request', 900));

$metrics = $store->metrics('api_request')->toArray();

print_r($metrics);
```

Metrics can include:

```text
count
average_ms
p50_ms
p90_ms
p95_ms
p99_ms
max_ms
error_rate
```

Use rolling metrics for SLOs, dashboards, throttling, and release gates.

---

## 18. SLO evaluation

SLOs define the performance goals your app must meet.

```php
$metrics = [
    'api_request' => [
        'p95_ms' => 680,
        'p99_ms' => 1500,
        'error_rate_percent' => 0.4,
    ],
    'database_export' => [
        'queue_drain_seconds' => 420,
        'sync_execution_allowed' => false,
    ],
];

$report = $kernel->sloEvaluator()->evaluate($metrics);

print_r($report->toArray());
```

A passing SLO report can be used in CI/CD and production release gates. A failed SLO should block release when `block_on_failed_slo` is enabled.

---

## 19. Degradation policy

Degradation policy decides what can be reduced or deferred under pressure.

```php
$decision = $kernel->degradationPolicy()->decide(
    feature: 'report_generation',
    pressure: 'critical'
);

print_r($decision->toArray());
```

Examples:

| Feature | During overload |
|---|---|
| Login | Keep protected, do not disable |
| CSRF | Keep protected, do not disable |
| Audit | Keep protected, do not disable |
| Reports | Queue or disable temporarily |
| Exports | Queue only |
| Analytics | Disable temporarily |
| Preview generation | Disable or defer |

Use `FeatureLoadShedder` when you want a simple feature-level decision:

```php
$shedder = $kernel->featureLoadShedder();
$decision = $shedder->evaluate('analytics', 'critical');
```

---

## 20. Capacity risk analysis

Capacity risk analysis identifies the likely bottleneck.

```php
$report = $kernel->capacityRiskAnalyzer()->analyze([
    'profile' => 'api_request',
    'p95_ms' => 1800,
    'queue_depth' => 2500,
    'worker_count' => 5,
    'max_concurrency' => 50,
    'active_concurrency' => 49,
]);

print_r($report->toArray());
```

Possible bottlenecks:

```text
concurrency_limit
queue_pressure
latency_budget
worker_shortage
slo_failure
database_export_overload
external_api_slowdown
memory_pressure
cache_miss_storm
```

Capacity reports should include remediation advice such as:

```text
increase workers
reduce max page size
force export to queue
enable cache fallback
lower concurrency for expensive task
investigate slow database query
review external API latency
```

---

## 21. Safe load simulation

Safe load simulation estimates capacity without generating abusive real traffic.

```php
$profile = $kernel->loadTestProfile(
    profile: 'api_request',
    targetRps: 100,
    averageLatencyMs: 750,
    durationSeconds: 60
);

$result = $kernel->safeLoadSimulator()->simulate($profile);

print_r($result->toArray());
```

Use this for planning:

```text
expected concurrency
risk status
bottlenecks
recommended workers
queue risk
SLO risk
```

This is not a replacement for real load testing. It is a safe planning model for security and release readiness.

---

## 22. Performance release gate

Use `PerformanceReleaseGate` before production deployment.

```php
$sloReport = $kernel->sloEvaluator()->evaluate([
    'api_request' => [
        'p95_ms' => 920,
        'p99_ms' => 2100,
        'error_rate_percent' => 1.4,
    ],
]);

$capacityReport = $kernel->capacityRiskAnalyzer()->analyze([
    'profile' => 'api_request',
    'p95_ms' => 920,
    'queue_depth' => 200,
]);

$gate = $kernel->performanceReleaseGate()->evaluate(
    sloReport: $sloReport,
    capacityReport: $capacityReport,
    missingProfiles: []
);

print_r($gate);
```

The gate should block release when:

```text
SLO failed
critical capacity risk exists
queue drain time is too high
required operation profile is missing
database export can still run synchronously
performance risk is not accepted
```

---

## 23. HTTP middleware usage

`ThroughputMiddleware` measures request latency and can add diagnostic headers.

```php
use Mnb\SecurityCore\Http\Middleware\ThroughputMiddleware;
use Mnb\SecurityCore\Throughput\ThroughputConfig;
use Mnb\SecurityCore\Throughput\ThroughputMeter;
use Mnb\SecurityCore\Throughput\ThroughputMonitor;

$config = ThroughputConfig::fromArray($securityConfig['throughput']);
$meter = new ThroughputMeter($config);
$monitor = new ThroughputMonitor($config);

$middleware = new ThroughputMiddleware(
    meter: $meter,
    monitor: $monitor,
    label: 'api_request'
);
```

Typical middleware order:

```text
Request ID / Trust / Host / Origin
    ↓
Secure Request Receiving
    ↓
Rate Limiting
    ↓
Authentication / Token Revocation
    ↓
Authorization / Tenant Boundary
    ↓
Throughput Middleware
    ↓
Controller
    ↓
Safe Error / Safe Response Handling
```

If `emit_headers` is enabled, responses may include:

```text
X-Throughput-Duration-MS
X-Throughput-Per-Second
X-Throughput-Status
```

For public production APIs, expose diagnostic headers carefully. They can be useful internally but may not be desired for all public routes.

---

## 24. API route example

```php
function listStudents(SecurityKernel $kernel): array
{
    $decision = $kernel->adaptiveThrottle()->decide('api_request', [
        'p95_ms' => 600,
        'queue_depth' => 100,
    ]);

    if (!$decision->allowed()) {
        return [
            'status' => false,
            'message' => 'The API is temporarily busy.',
            'retry_after_seconds' => $decision->retryAfterSeconds(),
        ];
    }

    $token = $kernel->concurrencyLimiter()->acquire('api_request');

    try {
        // Run service/database work.
        return [
            'status' => true,
            'data' => [],
        ];
    } finally {
        $token->release();
    }
}
```

---

## 25. Database export example

A database export should usually be queued, not run synchronously.

```php
$decision = $kernel->throughputPolicy()->evaluate(
    profile: 'database_export',
    sampleOrDuration: 1200,
    queued: false
);

if ($decision->action() === 'queue' || !$decision->allowed()) {
    $job = $kernel->jobDispatcher()->dispatch(
        name: 'database_export',
        payload: [
            'export_id' => $exportId,
            'requested_by' => $userId,
        ],
        queue: 'exports',
        idempotencyKey: 'database_export:' . $exportId
    );

    return $kernel->asyncResponseFactory()->accepted($job);
}
```

This combines:

```text
Throughput policy
Queue engine
Idempotency
Async 202 response
Memory-safe export profile
Audit logging
```

---

## 26. File scan example

```php
$token = $kernel->concurrencyLimiter()->acquire('file_scan');

try {
    $sample = $kernel->throughputPolicy()->evaluate(
        profile: 'file_scan',
        sampleOrDuration: 6000,
        queued: false
    );

    if ($sample->action() === 'queue') {
        // Dispatch file scan to queue.
    }

    // Run guarded scan or queue it.
} finally {
    $token->release();
}
```

File scanning should be limited because malware scanning, archive inspection, and document parsing can consume CPU, memory, and IO.

---

## 27. Webhook dispatch example

```php
$decision = $kernel->adaptiveThrottle()->decide('webhook_dispatch', [
    'p95_ms' => 1200,
    'queue_depth' => 700,
]);

if (!$decision->allowed()) {
    // Queue webhook delivery instead of sending immediately.
}

$token = $kernel->concurrencyLimiter()->acquire('webhook_dispatch');

try {
    $kernel->outboundHttpClient()->postJson($url, $payload);
} finally {
    $token->release();
}
```

This combines throughput control with SSRF-safe outbound HTTP.

---

## 28. CLI usage

Existing commands:

```bash
php bin/mnb-secure throughput:check
php bin/mnb-secure throughput:plan
```

Governance commands:

```bash
php bin/mnb-secure throughput:policy
php bin/mnb-secure throughput:profile api_request
php bin/mnb-secure throughput:budget api_request 1200 1
php bin/mnb-secure throughput:concurrency api_request
php bin/mnb-secure throughput:throttle api_request 1800 55
php bin/mnb-secure throughput:queue 1200 10 250
php bin/mnb-secure throughput:slo
php bin/mnb-secure throughput:capacity-risk
php bin/mnb-secure throughput:simulate api_request 100 750
php bin/mnb-secure performance:release-gate
```

Useful examples:

```bash
# Show complete throughput policy
php bin/mnb-secure throughput:policy

# Inspect one operation profile
php bin/mnb-secure throughput:profile database_export

# Check budget decision for 1200ms API request
php bin/mnb-secure throughput:budget api_request 1200 1

# Check concurrency state for file scans
php bin/mnb-secure throughput:concurrency file_scan

# Simulate API request load
php bin/mnb-secure throughput:simulate api_request 100 750

# Check release readiness from performance side
php bin/mnb-secure performance:release-gate
```

---

## 29. Demo file

Related demo:

```text
demos/36-throughput-governance-performance-capacity-engine.php
```

Run all demos:

```bash
php demos/run-all-demos.php
```

The demo should show:

```text
Throughput policy loading
Operation profile resolution
Latency budget decisions
Concurrency token acquire/release
Concurrency limit behavior
Adaptive throttle decisions
Queue pressure reports
SLO report generation
Capacity risk analysis
Safe load simulation
Performance release gate behavior
Vulnerability matrix coverage
```

---

## 30. Integration with queue/background jobs

Throughput management decides **whether work should run now**. The queue engine decides **how deferred work runs safely**.

Recommended pattern:

```text
Incoming request
    ↓
Throughput budget check
    ↓
If small and allowed → run now
If expensive or overloaded → dispatch job
    ↓
Return 202 Accepted
    ↓
Worker processes job with memory + concurrency + retry policies
```

Use queue deferral for:

```text
file_scan
database_export
backup_create
audit_export
security_verification
large_report
bulk_import
```

---

## 31. Integration with memory/resource safety

Throughput and memory should be configured together.

Example:

| Operation | Throughput control | Memory control |
|---|---|---|
| `file_scan` | max concurrency 3 | `upload_scan` memory profile |
| `database_export` | queue required | streaming/chunked export |
| `backup_create` | max concurrency 1 | temporary file budget |
| `queue_worker` | worker throughput | worker memory supervisor |

Do not increase concurrency without checking memory budget. More concurrent jobs can multiply memory usage.

---

## 32. Integration with rate limiting

Rate limiting controls **client request volume**.

Throughput controls **server capacity**.

Use both:

```text
Rate limiter says: this client is sending too many requests.
Throughput policy says: the whole system is overloaded.
```

Example:

```php
// First: per-user/per-IP rate limit.
// Then: global/operation-level throughput pressure.
$throttle = $kernel->adaptiveThrottle()->decide('api_request', $metrics);
```

A user can be under their personal rate limit while the system is still overloaded. In that case, throughput/backpressure should still protect the system.

---

## 33. Integration with database governance

Database search/export routes are common capacity risks.

Recommended rules:

```text
All searches must have max limit.
All filters must pass query complexity guard.
Large exports must be queued.
Expensive reports must use chunking.
Avoid fetchAll() for large datasets.
```

Example:

```php
$decision = $kernel->throughputPolicy()->evaluate('database_export', 1000, queued: false);

if (!$decision->allowed()) {
    // Queue export instead of blocking request thread.
}
```

---

## 34. Integration with production release gates

Before release, run:

```bash
php bin/mnb-secure throughput:slo
php bin/mnb-secure throughput:capacity-risk
php bin/mnb-secure performance:release-gate
php bin/mnb-secure final:gate
```

A release should be blocked when:

```text
Critical capacity risk exists
Required SLOs fail
Database export can still run synchronously
Queue drain time is too high
Critical operation has no profile
Concurrency store path is not writable
```

---

## 35. Audit events

The throughput engine can use these audit concepts:

```text
throughput.sample.recorded
throughput.budget.allowed
throughput.budget.warning
throughput.budget.critical
throughput.concurrency.acquired
throughput.concurrency.released
throughput.concurrency.blocked
throughput.throttle.allowed
throughput.throttle.blocked
throughput.queue_pressure.warning
throughput.queue_pressure.critical
throughput.slo.passed
throughput.slo.failed
throughput.degradation.applied
throughput.capacity_risk.detected
throughput.release_gate.passed
throughput.release_gate.blocked
```

Audit events should avoid logging sensitive request bodies, tokens, cookies, or raw PII.

---

## 36. Vulnerability matrix coverage

This feature improves coverage for:

```text
performance_dos
capacity_exhaustion
concurrency_exhaustion
queue_overload
slowloris_capacity_abuse
worker_saturation
database_export_overload
expensive_operation_abuse
missing_capacity_gate
failed_slo_release
```

Expected controls:

```text
ThroughputPolicy
OperationThroughputProfile
LatencyBudget
ConcurrencyLimiter
AdaptiveThrottle
BackpressureController
QueuePressureMonitor
SloEvaluator
DegradationPolicy
CapacityRiskAnalyzer
SafeLoadSimulator
PerformanceReleaseGate
```

Check matrix/report commands:

```bash
php bin/mnb-secure vulnerabilities:report
php bin/mnb-secure vulnerabilities:check performance_dos
php bin/mnb-secure vulnerabilities:check concurrency_exhaustion
php bin/mnb-secure vulnerabilities:check queue_overload
```

---

## 37. Testing examples

### 37.1 Profile resolves

```php
$profile = $kernel->throughputPolicy()->profile('api_request');

assert($profile->enabled() === true);
assert($profile->maxConcurrency() === 50);
```

### 37.2 Warning latency decision

```php
$decision = $kernel->throughputPolicy()->evaluate('api_request', 900);

assert($decision->status() === 'warning' || $decision->status() === 'critical');
```

### 37.3 Queue-required operation

```php
$decision = $kernel->throughputPolicy()->evaluate(
    profile: 'database_export',
    sampleOrDuration: 1000,
    queued: false
);

assert($decision->action() === 'queue');
```

### 37.4 Concurrency token release

```php
$limiter = $kernel->concurrencyLimiter();
$before = $limiter->activeCount('file_scan');

$token = $limiter->acquire('file_scan');
$during = $limiter->activeCount('file_scan');

$token->release();
$after = $limiter->activeCount('file_scan');

assert($during >= $before + 1);
assert($after <= $during);
```

### 37.5 Queue pressure warning

```php
$report = $kernel->queuePressureMonitor()->report(
    queueDepth: 1200,
    workerCount: 10,
    averageJobMs: 250,
    oldestJobSeconds: 100
);

assert(in_array($report['status'], ['ok', 'warning', 'critical'], true));
```

### 37.6 SLO failure

```php
$report = $kernel->sloEvaluator()->evaluate([
    'api_request' => [
        'p95_ms' => 1500,
        'p99_ms' => 3000,
        'error_rate_percent' => 2,
    ],
]);

assert($report->passed() === false);
```

---

## 38. Production checklist

Before enabling in production:

```text
Set realistic throughput profiles for every expensive operation.
Use file or external concurrency store for multi-process apps.
Ensure concurrency lock path is writable.
Keep login/auth/security features protected from degradation.
Force large exports and backups to queue.
Configure queue warning and critical depths.
Define SLO objectives for public APIs and admin-critical flows.
Enable performance release gate in CI/CD.
Monitor p95 and p99 latency, not only average latency.
Combine throughput with memory profiles.
Do not expose diagnostic throughput headers publicly unless intended.
Create alerts for critical queue pressure and SLO failures.
Run throughput CLI checks before release.
```

---

## 39. Common mistakes

### Mistake: using one global budget for everything

Bad:

```text
Every route gets 2000ms and 100 concurrency.
```

Better:

```text
Login: strict budget
API request: normal budget
File scan: low concurrency
Database export: queue required
Backup: one at a time
```

### Mistake: increasing concurrency without memory planning

More concurrency can make memory exhaustion worse.

Always check:

```text
max concurrency × memory per operation
```

### Mistake: only looking at average latency

Average latency hides tail problems. Track:

```text
p95
p99
max latency
error rate
queue drain time
```

### Mistake: running large exports synchronously

Large exports should return `202 Accepted` and be processed by queue workers.

### Mistake: disabling protected features during overload

Never degrade:

```text
authentication
authorization
CSRF
audit logging
security alerts
rate limiting
```

### Mistake: no release gate

Performance failures should block release just like security failures.

---

## 40. Recommended defaults

For small to medium PHP apps:

```text
api_request max concurrency: 25–50
login max concurrency: 5–10
file_scan max concurrency: 2–3
database_export max concurrency: 1–2, queue required
backup_create max concurrency: 1, queue required
webhook_dispatch max concurrency: 5
```

For shared hosting:

```text
Use lower concurrency values.
Force heavy work to queue.
Avoid long synchronous requests.
Use file concurrency store.
Limit exports and scans aggressively.
```

For VPS/dedicated servers:

```text
Tune based on CPU, memory, workers, database, and queue capacity.
Add real monitoring for p95/p99 and queue depth.
Use release gate before deployment.
```

---

## 41. Related documentation

```text
docs/api-security-and-rate-limiting.md
docs/memory-management-and-resource-safety.md
docs/async-request-response-queue-background-job-orchestration.md
docs/secure-database-connect-retrieval-update-delete-search-alter.md
docs/error-handling-safe-error-responses-and-hidden-technical-logs.md
docs/penetration-testing-security-verification-and-remediation.md
docs/vulnerability-blocking-matrix.md
```

---

## 42. Summary

The **Throughput and Performance Capacity Management** module gives `mnb-secure-core` a production safety layer for performance and capacity.

It helps you:

```text
Define operation-specific throughput profiles
Measure latency and throughput
Enforce latency budgets
Limit concurrency
Apply adaptive throttling
Monitor queue pressure
Evaluate SLOs
Degrade non-critical features safely
Analyze capacity risk
Simulate load safely
Block unsafe releases with a performance gate
```

Use this module whenever an operation can become slow, expensive, high-volume, or dangerous under load.
