<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Throughput\LoadTestProfile;
use Mnb\SecurityCore\Throughput\ThroughputSample;

demo_title('36. Throughput Governance and Performance Capacity Engine');

$config = require __DIR__ . '/../config/security.php';
$config['throughput']['concurrency']['store'] = 'memory';
$kernel = new SecurityKernel($config);

$policy = $kernel->throughputPolicy();
demo_step('Throughput policy loaded', array_keys($policy->profiles()));

$profile = $policy->profile('api_request');
demo_step('Operation profile resolved', $profile->toArray());

$fast = $policy->evaluate('api_request', ThroughputSample::fromDuration('api_request', 100));
$slow = $policy->evaluate('api_request', ThroughputSample::fromDuration('api_request', 800));
$critical = $policy->evaluate('database_export', ThroughputSample::fromDuration('database_export', 12000), false);
demo_step('Fast operation allowed', $fast->toArray());
demo_step('Slow operation warned', $slow->toArray());
demo_step('Queue-required operation is deferred by policy', $critical->toArray());

$limiterConfig = $config;
$limiterConfig['throughput']['profiles']['tiny_demo'] = ['max_concurrency' => 1, 'warning_latency_ms' => 10, 'critical_latency_ms' => 20];
$limiterConfig['throughput']['concurrency']['store'] = 'memory';
$limiter = (new SecurityKernel($limiterConfig))->concurrencyLimiter();
$token = $limiter->acquire('tiny_demo');
$blocked = !$limiter->tryAcquire('tiny_demo')['acquired'];
$token->release();
demo_step('Concurrency token acquired and released', $token->toArray());
demo_step('Concurrency limit blocks excess work', $blocked);

$queueReport = $kernel->queuePressureMonitor()->report(1200, 10, 250, 120);
demo_step('Queue pressure report generated', $queueReport);

$throttle = $kernel->adaptiveThrottle()->decide('api_request', ['p95_ms' => 1800, 'active_concurrency' => 55]);
demo_step('Adaptive throttle returns retry-after decision', $throttle->toArray());

$slo = $kernel->sloEvaluator()->evaluate([
    'api_request' => ['p95_ms' => 500, 'p99_ms' => 1400, 'error_rate_percent' => 0.1],
    'database_export' => ['queue_drain_seconds' => 300, 'sync_execution_allowed' => false],
]);
demo_step('SLO report generated', $slo->toArray());

$risk = $kernel->capacityRiskAnalyzer()->analyze([
    'p95_ms' => 2200,
    'critical_latency_ms' => 1500,
    'active_concurrency' => 50,
    'max_concurrency' => 50,
    'queue_depth' => 1200,
    'queue_warning_depth' => 1000,
]);
demo_step('Capacity risk report generated', $risk->toArray());

$simulation = $kernel->safeLoadSimulator()->simulate(new LoadTestProfile('api_request', 100, 750));
demo_step('Safe load simulation generated', $simulation->toArray());

$gateBlocked = $kernel->performanceReleaseGate()->evaluate(
    $kernel->sloEvaluator()->evaluate(['api_request' => ['p95_ms' => 900, 'p99_ms' => 2500, 'error_rate_percent' => 2]]),
    $risk
);
demo_step('Performance release gate blocks failed SLO/capacity', $gateBlocked);

$matrix = $kernel->vulnerabilityMatrix()->find('performance_dos');
demo_step('Vulnerability matrix coverage improved', $matrix?->toArray());

demo_result(
    $fast->allowed()
    && $slow->status() === 'warning'
    && $critical->action() === 'queue'
    && $blocked
    && in_array($queueReport['status'], ['warning', 'critical'], true)
    && in_array($throttle->decision(), ['throttle', 'degrade', 'queue'], true)
    && $slo->passed()
    && $risk->status() === 'critical'
    && $gateBlocked['passed'] === false
    && $matrix !== null,
    'Throughput profiles, latency budgets, concurrency limits, throttling, queue pressure, SLOs, capacity risk, release gate, and matrix coverage are working.'
);
