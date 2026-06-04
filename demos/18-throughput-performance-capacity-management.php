<?php
require __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Http\Middleware\ThroughputMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Logging\FileLogger;
use Mnb\SecurityCore\Throughput\ThroughputConfig;
use Mnb\SecurityCore\Throughput\ThroughputMeter;
use Mnb\SecurityCore\Throughput\ThroughputMonitor;
use Mnb\SecurityCore\Throughput\ThroughputPlanner;

demo_title('Concept 18: Throughput and Performance Capacity Management');

$base = demo_storage_path('throughput');
$config = ThroughputConfig::fromArray([
    'target_rps' => 40,
    'warning_latency_ms' => 50,
    'critical_latency_ms' => 250,
    'max_concurrency' => 10,
]);
$logger = new FileLogger($base . '/logs/throughput.log');
$meter = new ThroughputMeter($config, $logger);
$monitor = new ThroughputMonitor($config);

$measured = $meter->measure('student-search', function () {
    usleep(20_000);
    return ['rows' => 25];
}, units: 25, metadata: ['module' => 'students']);
$monitor->record($measured['sample']);

demo_step('Measured operation sample', $measured['sample']->toArray());
demo_result(($measured['result']['rows'] ?? 0) === 25, 'ThroughputMeter measures a business operation and returns result');
demo_result($measured['sample']->durationMs() > 0, 'ThroughputSample stores duration and throughput per second');

$pipeline = new MiddlewarePipeline([
    new ThroughputMiddleware($meter, $monitor, 'web'),
]);
$response = $pipeline->handle(new Request('GET', '/students'), fn() => Response::json(['status' => true]));

demo_step('Middleware throughput headers', $response->headers());
demo_result($response->status() === 200, 'Throughput middleware allows normal request');
demo_result(isset($response->headers()['X-Throughput-Duration-MS']), 'Throughput middleware adds duration header');

$summary = $monitor->summary();
demo_step('Throughput monitor summary', $summary);
demo_result($summary['samples'] >= 2, 'ThroughputMonitor records request and operation samples');
demo_result(isset($summary['p95_ms']) && isset($summary['throughput_per_second']), 'ThroughputMonitor summarizes p95 latency and throughput');

$plan = ThroughputPlanner::plan(targetRps: 40, averageLatencyMs: 120, maxConcurrency: 10, queueDepth: 250, averageJobMs: 800);
demo_step('Capacity plan', $plan);
demo_result($plan['required_concurrency'] >= 1, 'ThroughputPlanner calculates required concurrency');
demo_result(isset($plan['recommended_queue_workers']), 'ThroughputPlanner recommends queue workers');
