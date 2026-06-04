<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Http\Middleware\ThroughputMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Logging\FileLogger;
use Mnb\SecurityCore\Throughput\ThroughputConfig;
use Mnb\SecurityCore\Throughput\ThroughputMeter;
use Mnb\SecurityCore\Throughput\ThroughputMonitor;
use Mnb\SecurityCore\Throughput\ThroughputPlanner;

$config = require __DIR__ . '/../config/security.php';
$throughputConfig = ThroughputConfig::fromArray($config['throughput'] ?? []);
$logger = new FileLogger(($config['paths']['logs'] ?? __DIR__ . '/../storage/logs') . '/throughput.log');
$meter = new ThroughputMeter($throughputConfig, $logger);
$monitor = new ThroughputMonitor($throughputConfig);

$pipeline = new MiddlewarePipeline([
    new ThroughputMiddleware($meter, $monitor, 'api'),
]);

$response = $pipeline->handle(Request::fromGlobals(), function (Request $request) use ($meter): Response {
    $measured = $meter->measure('student-report-query', function () {
        // Replace this with your database/report service call.
        return ['students' => 120, 'status' => true];
    }, units: 120);

    return Response::json([
        'status' => true,
        'data' => $measured['result'],
        'throughput' => $measured['sample']->toArray(),
    ]);
});

// Capacity planning example for a school app endpoint.
$plan = ThroughputPlanner::plan(
    targetRps: 80,
    averageLatencyMs: 150,
    maxConcurrency: $throughputConfig->maxConcurrency(),
    queueDepth: 500,
    averageJobMs: 900
);

// In a real app, use $response->send(). Here we show the shape only.
echo $response->body() . PHP_EOL;
echo json_encode(['capacity_plan' => $plan], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
