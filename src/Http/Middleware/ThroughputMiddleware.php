<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Throughput\ThroughputMeter;
use Mnb\SecurityCore\Throughput\ThroughputMonitor;

class ThroughputMiddleware implements MiddlewareInterface
{
    public function __construct(
        private ThroughputMeter $meter,
        private ?ThroughputMonitor $monitor = null,
        private string $label = 'request'
    ) {}

    public function process(Request $request, callable $next): Response
    {
        $started = microtime(true);
        $response = $next($request);
        $sample = $this->meter->sample($this->label . ':' . $request->method() . ' ' . $request->path(), $started, microtime(true), 1, (string)$response->status(), [
            'method' => $request->method(),
            'path' => $request->path(),
            'status' => $response->status(),
        ]);
        $this->monitor?->record($sample);

        if (!$this->meter->config()->emitHeaders()) {
            return $response;
        }

        $latencyStatus = 'ok';
        if ($sample->durationMs() >= $this->meter->config()->criticalLatencyMs()) {
            $latencyStatus = 'critical';
        } elseif ($sample->durationMs() >= $this->meter->config()->warningLatencyMs()) {
            $latencyStatus = 'warning';
        }

        return $response
            ->withHeader('X-Throughput-Duration-MS', (string)$sample->durationMs())
            ->withHeader('X-Throughput-Per-Second', (string)$sample->throughputPerSecond())
            ->withHeader('X-Throughput-Status', $latencyStatus);
    }
}
