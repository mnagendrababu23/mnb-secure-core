<?php
namespace Mnb\SecurityCore\Throughput;

final class ThroughputAuditEvents
{
    public const POLICY_EVALUATED = 'throughput.policy.evaluated';
    public const LATENCY_WARNING = 'throughput.latency.warning';
    public const LATENCY_CRITICAL = 'throughput.latency.critical';
    public const CONCURRENCY_ACQUIRED = 'throughput.concurrency.acquired';
    public const CONCURRENCY_BLOCKED = 'throughput.concurrency.blocked';
    public const CONCURRENCY_RELEASED = 'throughput.concurrency.released';
    public const THROTTLE_DECIDED = 'throughput.throttle.decided';
    public const QUEUE_PRESSURE_CHECKED = 'throughput.queue_pressure.checked';
    public const SLO_EVALUATED = 'throughput.slo.evaluated';
    public const DEGRADATION_DECIDED = 'throughput.degradation.decided';
    public const CAPACITY_RISK_ANALYZED = 'throughput.capacity_risk.analyzed';
    public const RELEASE_GATE_PASSED = 'throughput.release_gate.passed';
    public const RELEASE_GATE_BLOCKED = 'throughput.release_gate.blocked';
}
