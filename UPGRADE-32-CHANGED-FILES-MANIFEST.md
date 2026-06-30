# Upgrade 32 changed files manifest

MNB Secure Core v1.0.1 — Throughput Governance and Performance Capacity Engine.

This patch ZIP contains only new or modified files and is intended to be applied over the v1.0.1 Upgrade 31 codebase.

## Files

- `CHANGELOG.md`
- `README.md`
- `bin/mnb-secure`
- `config/security.php`
- `config/security.production.php`
- `demos/36-throughput-governance-performance-capacity-engine.php`
- `docs/RELEASE-NOTES-v1.0.1.md`
- `src/Core/SecurityKernel.php`
- `src/Pentest/PayloadLibrary.php`
- `src/Pentest/PentestChecklist.php`
- `src/Pentest/VerificationMatrix.php`
- `src/Security/SecurityConfigValidator.php`
- `src/Throughput/AdaptiveThrottle.php`
- `src/Throughput/BackpressureController.php`
- `src/Throughput/BottleneckDetector.php`
- `src/Throughput/CapacityReport.php`
- `src/Throughput/CapacityRiskAnalyzer.php`
- `src/Throughput/CapacitySimulationResult.php`
- `src/Throughput/ConcurrencyLimiter.php`
- `src/Throughput/ConcurrencyStore.php`
- `src/Throughput/ConcurrencyToken.php`
- `src/Throughput/DegradationDecision.php`
- `src/Throughput/DegradationPolicy.php`
- `src/Throughput/FeatureLoadShedder.php`
- `src/Throughput/FileConcurrencyStore.php`
- `src/Throughput/InMemoryConcurrencyStore.php`
- `src/Throughput/LatencyBudget.php`
- `src/Throughput/LatencyBudgetRegistry.php`
- `src/Throughput/LoadTestProfile.php`
- `src/Throughput/OperationThroughputProfile.php`
- `src/Throughput/PercentileCalculator.php`
- `src/Throughput/PerformanceFinding.php`
- `src/Throughput/PerformanceReleaseGate.php`
- `src/Throughput/PerformanceRemediationAdvisor.php`
- `src/Throughput/PerformanceSampleStore.php`
- `src/Throughput/PerformanceSlo.php`
- `src/Throughput/QueueBacklogPolicy.php`
- `src/Throughput/QueueCapacityPlanner.php`
- `src/Throughput/QueuePressureMonitor.php`
- `src/Throughput/RollingWindowMetrics.php`
- `src/Throughput/SafeLoadSimulator.php`
- `src/Throughput/SloEvaluator.php`
- `src/Throughput/SloReport.php`
- `src/Throughput/SlowOperationClassifier.php`
- `src/Throughput/ThrottleDecision.php`
- `src/Throughput/ThroughputAuditEvents.php`
- `src/Throughput/ThroughputBudget.php`
- `src/Throughput/ThroughputBudgetDecision.php`
- `src/Throughput/ThroughputConfig.php`
- `src/Throughput/ThroughputPolicy.php`
- `src/Vulnerability/VulnerabilityControlMapper.php`
- `tests/run-tests.php`

## Validation

- PHP lint: passed
- Tests: 330 passed, 0 failed
- Demos: all demos passed
- Config validate: passed
- Vulnerability report: passed, score 98.91, grade A+
