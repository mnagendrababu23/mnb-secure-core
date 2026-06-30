# Upgrade 34 Changed Files Manifest

MNB Secure Core v1.0.1 — Async Request, Response Queue, and Background Job Orchestration Engine

This patch ZIP contains only changed/new files. Apply it over the current v1.0.1 upgrade 33 codebase.

## Changed/New Files

- `CHANGELOG.md`
- `README.md`
- `bin/mnb-secure`
- `config/security.php`
- `config/security.production.php`
- `demos/38-async-request-response-queue-background-job-engine.php`
- `docs/RELEASE-NOTES-v1.0.1.md`
- `src/Core/SecurityKernel.php`
- `src/Pentest/PayloadLibrary.php`
- `src/Pentest/PentestChecklist.php`
- `src/Pentest/VerificationMatrix.php`
- `src/Queue/AsyncResponse.php`
- `src/Queue/AsyncResponseFactory.php`
- `src/Queue/BackoffStrategy.php`
- `src/Queue/DatabaseQueueStore.php`
- `src/Queue/DeadLetterQueue.php`
- `src/Queue/DuplicateJobGuard.php`
- `src/Queue/FileQueueStore.php`
- `src/Queue/IdempotencyKey.php`
- `src/Queue/IdempotencyStore.php`
- `src/Queue/InMemoryQueueStore.php`
- `src/Queue/Job.php`
- `src/Queue/JobContext.php`
- `src/Queue/JobDispatcher.php`
- `src/Queue/JobHandlerInterface.php`
- `src/Queue/JobHandlerRegistry.php`
- `src/Queue/JobId.php`
- `src/Queue/JobMiddlewareInterface.php`
- `src/Queue/JobPayload.php`
- `src/Queue/JobPayloadProtector.php`
- `src/Queue/JobPayloadRedactor.php`
- `src/Queue/JobPriority.php`
- `src/Queue/JobResourceGuard.php`
- `src/Queue/JobResult.php`
- `src/Queue/JobStatus.php`
- `src/Queue/JobStatusResponseFactory.php`
- `src/Queue/JobTimeoutGuard.php`
- `src/Queue/QueueAuditEvents.php`
- `src/Queue/QueueConfig.php`
- `src/Queue/QueueDecision.php`
- `src/Queue/QueueMetrics.php`
- `src/Queue/QueueNamePolicy.php`
- `src/Queue/QueuePolicy.php`
- `src/Queue/QueuePressureGuard.php`
- `src/Queue/QueueReleaseGate.php`
- `src/Queue/QueueReport.php`
- `src/Queue/QueueStoreInterface.php`
- `src/Queue/RetryDecision.php`
- `src/Queue/RetryPolicy.php`
- `src/Queue/Worker.php`
- `src/Queue/WorkerConfig.php`
- `src/Queue/WorkerHealthReport.php`
- `src/Queue/WorkerHeartbeat.php`
- `src/Queue/WorkerSupervisor.php`
- `src/Security/SecurityConfigValidator.php`
- `src/Vulnerability/VulnerabilityControlMapper.php`
- `tests/run-tests.php`

## Validation

- PHP lint: passed
- Tests: 368 passed, 0 failed
- Demos: all demos passed
- Config validate: passed
- Queue CLI commands: passed
- Vulnerability report: passed
- Vulnerability grade: A+
