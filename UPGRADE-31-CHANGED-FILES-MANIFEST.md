# Upgrade 31 Changed Files Manifest

Package: `MNB Secure Core v1.0.1 — Memory Governance and Resource Safety Engine`

This patch package contains only new/changed files. Apply it over the current v1.0.1 codebase after upgrade 30.

## New files

- `src/Memory/MemoryAuditEvents.php`
- `src/Memory/MemoryBudget.php`
- `src/Memory/OperationMemoryProfile.php`
- `src/Memory/MemoryBudgetDecision.php`
- `src/Memory/MemoryPolicy.php`
- `src/Memory/StreamBudget.php`
- `src/Memory/StreamGuard.php`
- `src/Memory/SafeStreamReader.php`
- `src/Memory/SafeStreamWriter.php`
- `src/Memory/BoundedBuffer.php`
- `src/Memory/BoundedCollection.php`
- `src/Memory/PayloadSizeGuard.php`
- `src/Memory/DecodedPayloadGuard.php`
- `src/Memory/JsonDepthGuard.php`
- `src/Memory/ArrayDepthGuard.php`
- `src/Memory/OutputBufferGuard.php`
- `src/Memory/ResponseSizeBudget.php`
- `src/Memory/ResourceScope.php`
- `src/Memory/ResourceScopeManager.php`
- `src/Memory/CleanupStack.php`
- `src/Memory/TemporaryFileBudget.php`
- `src/Memory/TemporaryFileManager.php`
- `src/Memory/TempStorageSweeper.php`
- `src/Memory/MemoryLeakDetector.php`
- `src/Memory/WorkerMemorySupervisor.php`
- `demos/35-memory-governance-resource-safety-engine.php`

## Updated files

- `config/security.php`
- `config/security.production.php`
- `src/Core/SecurityKernel.php`
- `src/Security/SecurityConfigValidator.php`
- `src/Vulnerability/VulnerabilityControlMapper.php`
- `bin/mnb-secure`
- `tests/run-tests.php`
- `README.md`
- `CHANGELOG.md`
- `docs/RELEASE-NOTES-v1.0.1.md`

## Validation

- PHP lint: passed
- Tests: 312 passed, 0 failed
- Demos: all demos passed
- Config validate: passed
- Memory CLI commands: passed
- Vulnerability report: passed, score 98.73, grade A+
