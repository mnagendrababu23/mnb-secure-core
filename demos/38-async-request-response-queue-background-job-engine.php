<?php
require __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Queue\InMemoryQueueStore;
use Mnb\SecurityCore\Queue\JobHandlerInterface;
use Mnb\SecurityCore\Queue\Job;
use Mnb\SecurityCore\Queue\JobResult;

$config = require __DIR__ . '/../config/security.php';
$config['queue']['default_connection'] = 'memory';
$kernel = new SecurityKernel($config);
$store = new InMemoryQueueStore();
$handlers = $kernel->jobHandlerRegistry([
    'failing_job' => new class implements JobHandlerInterface {
        public function handle(Job $job): JobResult { return JobResult::failure('validation failure demo', [], false); }
    },
]);

$dispatcher = $kernel->jobDispatcher($store, $handlers);
$dispatch = $dispatcher->dispatch('test_job', ['file_id' => 123], 'default', null, 'demo:file:123');
$async = $kernel->asyncResponseFactory()->accepted($dispatch)->toArray();
$duplicate = $dispatcher->dispatch('test_job', ['file_id' => 123], 'default', null, 'demo:file:123');
$unknown = $dispatcher->dispatch('unknown_job', [], 'default');
$unsafePayload = $dispatcher->dispatch('test_job', ['token' => 'secret-token'], 'default', null, 'demo:unsafe');
$work = $kernel->queueWorker($store, $handlers)->workOnce('default');
$failed = $dispatcher->dispatch('failing_job', ['safe_id' => 999], 'default', null, 'demo:failing');
$failedWork = $kernel->queueWorker($store, $handlers)->workOnce('default');
$pressure = $kernel->queuePressureGuard($store)->check('default');
$releaseGate = $kernel->queueReleaseGate()->evaluate($store->metrics(), $handlers, ['test_job']);
$matrix = $kernel->vulnerabilityAdvisor()->recommend('unsafe_background_job');

$report = [
    'engine' => '34. Async Request, Response Queue, and Background Job Orchestration Engine',
    'policy_loaded' => $kernel->queuePolicy()->toArray()['enabled'] ?? false,
    'dispatch' => $dispatch,
    'async_response' => $async,
    'duplicate_dispatch' => $duplicate,
    'unknown_handler' => $unknown,
    'unsafe_payload' => $unsafePayload,
    'worker_success' => $work,
    'failed_dispatch' => $failed,
    'failed_worker' => $failedWork,
    'dead_letters' => $kernel->deadLetterQueue($store)->all(),
    'pressure' => $pressure,
    'release_gate' => $releaseGate,
    'vulnerability_matrix' => $matrix,
];

echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
