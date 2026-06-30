<?php
namespace Mnb\SecurityCore\Runtime;

use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Throwable;

final class SafeProcessRunner
{
    public function __construct(private ProcessPolicy $policy, private ?SecurityAuditTrail $audit = null) {}

    /** @param array<int,mixed> $arguments @param array<string,mixed> $environment */
    public function run(string $commandName, array $arguments = [], ?string $workingDirectory = null, array $environment = [], ?int $timeoutSeconds = null): ProcessResult
    {
        return $this->runRequest(new ProcessRequest($commandName, $arguments, $workingDirectory, $environment, $timeoutSeconds));
    }

    public function check(string $commandName, array $arguments = [], ?string $workingDirectory = null, array $environment = [], ?int $timeoutSeconds = null): array
    {
        $validation = $this->policy->validate(new ProcessRequest($commandName, $arguments, $workingDirectory, $environment, $timeoutSeconds));
        return [
            'passed' => (bool)$validation['passed'],
            'command' => $commandName,
            'reason' => $validation['reason'],
            'timeout_seconds' => $validation['timeout'],
            'max_output_bytes' => $validation['max_output_bytes'],
        ];
    }

    public function runRequest(ProcessRequest $request): ProcessResult
    {
        $validation = $this->policy->validate($request);
        if (!$validation['passed']) {
            $this->audit(RuntimeAuditEvents::PROCESS_BLOCKED, SecurityAuditEvent::OUTCOME_DENIED, SecurityAuditEvent::SEVERITY_WARNING, $request->commandName(), (string)$validation['reason']);
            return ProcessResult::deny((string)$validation['reason']);
        }

        if (!function_exists('proc_open')) {
            $this->audit(RuntimeAuditEvents::PROCESS_FAILED, SecurityAuditEvent::OUTCOME_FAILURE, SecurityAuditEvent::SEVERITY_WARNING, $request->commandName(), 'proc_open_disabled');
            return new ProcessResult(true, false, false, false, 2, '', 'proc_open is disabled', 'proc_open_disabled');
        }

        /** @var CommandDefinition $definition */
        $definition = $validation['definition'];
        $command = array_merge([$definition->binary()], $definition->allowedArgs(), $validation['args']);
        $descriptorSpec = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $startedAt = microtime(true);

        try {
            $process = @proc_open($command, $descriptorSpec, $pipes, $validation['cwd'], $validation['env']);
        } catch (Throwable $e) {
            $this->audit(RuntimeAuditEvents::PROCESS_FAILED, SecurityAuditEvent::OUTCOME_FAILURE, SecurityAuditEvent::SEVERITY_WARNING, $request->commandName(), 'process_start_failed');
            return new ProcessResult(true, false, false, false, 2, '', $e->getMessage(), 'process_start_failed');
        }

        if (!is_resource($process)) {
            $this->audit(RuntimeAuditEvents::PROCESS_FAILED, SecurityAuditEvent::OUTCOME_FAILURE, SecurityAuditEvent::SEVERITY_WARNING, $request->commandName(), 'process_start_failed');
            return new ProcessResult(true, false, false, false, 2, '', 'Process could not be started', 'process_start_failed');
        }

        foreach ($pipes as $pipe) {
            stream_set_blocking($pipe, false);
        }

        $stdout = '';
        $stderr = '';
        $timedOut = false;
        $outputTruncated = false;
        $maxOutput = (int)$validation['max_output_bytes'];
        $timeout = (int)$validation['timeout'];

        while (true) {
            $status = proc_get_status($process);
            $stdout .= $this->readPipe($pipes[1] ?? null, $maxOutput, $outputTruncated);
            $stderr .= $this->readPipe($pipes[2] ?? null, $maxOutput, $outputTruncated);

            if ((strlen($stdout) + strlen($stderr)) > $maxOutput) {
                $outputTruncated = true;
                $stdout = substr($stdout, 0, $maxOutput);
                $stderr = substr($stderr, 0, max(0, $maxOutput - strlen($stdout)));
                proc_terminate($process);
                usleep(100000);
                break;
            }

            if (!$status['running']) {
                break;
            }
            if ((microtime(true) - $startedAt) >= $timeout) {
                $timedOut = true;
                proc_terminate($process);
                usleep(100000);
                $status = proc_get_status($process);
                if ($status['running']) {
                    proc_terminate($process, 9);
                }
                break;
            }
            usleep(50000);
        }

        $stdout .= $this->readPipe($pipes[1] ?? null, $maxOutput, $outputTruncated);
        $stderr .= $this->readPipe($pipes[2] ?? null, $maxOutput, $outputTruncated);
        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }

        $exitCode = proc_close($process);
        $duration = microtime(true) - $startedAt;
        $exitCode = is_int($exitCode) ? $exitCode : 2;

        if ($timedOut) {
            $this->audit(RuntimeAuditEvents::PROCESS_TIMEOUT, SecurityAuditEvent::OUTCOME_FAILURE, SecurityAuditEvent::SEVERITY_WARNING, $request->commandName(), 'process_timeout');
            return new ProcessResult(true, false, false, true, 2, trim($stdout), trim($stderr), 'process_timeout', $outputTruncated, $duration);
        }
        if ($outputTruncated) {
            $this->audit(RuntimeAuditEvents::PROCESS_OUTPUT_LIMIT, SecurityAuditEvent::OUTCOME_FAILURE, SecurityAuditEvent::SEVERITY_WARNING, $request->commandName(), 'output_limit_exceeded');
            return new ProcessResult(true, false, false, false, 2, trim($stdout), trim($stderr), 'output_limit_exceeded', true, $duration);
        }

        $success = $exitCode === 0;
        $this->audit($success ? RuntimeAuditEvents::PROCESS_ALLOWED : RuntimeAuditEvents::PROCESS_FAILED, $success ? SecurityAuditEvent::OUTCOME_SUCCESS : SecurityAuditEvent::OUTCOME_FAILURE, $success ? SecurityAuditEvent::SEVERITY_INFO : SecurityAuditEvent::SEVERITY_WARNING, $request->commandName(), $success ? null : 'process_exit_' . $exitCode);
        return new ProcessResult(true, $success, false, false, $exitCode, trim($stdout), trim($stderr), $success ? null : 'process_exit_' . $exitCode, false, $duration);
    }

    private function readPipe(mixed $pipe, int $maxOutput, bool &$truncated): string
    {
        if (!is_resource($pipe)) {
            return '';
        }
        $chunk = stream_get_contents($pipe, max(1, $maxOutput + 1));
        if ($chunk === false || $chunk === '') {
            return '';
        }
        if (strlen($chunk) > $maxOutput) {
            $truncated = true;
            return substr($chunk, 0, $maxOutput);
        }
        return $chunk;
    }

    private function audit(string $event, string $outcome, string $severity, string $commandName, ?string $reason = null): void
    {
        if (!$this->audit) {
            return;
        }
        try {
            $this->audit->record(SecurityAuditEvent::make('system', $event, $outcome, $severity, [], ['command' => $commandName], ['reason' => $reason]));
        } catch (Throwable) {
            // Audit must never break runtime safety decisions.
        }
    }
}
