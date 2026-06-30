<?php
namespace Mnb\SecurityCore\Runtime;

final class ProcessResult
{
    public function __construct(
        private bool $allowed,
        private bool $successful,
        private bool $blocked,
        private bool $timedOut,
        private ?int $exitCode,
        private string $output = '',
        private string $errorOutput = '',
        private ?string $reason = null,
        private bool $outputTruncated = false,
        private float $durationSeconds = 0.0
    ) {}

    public static function deny(string $reason): self
    {
        return new self(false, false, true, false, null, '', '', $reason);
    }

    public function allowed(): bool { return $this->allowed; }
    public function isSuccessful(): bool { return $this->successful; }
    public function blocked(): bool { return $this->blocked; }
    public function timedOut(): bool { return $this->timedOut; }
    public function exitCode(): ?int { return $this->exitCode; }
    public function output(): string { return $this->output; }
    public function errorOutput(): string { return $this->errorOutput; }
    public function reason(): ?string { return $this->reason; }
    public function outputTruncated(): bool { return $this->outputTruncated; }
    public function durationSeconds(): float { return $this->durationSeconds; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'successful' => $this->successful,
            'blocked' => $this->blocked,
            'timed_out' => $this->timedOut,
            'exit_code' => $this->exitCode,
            'output' => $this->output,
            'error_output' => $this->errorOutput,
            'reason' => $this->reason,
            'output_truncated' => $this->outputTruncated,
            'duration_seconds' => round($this->durationSeconds, 4),
        ];
    }
}
