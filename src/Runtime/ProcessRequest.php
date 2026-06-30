<?php
namespace Mnb\SecurityCore\Runtime;

final class ProcessRequest
{
    /** @param array<int,mixed> $arguments @param array<string,mixed> $environment */
    public function __construct(
        private string $commandName,
        private array $arguments = [],
        private ?string $workingDirectory = null,
        private array $environment = [],
        private ?int $timeoutSeconds = null
    ) {}

    public function commandName(): string { return $this->commandName; }
    /** @return array<int,mixed> */ public function arguments(): array { return $this->arguments; }
    public function workingDirectory(): ?string { return $this->workingDirectory; }
    /** @return array<string,mixed> */ public function environment(): array { return $this->environment; }
    public function timeoutSeconds(): ?int { return $this->timeoutSeconds; }
}
