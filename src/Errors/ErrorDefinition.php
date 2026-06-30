<?php
namespace Mnb\SecurityCore\Errors;

final class ErrorDefinition
{
    /** @param array<string,mixed> $extra */
    public function __construct(
        private string $code,
        private int $status,
        private string $title,
        private string $publicMessage,
        private string $logLevel = 'error',
        private string $type = 'about:blank',
        private array $extra = []
    ) {}

    /** @param array<string,mixed> $data */
    public static function fromArray(string $code, array $data): self
    {
        return new self(
            strtoupper($code),
            (int)($data['status'] ?? 500),
            (string)($data['title'] ?? ucwords(strtolower(str_replace('_', ' ', $code)))),
            (string)($data['message'] ?? $data['public_message'] ?? 'Something went wrong. Please try again later.'),
            (string)($data['log_level'] ?? 'error'),
            (string)($data['type'] ?? ('https://errors.mnb.local/' . strtolower(str_replace('_', '-', $code)))),
            is_array($data['extra'] ?? null) ? $data['extra'] : []
        );
    }

    public function code(): string { return $this->code; }
    public function status(): int { return $this->status; }
    public function title(): string { return $this->title; }
    public function publicMessage(): string { return $this->publicMessage; }
    public function logLevel(): string { return $this->logLevel; }
    public function type(): string { return $this->type; }
    /** @return array<string,mixed> */
    public function extra(): array { return $this->extra; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'code' => $this->code,
            'status' => $this->status,
            'title' => $this->title,
            'public_message' => $this->publicMessage,
            'log_level' => $this->logLevel,
            'type' => $this->type,
            'extra' => $this->extra,
        ];
    }
}
