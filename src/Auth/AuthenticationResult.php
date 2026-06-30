<?php
namespace Mnb\SecurityCore\Auth;

class AuthenticationResult
{
    /** @param array<string,mixed> $metadata @param array<string,string> $errors */
    public function __construct(
        private bool $success,
        private ?AuthContext $auth = null,
        private ?string $plainToken = null,
        private ?array $tokenRecord = null,
        private string $message = '',
        private string $code = '',
        private int $status = 200,
        private array $errors = [],
        private array $metadata = []
    ) {}

    /** @param array<string,mixed> $metadata */
    public static function authenticated(?AuthContext $auth = null, ?string $plainToken = null, ?array $tokenRecord = null, array $metadata = []): self
    {
        return new self(true, $auth, $plainToken, $tokenRecord, 'Authenticated', 'authenticated', 200, [], $metadata);
    }

    /** @param array<string,string> $errors @param array<string,mixed> $metadata */
    public static function failure(string $message = 'Authentication failed', string $code = 'authentication_failed', int $status = 401, array $errors = [], array $metadata = []): self
    {
        return new self(false, null, null, null, $message, $code, $status, $errors, $metadata);
    }

    public function success(): bool { return $this->success; }
    public function failed(): bool { return !$this->success; }
    public function auth(): ?AuthContext { return $this->auth; }
    public function context(): ?AuthContext { return $this->auth; }
    public function plainToken(): ?string { return $this->plainToken; }
    /** @return array<string,mixed>|null */ public function tokenRecord(): ?array { return $this->tokenRecord; }
    public function message(): string { return $this->message; }
    public function safeMessage(): string { return $this->success ? $this->message : 'Authentication failed'; }
    public function code(): string { return $this->code; }
    public function status(): int { return $this->status; }
    /** @return array<string,string> */ public function errors(): array { return $this->errors; }
    public function metadata(string $key, mixed $default = null): mixed { return $this->metadata[$key] ?? $default; }
    /** @return array<string,mixed> */ public function allMetadata(): array { return $this->metadata; }

    /** @return array<string,mixed> */
    public function toArray(bool $includePlainToken = false): array
    {
        $out = [
            'success' => $this->success,
            'code' => $this->code,
            'message' => $this->success ? $this->message : $this->safeMessage(),
            'status' => $this->status,
            'auth' => $this->auth?->toArray(),
            'errors' => $this->errors,
            'metadata' => $this->metadata,
        ];
        if ($includePlainToken && $this->plainToken !== null) {
            $out['plain_token'] = $this->plainToken;
        }
        return $out;
    }
}
