<?php
namespace Mnb\SecurityCore\Errors;

final class ErrorPolicy
{
    public const FORMATS = ['auto', 'json', 'html', 'text', 'problem_json'];

    /** @param array<string,mixed> $config */
    public function __construct(private array $config = []) {}

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config): self
    {
        return new self($config);
    }

    /** @return array<string,mixed> */
    public function errors(): array
    {
        return is_array($this->config['errors'] ?? null) ? $this->config['errors'] : [];
    }

    /** @return array<string,mixed> */
    public function app(): array
    {
        return is_array($this->config['app'] ?? null) ? $this->config['app'] : [];
    }

    public function environment(): string
    {
        return (string)($this->app()['env'] ?? 'production');
    }

    public function debug(): bool
    {
        return (bool)($this->app()['debug'] ?? false);
    }

    public function hideFrontendErrors(): bool
    {
        return (bool)($this->errors()['hide_frontend_errors'] ?? true);
    }

    public function includeRequestId(): bool
    {
        return (bool)($this->errors()['include_request_id'] ?? true);
    }

    public function defaultPublicMessage(): string
    {
        return (string)($this->errors()['default_public_message'] ?? 'Something went wrong. Please try again later.');
    }

    public function responseFormat(string $acceptHeader = ''): string
    {
        $format = (string)($this->errors()['response_format'] ?? 'auto');
        if (!in_array($format, self::FORMATS, true)) {
            $format = 'json';
        }
        if ($format !== 'auto') {
            return $format;
        }
        $accept = strtolower($acceptHeader);
        if (str_contains($accept, 'application/problem+json')) {
            return 'problem_json';
        }
        if (str_contains($accept, 'text/html')) {
            return 'html';
        }
        if (str_contains($accept, 'text/plain')) {
            return 'text';
        }
        return 'json';
    }

    public function shouldExposeDebug(): bool
    {
        $debug = is_array($this->errors()['debug'] ?? null) ? $this->errors()['debug'] : [];
        if ($this->environment() === 'production' && !empty($debug['allow_in_production']) === false) {
            return false;
        }
        return $this->debug() && ($this->environment() !== 'production' || !empty($debug['allow_in_production']));
    }

    public function includeStackTrace(): bool
    {
        $debug = is_array($this->errors()['debug'] ?? null) ? $this->errors()['debug'] : [];
        return $this->shouldExposeDebug() && !empty($debug['include_stack_trace']);
    }

    public function includeFileLine(): bool
    {
        $debug = is_array($this->errors()['debug'] ?? null) ? $this->errors()['debug'] : [];
        return $this->shouldExposeDebug() && (($debug['include_file_line'] ?? true) !== false);
    }

    public function maxStackFrames(): int
    {
        $debug = is_array($this->errors()['debug'] ?? null) ? $this->errors()['debug'] : [];
        return max(1, min(50, (int)($debug['max_stack_frames'] ?? 8)));
    }

    public function redactionEnabled(): bool
    {
        $redaction = is_array($this->errors()['redaction'] ?? null) ? $this->errors()['redaction'] : [];
        return (bool)($redaction['enabled'] ?? true);
    }

    public function redactionReplacement(): string
    {
        $redaction = is_array($this->errors()['redaction'] ?? null) ? $this->errors()['redaction'] : [];
        return (string)($redaction['replacement'] ?? '[redacted]');
    }

    public function redactPaths(): bool
    {
        $redaction = is_array($this->errors()['redaction'] ?? null) ? $this->errors()['redaction'] : [];
        return (bool)($redaction['redact_paths'] ?? true);
    }

    public function redactPii(): bool
    {
        $redaction = is_array($this->errors()['redaction'] ?? null) ? $this->errors()['redaction'] : [];
        return (bool)($redaction['redact_pii'] ?? true);
    }

    /** @return array<string,string> */
    public function validationFieldMap(): array
    {
        $validation = is_array($this->errors()['validation'] ?? null) ? $this->errors()['validation'] : [];
        return is_array($validation['public_field_map'] ?? null) ? array_map('strval', $validation['public_field_map']) : [];
    }

    public function normalizeValidationFields(): bool
    {
        $validation = is_array($this->errors()['validation'] ?? null) ? $this->errors()['validation'] : [];
        return (bool)($validation['normalize_field_names'] ?? true);
    }

    public function hideInternalValidationFields(): bool
    {
        $validation = is_array($this->errors()['validation'] ?? null) ? $this->errors()['validation'] : [];
        return (bool)($validation['hide_internal_fields'] ?? true);
    }

    public function fingerprintingEnabled(): bool
    {
        $fingerprinting = is_array($this->errors()['fingerprinting'] ?? null) ? $this->errors()['fingerprinting'] : [];
        return (bool)($fingerprinting['enabled'] ?? true);
    }

    /** @return array<string,mixed> */
    public function escalation(): array
    {
        return is_array($this->errors()['escalation'] ?? null) ? $this->errors()['escalation'] : [];
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'enabled' => (bool)($this->errors()['enabled'] ?? true),
            'environment' => $this->environment(),
            'hide_frontend_errors' => $this->hideFrontendErrors(),
            'response_format' => $this->errors()['response_format'] ?? 'auto',
            'include_request_id' => $this->includeRequestId(),
            'debug_exposure_allowed' => $this->shouldExposeDebug(),
            'include_stack_trace' => $this->includeStackTrace(),
            'include_file_line' => $this->includeFileLine(),
            'redaction_enabled' => $this->redactionEnabled(),
            'redact_paths' => $this->redactPaths(),
            'redact_pii' => $this->redactPii(),
            'fingerprinting_enabled' => $this->fingerprintingEnabled(),
            'escalation_enabled' => (bool)($this->escalation()['enabled'] ?? true),
        ];
    }
}
