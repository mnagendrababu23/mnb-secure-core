<?php
namespace Mnb\SecurityCore\Errors;

final class ErrorCatalog
{
    /** @var array<string,ErrorDefinition> */
    private array $definitions = [];

    /** @param array<string,mixed> $definitions */
    public function __construct(array $definitions = [])
    {
        foreach (self::defaults() as $code => $data) {
            $this->definitions[strtoupper($code)] = ErrorDefinition::fromArray($code, $data);
        }
        foreach ($definitions as $code => $data) {
            if (is_array($data)) {
                $this->definitions[strtoupper((string)$code)] = ErrorDefinition::fromArray((string)$code, $data);
            }
        }
    }

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config): self
    {
        $errors = is_array($config['errors'] ?? null) ? $config['errors'] : [];
        return new self(is_array($errors['catalog'] ?? null) ? $errors['catalog'] : []);
    }

    public function get(string $code): ErrorDefinition
    {
        $code = strtoupper($code);
        return $this->definitions[$code] ?? $this->definitions['INTERNAL_ERROR'];
    }

    public function has(string $code): bool
    {
        return isset($this->definitions[strtoupper($code)]);
    }

    /** @return array<string,array<string,mixed>> */
    public function all(): array
    {
        $out = [];
        foreach ($this->definitions as $code => $definition) {
            $out[$code] = $definition->toArray();
        }
        ksort($out);
        return $out;
    }

    /** @return array<string,array<string,mixed>> */
    public static function defaults(): array
    {
        return [
            'AUTH_REQUIRED' => ['status' => 401, 'title' => 'Authentication required', 'message' => 'Please sign in to continue.', 'log_level' => 'warning'],
            'FORBIDDEN' => ['status' => 403, 'title' => 'Forbidden', 'message' => 'You are not allowed to perform this action.', 'log_level' => 'warning'],
            'NOT_FOUND' => ['status' => 404, 'title' => 'Not found', 'message' => 'The requested record was not found.', 'log_level' => 'warning'],
            'VALIDATION_FAILED' => ['status' => 422, 'title' => 'Validation failed', 'message' => 'Validation failed.', 'log_level' => 'warning'],
            'RATE_LIMITED' => ['status' => 429, 'title' => 'Too many requests', 'message' => 'Too many requests. Please retry later.', 'log_level' => 'warning'],
            'UPLOAD_BLOCKED' => ['status' => 422, 'title' => 'Upload blocked', 'message' => 'The uploaded file was blocked for security reasons.', 'log_level' => 'warning'],
            'CSRF_FAILED' => ['status' => 419, 'title' => 'Security check failed', 'message' => 'The request security token is invalid or expired.', 'log_level' => 'warning'],
            'SECURITY_BLOCKED' => ['status' => 403, 'title' => 'Security blocked', 'message' => 'This request was blocked for security reasons.', 'log_level' => 'warning'],
            'BUSINESS_RULE_FAILED' => ['status' => 422, 'title' => 'Action cannot be completed', 'message' => 'This action cannot be completed.', 'log_level' => 'warning'],
            'MEMORY_LIMIT_EXCEEDED' => ['status' => 503, 'title' => 'Resource limit exceeded', 'message' => 'The request needs more resources than allowed. Please reduce the data size or try a smaller export/import.', 'log_level' => 'warning'],
            'THROUGHPUT_LIMIT_EXCEEDED' => ['status' => 503, 'title' => 'Service busy', 'message' => 'The system is currently busy. Please retry after a short time.', 'log_level' => 'warning'],
            'SERVICE_UNAVAILABLE' => ['status' => 503, 'title' => 'Service unavailable', 'message' => 'The service is temporarily unavailable. Please try again later.', 'log_level' => 'error'],
            'INTERNAL_ERROR' => ['status' => 500, 'title' => 'Internal error', 'message' => 'Something went wrong. Please try again later.', 'log_level' => 'error'],
        ];
    }
}
