<?php
namespace Mnb\SecurityCore\Logging;

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Http\Request;

class AutoAuditLogger
{
    /** @var list<string> */
    private array $sensitiveKeys;

    public function __construct(
        private SecurityAuditTrail $audit,
        private array $config = []
    ) {
        $this->sensitiveKeys = array_map('strtolower', $config['sensitive_input_keys'] ?? [
            'password', 'password_confirmation', 'current_password', 'new_password', 'token', 'api_token',
            'secret', 'api_key', 'authorization', 'cookie', 'session', 'csrf', 'otp', 'private_key',
        ]);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function recordAction(string $action, string $outcome = SecurityAuditEvent::OUTCOME_SUCCESS, array $actor = [], array $target = [], array $context = [], array $meta = []): array
    {
        $action = $this->normalizeAction($action);
        $category = $this->categoryForAction($action);
        $severity = $this->severityFor($action, $outcome);

        return $this->audit->record(SecurityAuditEvent::make(
            $category,
            $action,
            $outcome,
            $severity,
            $this->sanitize($actor),
            $this->sanitize($target),
            $this->sanitize($context),
            $this->sanitize($meta)
        ));
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function add(array $actor = [], array $target = [], array $context = [], array $meta = [], bool $success = true): array
    {
        return $this->recordAction('record.add', $this->outcome($success), $actor, $target, $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function edit(array $actor = [], array $target = [], array $context = [], array $meta = [], bool $success = true): array
    {
        return $this->recordAction('record.edit', $this->outcome($success), $actor, $target, $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function update(array $actor = [], array $target = [], array $context = [], array $meta = [], bool $success = true): array
    {
        return $this->recordAction('record.update', $this->outcome($success), $actor, $target, $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function delete(array $actor = [], array $target = [], array $context = [], array $meta = [], bool $success = true): array
    {
        return $this->recordAction('record.delete', $this->outcome($success), $actor, $target, $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function submission(array $actor = [], array $target = [], array $context = [], array $meta = [], bool $success = true): array
    {
        return $this->recordAction('submission.created', $this->outcome($success), $actor, $target, $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function emailSent(array $actor = [], array $target = [], array $context = [], array $meta = [], bool $success = true): array
    {
        return $this->recordAction('email.sent', $this->outcome($success), $actor, $target, $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function loginSuccess(array $actor = [], array $context = [], array $meta = []): array
    {
        return $this->recordAction('auth.login', SecurityAuditEvent::OUTCOME_SUCCESS, $actor, [], $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function loginFailed(array $actor = [], array $context = [], array $meta = []): array
    {
        return $this->recordAction('auth.login', SecurityAuditEvent::OUTCOME_FAILURE, $actor, [], $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function registerSuccess(array $actor = [], array $context = [], array $meta = []): array
    {
        return $this->recordAction('auth.register', SecurityAuditEvent::OUTCOME_SUCCESS, $actor, [], $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function registerFailed(array $actor = [], array $context = [], array $meta = []): array
    {
        return $this->recordAction('auth.register', SecurityAuditEvent::OUTCOME_FAILURE, $actor, [], $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function passwordVerificationSuccess(array $actor = [], array $context = [], array $meta = []): array
    {
        return $this->recordAction('auth.password_verification', SecurityAuditEvent::OUTCOME_SUCCESS, $actor, [], $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function passwordVerificationFailed(array $actor = [], array $context = [], array $meta = []): array
    {
        return $this->recordAction('auth.password_verification', SecurityAuditEvent::OUTCOME_FAILURE, $actor, [], $context, $meta);
    }

    /** @param array<string,mixed> $target @param array<string,mixed> $meta */
    public function recordRequest(Request $request, int $statusCode, array $target = [], array $meta = []): ?array
    {
        $action = $this->inferAction($request);
        if ($action === null) {
            return null;
        }

        $success = $statusCode < 400;
        $outcome = $this->outcome($success);
        $actor = self::actorFromRequest($request);
        $context = SecurityAuditEvent::contextFromRequest($request);
        $target = $target + [
            'path' => $request->path(),
            'method' => $request->method(),
            'route' => $request->attribute('route_name'),
        ];
        $meta = $meta + [
            'status_code' => $statusCode,
            'auto' => true,
        ];

        return $this->recordAction($action, $outcome, $actor, $target, $context, $meta);
    }

    /** @return array<string,mixed> */
    public static function actorFromRequest(Request $request): array
    {
        $auth = $request->attribute(AuthContext::ATTRIBUTE);
        if ($auth instanceof AuthContext && $auth->isAuthenticated()) {
            return array_filter([
                'user_id' => $auth->id(),
                'roles' => $auth->roles(),
            ], fn($value) => $value !== null && $value !== []);
        }

        $userId = $request->attribute('auth_user_id');
        if ($userId !== null && $userId !== '') {
            return ['user_id' => $userId];
        }

        $email = $request->input('email');
        if (is_scalar($email) && trim((string)$email) !== '') {
            return ['email_fingerprint' => SecurityAuditEvent::fingerprint(strtolower(trim((string)$email)))];
        }

        return [];
    }

    public function inferAction(Request $request): ?string
    {
        $method = $request->method();
        $path = strtolower(trim($request->path(), '/'));

        if ($method === 'OPTIONS' && empty($this->config['log_preflight'])) {
            return null;
        }
        if (in_array($method, ['GET', 'HEAD'], true) && empty($this->config['log_reads'])) {
            return null;
        }

        $route = strtolower((string)($request->attribute('route_name') ?? ''));
        $text = trim($route . ' ' . str_replace(['-', '_', '/'], ' ', $path));

        if ($this->matchesAny($path, $this->config['excluded_paths'] ?? [])) {
            return null;
        }
        if (preg_match('/\b(login|signin|sign in)\b/', $text)) {
            return 'auth.login';
        }
        if (preg_match('/\b(register|signup|sign up)\b/', $text)) {
            return 'auth.register';
        }
        if (str_contains($text, 'password') && preg_match('/\b(verify|check|confirm|reset|forgot)\b/', $text)) {
            return 'auth.password_verification';
        }
        if (str_contains($text, 'email') && preg_match('/\b(send|sent|mail|notify|notification)\b/', $text)) {
            return 'email.sent';
        }
        if (preg_match('/\b(submit|submission|form)\b/', $text) && in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            return 'submission.created';
        }
        if ($method === 'DELETE') {
            return 'record.delete';
        }
        if ($method === 'POST') {
            return preg_match('/\b(update|edit)\b/', $text) ? 'record.update' : 'record.add';
        }
        if (in_array($method, ['PUT', 'PATCH'], true)) {
            return preg_match('/\b(edit)\b/', $text) ? 'record.edit' : 'record.update';
        }
        if (in_array($method, ['GET', 'HEAD'], true)) {
            return 'record.view';
        }
        return 'request.' . strtolower($method);
    }

    private function normalizeAction(string $action): string
    {
        $action = strtolower(trim($action));
        $action = preg_replace('/[^a-z0-9_.:-]+/', '.', $action) ?: 'system.event';
        $action = trim($action, '.:-_');
        return strlen($action) >= 2 ? $action : 'system.event';
    }

    private function outcome(bool $success): string
    {
        return $success ? SecurityAuditEvent::OUTCOME_SUCCESS : SecurityAuditEvent::OUTCOME_FAILURE;
    }

    private function categoryForAction(string $action): string
    {
        $prefix = strtolower(strtok($action, '.:') ?: $action);
        return match ($prefix) {
            'auth', 'login', 'register', 'password' => SecurityAuditEvent::CATEGORY_AUTH,
            'token', 'api_token' => SecurityAuditEvent::CATEGORY_TOKEN,
            'upload', 'file' => SecurityAuditEvent::CATEGORY_UPLOAD,
            'admin' => SecurityAuditEvent::CATEGORY_ADMIN,
            'db', 'database', 'schema' => SecurityAuditEvent::CATEGORY_DATABASE,
            'submission' => defined(SecurityAuditEvent::class . '::CATEGORY_SUBMISSION') ? SecurityAuditEvent::CATEGORY_SUBMISSION : 'submission',
            'email', 'mail', 'notification' => defined(SecurityAuditEvent::class . '::CATEGORY_EMAIL') ? SecurityAuditEvent::CATEGORY_EMAIL : 'email',
            'record', 'request', 'update', 'delete', 'add', 'edit' => SecurityAuditEvent::CATEGORY_SYSTEM,
            'secret', 'sensitive', 'privacy' => SecurityAuditEvent::CATEGORY_SENSITIVE,
            default => SecurityAuditEvent::CATEGORY_SYSTEM,
        };
    }

    private function severityFor(string $action, string $outcome): string
    {
        if ($outcome === SecurityAuditEvent::OUTCOME_FAILURE || $outcome === SecurityAuditEvent::OUTCOME_DENIED) {
            return SecurityAuditEvent::SEVERITY_WARNING;
        }
        if (str_starts_with($action, 'admin.') || str_starts_with($action, 'auth.password')) {
            return SecurityAuditEvent::SEVERITY_NOTICE;
        }
        return SecurityAuditEvent::SEVERITY_INFO;
    }

    /** @param mixed $value @return mixed */
    private function sanitize(mixed $value): mixed
    {
        if (!is_array($value)) {
            return is_string($value) ? $this->redactString($value) : $value;
        }
        foreach ($value as $key => $item) {
            $keyString = strtolower((string)$key);
            foreach ($this->sensitiveKeys as $sensitiveKey) {
                if ($sensitiveKey !== '' && str_contains($keyString, $sensitiveKey)) {
                    $value[$key] = '[redacted]';
                    continue 2;
                }
            }
            $value[$key] = $this->sanitize($item);
        }
        return $value;
    }

    private function redactString(string $value): string
    {
        return preg_replace('/(Bearer\s+)[A-Za-z0-9._\-]+/i', '$1[redacted]', $value) ?? $value;
    }

    /** @param mixed $patterns */
    private function matchesAny(string $path, mixed $patterns): bool
    {
        if (!is_array($patterns)) {
            return false;
        }
        foreach ($patterns as $pattern) {
            if (!is_scalar($pattern)) {
                continue;
            }
            $pattern = strtolower(trim((string)$pattern));
            if ($pattern === '') {
                continue;
            }
            if ($path === trim($pattern, '/')) {
                return true;
            }
            if (str_ends_with($pattern, '*') && str_starts_with($path, trim(substr($pattern, 0, -1), '/'))) {
                return true;
            }
        }
        return false;
    }
}
