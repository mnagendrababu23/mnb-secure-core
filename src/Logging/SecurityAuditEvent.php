<?php
namespace Mnb\SecurityCore\Logging;

use Mnb\SecurityCore\Http\Request;

class SecurityAuditEvent
{
    public const OUTCOME_SUCCESS = 'success';
    public const OUTCOME_FAILURE = 'failure';
    public const OUTCOME_DENIED = 'denied';
    public const OUTCOME_WARNING = 'warning';
    public const OUTCOME_INFO = 'info';

    public const SEVERITY_INFO = 'info';
    public const SEVERITY_NOTICE = 'notice';
    public const SEVERITY_WARNING = 'warning';
    public const SEVERITY_CRITICAL = 'critical';

    public const CATEGORY_AUTH = 'auth';
    public const CATEGORY_TOKEN = 'token';
    public const CATEGORY_UPLOAD = 'upload';
    public const CATEGORY_ADMIN = 'admin';
    public const CATEGORY_DATABASE = 'database';
    public const CATEGORY_SENSITIVE = 'sensitive';
    public const CATEGORY_SYSTEM = 'system';

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function __construct(
        public readonly string $category,
        public readonly string $action,
        public readonly string $outcome = self::OUTCOME_INFO,
        public readonly string $severity = self::SEVERITY_INFO,
        public readonly array $actor = [],
        public readonly array $target = [],
        public readonly array $context = [],
        public readonly array $meta = [],
        public readonly ?string $eventId = null,
        public readonly ?string $occurredAt = null
    ) {
        self::assertSlug($category, 'category');
        self::assertSlug($action, 'action');
        self::assertAllowed($outcome, [self::OUTCOME_SUCCESS, self::OUTCOME_FAILURE, self::OUTCOME_DENIED, self::OUTCOME_WARNING, self::OUTCOME_INFO], 'outcome');
        self::assertAllowed($severity, [self::SEVERITY_INFO, self::SEVERITY_NOTICE, self::SEVERITY_WARNING, self::SEVERITY_CRITICAL], 'severity');
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public static function make(string $category, string $action, string $outcome = self::OUTCOME_INFO, string $severity = self::SEVERITY_INFO, array $actor = [], array $target = [], array $context = [], array $meta = []): self
    {
        return new self($category, $action, $outcome, $severity, $actor, $target, $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $context @param array<string,mixed> $meta */
    public static function login(string $outcome, array $actor = [], array $context = [], array $meta = []): self
    {
        $severity = $outcome === self::OUTCOME_SUCCESS ? self::SEVERITY_INFO : self::SEVERITY_WARNING;
        return self::make(self::CATEGORY_AUTH, 'login', $outcome, $severity, $actor, [], $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public static function token(string $action, string $outcome, array $actor = [], array $target = [], array $context = [], array $meta = []): self
    {
        $severity = $outcome === self::OUTCOME_FAILURE ? self::SEVERITY_WARNING : self::SEVERITY_INFO;
        return self::make(self::CATEGORY_TOKEN, $action, $outcome, $severity, $actor, $target, $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public static function upload(string $outcome, array $actor = [], array $target = [], array $context = [], array $meta = []): self
    {
        $severity = $outcome === self::OUTCOME_SUCCESS ? self::SEVERITY_INFO : self::SEVERITY_WARNING;
        return self::make(self::CATEGORY_UPLOAD, 'upload', $outcome, $severity, $actor, $target, $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public static function admin(string $action, string $outcome = self::OUTCOME_SUCCESS, array $actor = [], array $target = [], array $context = [], array $meta = []): self
    {
        return self::make(self::CATEGORY_ADMIN, $action, $outcome, self::SEVERITY_NOTICE, $actor, $target, $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public static function database(string $action, string $outcome = self::OUTCOME_SUCCESS, array $actor = [], array $target = [], array $context = [], array $meta = []): self
    {
        return self::make(self::CATEGORY_DATABASE, $action, $outcome, self::SEVERITY_INFO, $actor, $target, $context, $meta);
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public static function sensitive(string $action, string $outcome = self::OUTCOME_SUCCESS, array $actor = [], array $target = [], array $context = [], array $meta = []): self
    {
        return self::make(self::CATEGORY_SENSITIVE, $action, $outcome, self::SEVERITY_NOTICE, $actor, $target, $context, $meta);
    }

    /** @return array<string,mixed> */
    public function toRecord(): array
    {
        return [
            'event_id' => $this->eventId ?: self::newEventId(),
            'time' => $this->occurredAt ?: date('c'),
            'category' => $this->category,
            'action' => $this->action,
            'outcome' => $this->outcome,
            'severity' => $this->severity,
            'actor' => $this->actor,
            'target' => $this->target,
            'context' => $this->context,
            'meta' => $this->meta,
        ];
    }

    /** @return array<string,mixed> */
    public static function contextFromRequest(Request $request, array $extra = []): array
    {
        return array_filter([
            'ip' => $request->ip(),
            'remote_ip' => method_exists($request, 'remoteIp') ? $request->remoteIp() : null,
            'method' => $request->method(),
            'path' => $request->path(),
            'host' => method_exists($request, 'effectiveHost') ? $request->effectiveHost() : null,
            'user_agent' => $request->header('user-agent'),
        ] + $extra, fn($value) => $value !== null && $value !== '');
    }

    public static function fingerprint(string $value, int $length = 12): string
    {
        return substr(hash('sha256', $value), 0, max(6, min(64, $length)));
    }

    private static function newEventId(): string
    {
        try {
            return bin2hex(random_bytes(16));
        } catch (\Throwable) {
            return str_replace('.', '', uniqid('audit_', true));
        }
    }

    private static function assertSlug(string $value, string $field): void
    {
        if (!preg_match('/^[a-z][a-z0-9_.:-]{1,95}$/', $value)) {
            throw new \InvalidArgumentException("Audit event {$field} must be a safe slug.");
        }
    }

    /** @param list<string> $allowed */
    private static function assertAllowed(string $value, array $allowed, string $field): void
    {
        if (!in_array($value, $allowed, true)) {
            throw new \InvalidArgumentException("Audit event {$field} is invalid.");
        }
    }
}
