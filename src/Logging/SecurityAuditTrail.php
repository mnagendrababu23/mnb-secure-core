<?php
namespace Mnb\SecurityCore\Logging;

use Mnb\SecurityCore\Contracts\LoggerInterface;
use Mnb\SecurityCore\Http\Request;

class SecurityAuditTrail
{
    public function __construct(
        private TamperEvidentAuditLogger $audit,
        private ?LoggerInterface $logger = null
    ) {}

    public function record(SecurityAuditEvent $event): array
    {
        $entry = $this->audit->recordEvent($event);
        $this->mirrorToLogger($entry);
        return $entry;
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function loginSuccess(array $actor, array $context = [], array $meta = []): array
    {
        return $this->record(SecurityAuditEvent::login(SecurityAuditEvent::OUTCOME_SUCCESS, $actor, $context, $meta));
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function loginFailure(array $actor = [], array $context = [], array $meta = []): array
    {
        return $this->record(SecurityAuditEvent::login(SecurityAuditEvent::OUTCOME_FAILURE, $actor, $context, $meta));
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function tokenIssued(array $actor, array $target = [], array $context = [], array $meta = []): array
    {
        return $this->record(SecurityAuditEvent::token('issued', SecurityAuditEvent::OUTCOME_SUCCESS, $actor, $target, $context, $meta));
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function tokenValidated(array $actor, array $target = [], array $context = [], array $meta = []): array
    {
        return $this->record(SecurityAuditEvent::token('validated', SecurityAuditEvent::OUTCOME_SUCCESS, $actor, $target, $context, $meta));
    }

    /** @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function tokenRejected(array $target = [], array $context = [], array $meta = []): array
    {
        return $this->record(SecurityAuditEvent::token('rejected', SecurityAuditEvent::OUTCOME_FAILURE, [], $target, $context, $meta));
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function tokenRevoked(array $actor = [], array $target = [], array $context = [], array $meta = []): array
    {
        return $this->record(SecurityAuditEvent::token('revoked', SecurityAuditEvent::OUTCOME_SUCCESS, $actor, $target, $context, $meta));
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function uploadAccepted(array $actor = [], array $target = [], array $context = [], array $meta = []): array
    {
        return $this->record(SecurityAuditEvent::upload(SecurityAuditEvent::OUTCOME_SUCCESS, $actor, $target, $context, $meta));
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function uploadRejected(array $actor = [], array $target = [], array $context = [], array $meta = []): array
    {
        return $this->record(SecurityAuditEvent::upload(SecurityAuditEvent::OUTCOME_FAILURE, $actor, $target, $context, $meta));
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function adminAction(string $action, array $actor, array $target = [], array $context = [], array $meta = []): array
    {
        return $this->record(SecurityAuditEvent::admin($action, SecurityAuditEvent::OUTCOME_SUCCESS, $actor, $target, $context, $meta));
    }

    /** @param array<string,mixed> $actor @param array<string,mixed> $target @param array<string,mixed> $context @param array<string,mixed> $meta */
    public function sensitiveAction(string $action, array $actor = [], array $target = [], array $context = [], array $meta = []): array
    {
        return $this->record(SecurityAuditEvent::sensitive($action, SecurityAuditEvent::OUTCOME_SUCCESS, $actor, $target, $context, $meta));
    }

    /** @return array<string,mixed> */
    public static function contextFromRequest(Request $request, array $extra = []): array
    {
        return SecurityAuditEvent::contextFromRequest($request, $extra);
    }

    /** @param array<string,mixed> $entry */
    private function mirrorToLogger(array $entry): void
    {
        if (!$this->logger) {
            return;
        }

        $message = 'Security audit event: ' . ($entry['category'] ?? 'unknown') . '.' . ($entry['action'] ?? 'unknown');
        $severity = (string)($entry['severity'] ?? SecurityAuditEvent::SEVERITY_INFO);
        $context = [
            'event_id' => $entry['event_id'] ?? null,
            'category' => $entry['category'] ?? null,
            'action' => $entry['action'] ?? null,
            'outcome' => $entry['outcome'] ?? null,
            'actor' => $entry['actor'] ?? [],
            'target' => $entry['target'] ?? [],
            'context' => $entry['context'] ?? [],
        ];

        if (in_array($severity, [SecurityAuditEvent::SEVERITY_WARNING, SecurityAuditEvent::SEVERITY_CRITICAL], true)) {
            $severity === SecurityAuditEvent::SEVERITY_CRITICAL
                ? $this->logger->error($message, $context)
                : $this->logger->warning($message, $context);
            return;
        }
        $this->logger->info($message, $context);
    }
}
