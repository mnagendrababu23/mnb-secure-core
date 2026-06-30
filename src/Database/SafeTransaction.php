<?php
namespace Mnb\SecurityCore\Database;

use InvalidArgumentException;
use Mnb\SecurityCore\Contracts\DatabaseConnectionInterface;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Authz\TenantContext;
use Throwable;

final class SafeTransaction
{
    private int $operations = 0;

    public function __construct(
        private DatabaseConnectionInterface $connection,
        private ?object $audit = null,
        private int $maxOperations = 50
    ) {}

    /** @template T @param callable(self):T $callback @return T */
    public function run(TenantContext $context, callable $callback): mixed
    {
        $this->audit(DatabaseAuditEvents::TRANSACTION_BEGIN, $context, ['max_operations' => $this->maxOperations]);
        try {
            $result = $this->connection->transaction(function () use ($callback) {
                return $callback($this);
            });
            $this->audit(DatabaseAuditEvents::TRANSACTION_COMMIT, $context, ['operations' => $this->operations]);
            return $result;
        } catch (Throwable $e) {
            $this->audit(DatabaseAuditEvents::TRANSACTION_ROLLBACK, $context, ['operations' => $this->operations, 'error_class' => get_class($e)]);
            throw $e;
        }
    }

    public function countOperation(): void
    {
        $this->operations++;
        if ($this->operations > $this->maxOperations) {
            throw new InvalidArgumentException("Database transaction operation count exceeds {$this->maxOperations}.");
        }
    }

    private function audit(string $action, TenantContext $context, array $meta = []): void
    {
        if (!$this->audit) {
            return;
        }
        if (method_exists($this->audit, 'recordEvent')) {
            $this->audit->recordEvent(SecurityAuditEvent::database($action, SecurityAuditEvent::OUTCOME_SUCCESS, ['user_id' => $context->userId], ['transaction' => 'database'], [], $meta));
            return;
        }
        if (method_exists($this->audit, 'record')) {
            $this->audit->record($action, ['user_id' => $context->userId], ['transaction' => 'database'], $meta);
        }
    }
}
