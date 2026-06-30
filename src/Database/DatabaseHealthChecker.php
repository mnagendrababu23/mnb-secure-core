<?php
namespace Mnb\SecurityCore\Database;

use Mnb\SecurityCore\Contracts\DatabaseConnectionInterface;
use PDO;
use Throwable;

final class DatabaseHealthChecker
{
    public function __construct(private array $config = [], private ?DatabaseConnectionInterface $connection = null) {}

    /** @return array<string,mixed> */
    public function check(bool $connect = false): array
    {
        $issues = [];
        $db = is_array($this->config['database'] ?? null) ? $this->config['database'] : [];
        $driver = (string)($db['driver'] ?? 'mysql');
        if (!in_array($driver, ['mysql', 'sqlite', 'pgsql'], true)) {
            $issues[] = ['level' => 'high', 'key' => 'invalid_driver', 'message' => 'Database driver should be mysql, sqlite, or pgsql.'];
        }
        $charset = (string)($db['charset'] ?? 'utf8mb4');
        if ($driver !== 'sqlite' && !in_array(strtolower($charset), ['utf8mb4', 'utf8'], true)) {
            $issues[] = ['level' => 'medium', 'key' => 'unsafe_charset', 'message' => 'Use utf8mb4 for MySQL/MariaDB connections.'];
        }
        $cfg = DatabaseConfig::fromArray($db);
        $options = $cfg->securePdoOptions();
        if (($options[PDO::ATTR_EMULATE_PREPARES] ?? true) !== false) {
            $issues[] = ['level' => 'high', 'key' => 'emulated_prepares_enabled', 'message' => 'PDO emulated prepares should be disabled.'];
        }
        if (($options[PDO::ATTR_ERRMODE] ?? null) !== PDO::ERRMODE_EXCEPTION) {
            $issues[] = ['level' => 'high', 'key' => 'pdo_exceptions_disabled', 'message' => 'PDO should use ERRMODE_EXCEPTION.'];
        }
        $connection = ['checked' => false, 'passed' => null, 'error' => null];
        if ($connect && $this->connection !== null) {
            $connection['checked'] = true;
            try {
                $this->connection->fetchOne('SELECT 1');
                $connection['passed'] = true;
            } catch (Throwable $e) {
                $connection['passed'] = false;
                $connection['error'] = get_class($e);
                $issues[] = ['level' => 'high', 'key' => 'connection_failed', 'message' => 'Database connection check failed.'];
            }
        }
        $errors = array_values(array_filter($issues, fn(array $issue): bool => in_array($issue['level'], ['critical', 'high'], true)));
        return [
            'passed' => count($errors) === 0,
            'driver' => $driver,
            'dsn_shape' => preg_replace('/password=[^;]+/i', 'password=[redacted]', $cfg->dsn),
            'secure_pdo_options' => [
                'errmode_exception' => ($options[PDO::ATTR_ERRMODE] ?? null) === PDO::ERRMODE_EXCEPTION,
                'emulated_prepares_disabled' => ($options[PDO::ATTR_EMULATE_PREPARES] ?? true) === false,
                'stringify_fetches_disabled' => ($options[PDO::ATTR_STRINGIFY_FETCHES] ?? true) === false,
            ],
            'connection' => $connection,
            'issues' => $issues,
        ];
    }
}
