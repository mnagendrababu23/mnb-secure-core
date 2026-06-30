<?php
namespace Mnb\SecurityCore\Core;

use InvalidArgumentException;
use PDO;
use RuntimeException;
use Throwable;

class StorageDriverResolver
{
    public const FILE = 'file';
    public const REDIS = 'redis';
    public const DATABASE = 'database';

    /** @return array<int,string> */
    public static function supportedDrivers(): array
    {
        return [self::FILE, self::REDIS, self::DATABASE];
    }

    public static function driver(array $config, string $section, string $envKey, string $default = self::FILE): string
    {
        $sectionConfig = $config[$section] ?? [];
        if ($sectionConfig !== [] && !is_array($sectionConfig)) {
            throw new InvalidArgumentException("Storage config section '{$section}' must be an array.");
        }

        $raw = $sectionConfig['driver'] ?? ($_ENV[$envKey] ?? $default);
        if (!is_scalar($raw) || trim((string)$raw) === '') {
            throw new InvalidArgumentException("Storage driver for '{$section}' must be one of: " . implode(', ', self::supportedDrivers()) . '.');
        }

        $driver = strtolower(trim((string)$raw));
        if (!in_array($driver, self::supportedDrivers(), true)) {
            throw new InvalidArgumentException("Unsupported storage driver '{$raw}' for '{$section}'. Supported drivers: " . implode(', ', self::supportedDrivers()) . '.');
        }

        return $driver;
    }

    public static function prefix(mixed $value, string $default, string $label): string
    {
        if ($value === null || $value === '') {
            return $default;
        }
        if (!is_scalar($value)) {
            throw new InvalidArgumentException("{$label} prefix must be a string.");
        }
        return (string)$value;
    }

    public static function directoryPath(mixed $path, string $label): string
    {
        if (!is_scalar($path) || trim((string)$path) === '') {
            throw new InvalidArgumentException("{$label} path must be a non-empty string.");
        }

        $path = rtrim((string)$path, DIRECTORY_SEPARATOR);
        if ($path === '') {
            throw new InvalidArgumentException("{$label} path must be a non-empty string.");
        }

        if (is_file($path)) {
            throw new InvalidArgumentException("{$label} path points to a file, but a directory is required: {$path}");
        }

        if (!is_dir($path) && !@mkdir($path, 0775, true) && !is_dir($path)) {
            throw new RuntimeException("Unable to create {$label} directory: {$path}");
        }

        if (!is_writable($path)) {
            throw new RuntimeException("{$label} directory is not writable: {$path}");
        }

        return $path;
    }

    public static function filePath(mixed $path, string $label): string
    {
        if (!is_scalar($path) || trim((string)$path) === '') {
            throw new InvalidArgumentException("{$label} file path must be a non-empty string.");
        }

        $path = (string)$path;
        if (is_dir($path)) {
            throw new InvalidArgumentException("{$label} file path points to a directory: {$path}");
        }

        $dir = dirname($path);
        self::directoryPath($dir, $label . ' directory');

        return $path;
    }

    /** @param array<int,string> $methods */
    public static function assertRedisClient(object $redis, array $methods, string $label): void
    {
        foreach ($methods as $method) {
            if (!method_exists($redis, $method)) {
                throw new InvalidArgumentException("Redis client for {$label} driver must provide method {$method}().");
            }
        }
    }

    public static function assertRedisExtension(): void
    {
        if (!class_exists('Redis')) {
            throw new RuntimeException('Redis extension is not installed. Use file/database driver, inject a compatible Redis client, or install ext-redis.');
        }
    }

    public static function pdoDriver(PDO $pdo): ?string
    {
        try {
            $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        } catch (Throwable) {
            return null;
        }

        return is_string($driver) && $driver !== '' ? strtolower($driver) : null;
    }

    public static function assertDatabaseStoreDriver(PDO $pdo, string $label): void
    {
        $driver = self::pdoDriver($pdo);
        if ($driver === null) {
            return;
        }

        if (!in_array($driver, ['mysql'], true)) {
            throw new RuntimeException("Database-backed {$label} storage currently requires a MySQL/MariaDB PDO connection. Detected '{$driver}'. Use file/redis driver or configure DB_DRIVER=mysql.");
        }
    }
}
