<?php
namespace Mnb\SecurityCore\Core;

use Mnb\SecurityCore\Auth\Stores\DatabaseTokenStore;
use Mnb\SecurityCore\Auth\Stores\FileTokenStore;
use Mnb\SecurityCore\Auth\Stores\RedisTokenStore;
use Mnb\SecurityCore\Cache\DatabaseCache;
use Mnb\SecurityCore\Cache\FileCache;
use Mnb\SecurityCore\Cache\RedisCache;
use Mnb\SecurityCore\Contracts\CacheInterface;
use Mnb\SecurityCore\Contracts\MalwareScannerInterface;
use Mnb\SecurityCore\Contracts\RateLimiterInterface;
use Mnb\SecurityCore\Contracts\TokenStoreInterface;
use Mnb\SecurityCore\Database\DatabaseConfig;
use Mnb\SecurityCore\Database\PdoConnectionFactory;
use Mnb\SecurityCore\Files\ClamAvMalwareScanner;
use Mnb\SecurityCore\Files\CompositeMalwareScanner;
use Mnb\SecurityCore\Files\FileUploadPolicy;
use Mnb\SecurityCore\Files\HeuristicMalwareScanner;
use Mnb\SecurityCore\Files\LocalPrivateStorage;
use Mnb\SecurityCore\Files\NullMalwareScanner;
use Mnb\SecurityCore\Files\SecureFileManager;
use Mnb\SecurityCore\RateLimit\DatabaseRateLimiter;
use Mnb\SecurityCore\RateLimit\FileRateLimiter;
use Mnb\SecurityCore\RateLimit\RedisRateLimiter;
use Mnb\SecurityCore\Memory\MemoryConfig;
use Mnb\SecurityCore\Memory\MemoryGuard;
use Mnb\SecurityCore\Logging\FileLogger;
use Mnb\SecurityCore\Security\ServerIdentityHider;
use PDO;

class SecurityKernel
{
    public function __construct(private array $config) {}

    public function fileCache(): FileCache
    {
        return new FileCache($this->config['paths']['cache']);
    }

    public function cache(?PDO $pdo = null, ?object $redis = null): CacheInterface
    {
        $driver = $this->config['cache']['driver'] ?? ($_ENV['CACHE_DRIVER'] ?? 'file');
        if ($driver === 'redis') {
            return new RedisCache($redis ?: $this->redis(), $this->config['cache']['prefix'] ?? 'mnb:cache:');
        }
        if ($driver === 'database') {
            return new DatabaseCache($pdo ?: $this->pdo(), $this->config['cache']['table'] ?? 'mnb_cache', $this->config['cache']['prefix'] ?? 'mnb:cache:');
        }
        return $this->fileCache();
    }

    public function fileRateLimiter(): FileRateLimiter
    {
        return new FileRateLimiter($this->config['paths']['cache'] . '/rate_limits');
    }

    public function rateLimiter(?PDO $pdo = null, ?object $redis = null): RateLimiterInterface
    {
        $driver = $this->config['rate_limiter']['driver'] ?? ($_ENV['RATE_LIMIT_DRIVER'] ?? 'file');
        if ($driver === 'redis') {
            return new RedisRateLimiter($redis ?: $this->redis(), $this->config['rate_limiter']['prefix'] ?? 'mnb:rate:');
        }
        if ($driver === 'database') {
            return new DatabaseRateLimiter($pdo ?: $this->pdo(), $this->config['rate_limiter']['table'] ?? 'mnb_rate_limits', $this->config['rate_limiter']['prefix'] ?? 'mnb:rate:');
        }
        return $this->fileRateLimiter();
    }

    public function tokenStore(?PDO $pdo = null, ?object $redis = null): TokenStoreInterface
    {
        $driver = $this->config['token_store']['driver'] ?? ($_ENV['TOKEN_STORE_DRIVER'] ?? 'file');
        if ($driver === 'redis') {
            return new RedisTokenStore($redis ?: $this->redis(), $this->config['token_store']['prefix'] ?? 'mnb:token:');
        }
        if ($driver === 'database') {
            return new DatabaseTokenStore($pdo ?: $this->pdo(), $this->config['token_store']['table'] ?? 'mnb_api_tokens');
        }
        return new FileTokenStore($this->config['paths']['tokens'] ?? ($this->config['paths']['cache'] . '/tokens.json'));
    }

    public function secureFileManager(?MalwareScannerInterface $scanner = null): SecureFileManager
    {
        $storage = new LocalPrivateStorage($this->config['paths']['private_storage']);
        $policy = FileUploadPolicy::fromConfig($this->config['uploads'], $this->config['limits']['upload_max_bytes']);
        return new SecureFileManager($storage, $policy, $this->config['paths']['quarantine'], $scanner ?: $this->malwareScanner());
    }

    public function malwareScanner(): MalwareScannerInterface
    {
        $config = $this->config['uploads']['scanner'] ?? [];
        $driver = $config['driver'] ?? ($_ENV['UPLOAD_SCANNER_DRIVER'] ?? 'heuristic');
        if ($driver === 'none') {
            return new NullMalwareScanner();
        }
        if ($driver === 'clamav') {
            return new ClamAvMalwareScanner(
                $config['clamav_binary'] ?? ($_ENV['CLAMAV_BINARY'] ?? 'clamscan'),
                (int)($config['timeout_seconds'] ?? 30),
                (bool)($config['fail_closed'] ?? false)
            );
        }
        if ($driver === 'composite') {
            return new CompositeMalwareScanner([
                new HeuristicMalwareScanner((int)($config['heuristic_read_bytes'] ?? 2097152)),
                new ClamAvMalwareScanner(
                    $config['clamav_binary'] ?? ($_ENV['CLAMAV_BINARY'] ?? 'clamscan'),
                    (int)($config['timeout_seconds'] ?? 30),
                    (bool)($config['fail_closed'] ?? false)
                ),
            ]);
        }
        return new HeuristicMalwareScanner((int)($config['heuristic_read_bytes'] ?? 2097152));
    }

    public function memoryGuard(): MemoryGuard
    {
        $logger = new FileLogger($this->config['paths']['logs'] . '/memory.log');
        return new MemoryGuard(MemoryConfig::fromArray($this->config['memory'] ?? []), $logger);
    }

    public function serverIdentityHider(): ServerIdentityHider
    {
        return new ServerIdentityHider($this->config['origin_protection'] ?? []);
    }

    public function pdo(): PDO
    {
        return (new PdoConnectionFactory())->create(DatabaseConfig::fromArray($this->config['database'] ?? []))->pdo();
    }

    private function redis(): object
    {
        if (!class_exists('Redis')) {
            throw new \RuntimeException('Redis extension is not installed. Use file/database driver or install ext-redis.');
        }
        $redis = new \Redis();
        $config = $this->config['redis'] ?? [];
        $redis->connect($config['host'] ?? '127.0.0.1', (int)($config['port'] ?? 6379), (float)($config['timeout'] ?? 1.5));
        if (!empty($config['password'])) {
            $redis->auth($config['password']);
        }
        if (isset($config['database'])) {
            $redis->select((int)$config['database']);
        }
        return $redis;
    }
}
