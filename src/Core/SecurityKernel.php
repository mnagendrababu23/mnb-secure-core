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
use Mnb\SecurityCore\RateLimit\RateLimitPolicy;
use Mnb\SecurityCore\RateLimit\RateLimitPolicyRegistry;
use Mnb\SecurityCore\Http\Middleware\RateLimitPolicyMiddleware;
use Mnb\SecurityCore\Http\Middleware\AutoAuditMiddleware;
use Mnb\SecurityCore\Http\Middleware\CorsMiddleware;
use Mnb\SecurityCore\Http\Middleware\RequestTrustMiddleware;
use Mnb\SecurityCore\Http\Middleware\SecurityHeadersMiddleware;
use Mnb\SecurityCore\Http\Middleware\InputValidationMiddleware;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Memory\MemoryConfig;
use Mnb\SecurityCore\Memory\MemoryGuard;
use Mnb\SecurityCore\Logging\FileLogger;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Mnb\SecurityCore\Logging\NullSecurityAuditTrail;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;
use Mnb\SecurityCore\Logging\AutoAuditLogger;
use Mnb\SecurityCore\Contracts\LoggerInterface;
use Mnb\SecurityCore\Suggestions\AutoSuggestionEngine;
use Mnb\SecurityCore\Validation\InputSanitizer;
use Mnb\SecurityCore\Validation\InputValidator;
use Mnb\SecurityCore\Security\ServerIdentityHider;
use PDO;

class SecurityKernel
{
    public function __construct(private array $config) {}

    public function fileCache(): FileCache
    {
        return new FileCache(StorageDriverResolver::directoryPath($this->config['paths']['cache'] ?? '', 'cache'));
    }

    public function cache(?PDO $pdo = null, ?object $redis = null): CacheInterface
    {
        $driver = StorageDriverResolver::driver($this->config, 'cache', 'CACHE_DRIVER');
        $cacheConfig = is_array($this->config['cache'] ?? null) ? $this->config['cache'] : [];

        if ($driver === StorageDriverResolver::REDIS) {
            $client = $redis ?: $this->redis();
            StorageDriverResolver::assertRedisClient($client, ['get', 'set', 'del'], 'cache');
            return new RedisCache($client, StorageDriverResolver::prefix($cacheConfig['prefix'] ?? null, 'mnb:cache:', 'cache'));
        }

        if ($driver === StorageDriverResolver::DATABASE) {
            $connection = $pdo ?: $this->pdo();
            StorageDriverResolver::assertDatabaseStoreDriver($connection, 'cache');
            return new DatabaseCache($connection, $cacheConfig['table'] ?? 'mnb_cache', StorageDriverResolver::prefix($cacheConfig['prefix'] ?? null, 'mnb:cache:', 'cache'));
        }

        return $this->fileCache();
    }

    public function fileRateLimiter(): FileRateLimiter
    {
        $cachePath = StorageDriverResolver::directoryPath($this->config['paths']['cache'] ?? '', 'cache');
        return new FileRateLimiter(StorageDriverResolver::directoryPath($cachePath . '/rate_limits', 'rate limiter cache'));
    }

    public function rateLimiter(?PDO $pdo = null, ?object $redis = null): RateLimiterInterface
    {
        $driver = StorageDriverResolver::driver($this->config, 'rate_limiter', 'RATE_LIMIT_DRIVER');
        $rateConfig = is_array($this->config['rate_limiter'] ?? null) ? $this->config['rate_limiter'] : [];

        if ($driver === StorageDriverResolver::REDIS) {
            $client = $redis ?: $this->redis();
            StorageDriverResolver::assertRedisClient($client, ['incr', 'expire', 'del'], 'rate limiter');
            return new RedisRateLimiter($client, StorageDriverResolver::prefix($rateConfig['prefix'] ?? null, 'mnb:rate:', 'rate limiter'));
        }

        if ($driver === StorageDriverResolver::DATABASE) {
            $connection = $pdo ?: $this->pdo();
            StorageDriverResolver::assertDatabaseStoreDriver($connection, 'rate limiter');
            return new DatabaseRateLimiter($connection, $rateConfig['table'] ?? 'mnb_rate_limits', StorageDriverResolver::prefix($rateConfig['prefix'] ?? null, 'mnb:rate:', 'rate limiter'));
        }

        return $this->fileRateLimiter();
    }


    public function rateLimitPolicies(): RateLimitPolicyRegistry
    {
        return RateLimitPolicyRegistry::fromConfig($this->config);
    }

    public function rateLimitPolicy(string $name): RateLimitPolicy
    {
        return $this->rateLimitPolicies()->get($name);
    }

    public function rateLimitMiddleware(string $policyName = 'api', ?string $routeName = null, ?PDO $pdo = null, ?object $redis = null): RateLimitPolicyMiddleware
    {
        return new RateLimitPolicyMiddleware($this->rateLimiter($pdo, $redis), $this->rateLimitPolicies(), $policyName, $routeName);
    }

    public function tokenStore(?PDO $pdo = null, ?object $redis = null): TokenStoreInterface
    {
        $driver = StorageDriverResolver::driver($this->config, 'token_store', 'TOKEN_STORE_DRIVER');
        $tokenConfig = is_array($this->config['token_store'] ?? null) ? $this->config['token_store'] : [];

        if ($driver === StorageDriverResolver::REDIS) {
            $client = $redis ?: $this->redis();
            StorageDriverResolver::assertRedisClient($client, ['get', 'set', 'sAdd', 'sMembers'], 'token store');
            return new RedisTokenStore($client, StorageDriverResolver::prefix($tokenConfig['prefix'] ?? null, 'mnb:token:', 'token store'));
        }

        if ($driver === StorageDriverResolver::DATABASE) {
            $connection = $pdo ?: $this->pdo();
            StorageDriverResolver::assertDatabaseStoreDriver($connection, 'token store');
            return new DatabaseTokenStore($connection, $tokenConfig['table'] ?? 'mnb_api_tokens');
        }

        $defaultTokenFile = StorageDriverResolver::directoryPath($this->config['paths']['cache'] ?? '', 'cache') . '/tokens.json';
        return new FileTokenStore(StorageDriverResolver::filePath($this->config['paths']['tokens'] ?? $defaultTokenFile, 'token store'));
    }

    public function uploadPolicy(?string $profile = null): FileUploadPolicy
    {
        return FileUploadPolicy::fromConfig(
            is_array($this->config['uploads'] ?? null) ? $this->config['uploads'] : [],
            (int)($this->config['limits']['upload_max_bytes'] ?? 10 * 1024 * 1024),
            (string)($this->config['app']['env'] ?? 'local'),
            $profile
        );
    }

    public function secureFileManager(?MalwareScannerInterface $scanner = null, ?string $profile = null, ?SecurityAuditTrail $audit = null): SecureFileManager
    {
        $storage = new LocalPrivateStorage($this->config['paths']['private_storage']);
        $policy = $this->uploadPolicy($profile);
        return new SecureFileManager($storage, $policy, $this->config['paths']['quarantine'], $scanner ?: $this->malwareScanner(), $audit);
    }

    public function auditLogger(): TamperEvidentAuditLogger
    {
        $auditConfig = is_array($this->config['audit'] ?? null) ? $this->config['audit'] : [];
        $file = (string)($auditConfig['file'] ?? (rtrim((string)($this->config['paths']['audit'] ?? 'storage/audit'), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'security-audit.log'));
        return new TamperEvidentAuditLogger($file);
    }

    public function auditTrail(?LoggerInterface $logger = null): SecurityAuditTrail
    {
        $auditConfig = is_array($this->config['audit'] ?? null) ? $this->config['audit'] : [];
        if (array_key_exists('enabled', $auditConfig) && $auditConfig['enabled'] === false) {
            return new NullSecurityAuditTrail();
        }
        if ($logger === null && !empty($auditConfig['mirror_to_log'])) {
            $logFile = (string)($auditConfig['log_file'] ?? (rtrim((string)($this->config['paths']['logs'] ?? 'storage/logs'), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'security-audit.log'));
            $logger = new FileLogger($logFile);
        }
        return new SecurityAuditTrail($this->auditLogger(), $logger);
    }

    public function autoAuditLogger(?SecurityAuditTrail $audit = null): AutoAuditLogger
    {
        $auditConfig = is_array($this->config['audit'] ?? null) ? $this->config['audit'] : [];
        $autoConfig = is_array($auditConfig['auto'] ?? null) ? $auditConfig['auto'] : [];
        return new AutoAuditLogger($audit ?: $this->auditTrail(), $autoConfig);
    }

    public function autoAuditMiddleware(?SecurityAuditTrail $audit = null): AutoAuditMiddleware
    {
        $auditConfig = is_array($this->config['audit'] ?? null) ? $this->config['audit'] : [];
        $autoConfig = is_array($auditConfig['auto'] ?? null) ? $auditConfig['auto'] : [];
        return new AutoAuditMiddleware($this->autoAuditLogger($audit), $autoConfig);
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

    public function requestFromGlobals(): Request
    {
        return Request::fromGlobals($this->config['app']['trusted_proxies'] ?? []);
    }

    public function requestTrustMiddleware(): RequestTrustMiddleware
    {
        return new RequestTrustMiddleware($this->config['origin_protection'] ?? []);
    }

    public function corsMiddleware(): CorsMiddleware
    {
        return new CorsMiddleware($this->config['cors'] ?? []);
    }

    public function securityHeadersMiddleware(?callable $nonceResolver = null): SecurityHeadersMiddleware
    {
        return new SecurityHeadersMiddleware($this->config['security_headers'] ?? [], $nonceResolver);
    }

    public function inputValidator(): InputValidator
    {
        return new InputValidator();
    }

    public function inputSanitizer(): InputSanitizer
    {
        return new InputSanitizer();
    }

    public function inputValidationMiddleware(array $routePolicies = []): InputValidationMiddleware
    {
        $config = is_array($this->config['request_validation'] ?? null) ? $this->config['request_validation'] : [];
        if ($routePolicies !== []) {
            $config['routes'] = array_merge(is_array($config['routes'] ?? null) ? $config['routes'] : [], $routePolicies);
        }
        return new InputValidationMiddleware($config, $this->inputValidator(), $this->inputSanitizer());
    }

    public function suggestionEngine(array $customRules = []): AutoSuggestionEngine
    {
        $suggestionConfig = is_array($this->config['suggestions'] ?? null) ? $this->config['suggestions'] : [];
        $rules = is_array($suggestionConfig['rules'] ?? null) ? $suggestionConfig['rules'] : [];
        return new AutoSuggestionEngine(array_merge($rules, $customRules));
    }

    public function pdo(): PDO
    {
        return (new PdoConnectionFactory())->create(DatabaseConfig::fromArray($this->config['database'] ?? []))->pdo();
    }

    private function redis(): object
    {
        StorageDriverResolver::assertRedisExtension();

        $config = is_array($this->config['redis'] ?? null) ? $this->config['redis'] : [];
        $host = $config['host'] ?? '127.0.0.1';
        if (!is_scalar($host) || trim((string)$host) === '') {
            throw new \InvalidArgumentException('Redis host must be a non-empty string.');
        }

        $port = (int)($config['port'] ?? 6379);
        if ($port < 1 || $port > 65535) {
            throw new \InvalidArgumentException('Redis port must be between 1 and 65535.');
        }

        $timeout = (float)($config['timeout'] ?? 1.5);
        if ($timeout <= 0) {
            throw new \InvalidArgumentException('Redis timeout must be greater than zero.');
        }

        $redis = new \Redis();
        $connected = $redis->connect((string)$host, $port, $timeout);
        if ($connected === false) {
            throw new \RuntimeException('Unable to connect to Redis at ' . (string)$host . ':' . $port . '.');
        }

        if (isset($config['password']) && (string)$config['password'] !== '') {
            $redis->auth((string)$config['password']);
        }

        if (isset($config['database']) && $config['database'] !== null && $config['database'] !== '') {
            $database = (int)$config['database'];
            if ($database < 0) {
                throw new \InvalidArgumentException('Redis database index must be zero or greater.');
            }
            $redis->select($database);
        }

        return $redis;
    }
}
