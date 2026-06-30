<?php
namespace Mnb\SecurityCore\Core;

use Mnb\SecurityCore\Auth\Stores\DatabaseTokenStore;
use Mnb\SecurityCore\Auth\Csrf;
use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Auth\AuthenticationRegistry;
use Mnb\SecurityCore\Auth\AuthenticationStrategy;
use Mnb\SecurityCore\Auth\AuthWorkflowService;
use Mnb\SecurityCore\Auth\PasswordHasher;
use Mnb\SecurityCore\Auth\PasswordPolicy;
use Mnb\SecurityCore\Auth\UserProviderInterface;
use Mnb\SecurityCore\Authorization\AuthorizationPolicy;
use Mnb\SecurityCore\Authorization\AuthorizationRegistry;
use Mnb\SecurityCore\Http\Middleware\AuthorizationMiddleware;
use Mnb\SecurityCore\Http\Middleware\ApiTokenMiddleware;
use Mnb\SecurityCore\Http\Middleware\AuthenticationMiddleware;
use Mnb\SecurityCore\Http\Middleware\ContentTypeMiddleware;
use Mnb\SecurityCore\Http\Middleware\CsrfMiddleware;
use Mnb\SecurityCore\Http\Middleware\HttpsMiddleware;
use Mnb\SecurityCore\Http\Middleware\JsonBodyParserMiddleware;
use Mnb\SecurityCore\Http\Middleware\RequestIdMiddleware;
use Mnb\SecurityCore\Http\Middleware\RequestMethodMiddleware;
use Mnb\SecurityCore\Http\Middleware\RequestSizeMiddleware;
use Mnb\SecurityCore\Http\Middleware\ServerIdentityProtectionMiddleware;
use Mnb\SecurityCore\Http\Middleware\SuspiciousRequestMiddleware;
use Mnb\SecurityCore\Http\Middleware\TrustedHostMiddleware;
use Mnb\SecurityCore\Http\Middleware\WebhookSignatureMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\RequestReceivingProfile;
use Mnb\SecurityCore\Http\RequestReceivingRegistry;
use Mnb\SecurityCore\Http\SecureRequestReceiver;
use Mnb\SecurityCore\Http\WebhookSignatureVerifier;
use Mnb\SecurityCore\Auth\Stores\FileTokenStore;
use Mnb\SecurityCore\Auth\Stores\RedisTokenStore;
use Mnb\SecurityCore\Cache\DatabaseCache;
use Mnb\SecurityCore\Cache\FileCache;
use Mnb\SecurityCore\Cache\RedisCache;
use Mnb\SecurityCore\Cache\CacheInvalidator;
use Mnb\SecurityCore\Cache\CacheKeyBuilder;
use Mnb\SecurityCore\Cache\CachePolicy;
use Mnb\SecurityCore\Cache\CacheRegistry;
use Mnb\SecurityCore\Cache\CacheStampedeGuard;
use Mnb\SecurityCore\Cache\EncryptedCache;
use Mnb\SecurityCore\Cache\SafeCacheSerializer;
use Mnb\SecurityCore\Cache\SecureCache;
use Mnb\SecurityCore\Cache\TaggedCache;
use Mnb\SecurityCore\Contracts\CacheInterface;
use Mnb\SecurityCore\Contracts\MalwareScannerInterface;
use Mnb\SecurityCore\Contracts\RateLimiterInterface;
use Mnb\SecurityCore\Contracts\TokenStoreInterface;
use Mnb\SecurityCore\Env\ArraySecretProvider;
use Mnb\SecurityCore\Env\EnvSecretProvider;
use Mnb\SecurityCore\Env\EnvironmentValidator;
use Mnb\SecurityCore\Env\KeyDeriver;
use Mnb\SecurityCore\Env\SecretHealthReport;
use Mnb\SecurityCore\Env\SecretInventory;
use Mnb\SecurityCore\Env\SecretManager;
use Mnb\SecurityCore\Env\SecretProviderInterface;
use Mnb\SecurityCore\Env\SecretRedactor;
use Mnb\SecurityCore\Env\SecretRotationReport;
use Mnb\SecurityCore\Database\DatabaseConfig;
use Mnb\SecurityCore\Database\PdoConnectionFactory;
use Mnb\SecurityCore\Database\DatabaseHealthChecker;
use Mnb\SecurityCore\Database\DatabaseOperationPolicy;
use Mnb\SecurityCore\Database\DatabasePolicyRegistry;
use Mnb\SecurityCore\Database\DatabasePrivilegeInspector;
use Mnb\SecurityCore\Database\DatabaseResultFilter;
use Mnb\SecurityCore\Database\QueryComplexityGuard;
use Mnb\SecurityCore\Database\QueryCostPolicy;
use Mnb\SecurityCore\Database\RawQueryGuard;
use Mnb\SecurityCore\Database\SchemaChangePolicy;
use Mnb\SecurityCore\Database\SchemaMigrationGuard;
use Mnb\SecurityCore\Database\SecureDatabase;
use Mnb\SecurityCore\Database\SecureQueryBuilder;
use Mnb\SecurityCore\Contracts\DatabaseConnectionInterface;
use Mnb\SecurityCore\Files\ClamAvMalwareScanner;
use Mnb\SecurityCore\Files\CompositeMalwareScanner;
use Mnb\SecurityCore\Files\FileUploadPolicy;
use Mnb\SecurityCore\Files\FileSecurityRegistry;
use Mnb\SecurityCore\Files\ProtectedDownloadManager;
use Mnb\SecurityCore\Files\ArchiveInspector;
use Mnb\SecurityCore\Files\DocumentInspectorInterface;
use Mnb\SecurityCore\Files\DocumentSanitizerInterface;
use Mnb\SecurityCore\Files\NullDocumentSanitizer;
use Mnb\SecurityCore\Files\FileRetentionManager;
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
use Mnb\SecurityCore\Http\Middleware\TrustBoundaryMiddleware;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Memory\MemoryConfig;
use Mnb\SecurityCore\Memory\MemoryGuard;
use Mnb\SecurityCore\Memory\MemoryPolicy;
use Mnb\SecurityCore\Memory\StreamGuard;
use Mnb\SecurityCore\Memory\SafeStreamReader;
use Mnb\SecurityCore\Memory\SafeStreamWriter;
use Mnb\SecurityCore\Memory\PayloadSizeGuard;
use Mnb\SecurityCore\Memory\DecodedPayloadGuard;
use Mnb\SecurityCore\Memory\JsonDepthGuard;
use Mnb\SecurityCore\Memory\ArrayDepthGuard;
use Mnb\SecurityCore\Memory\OutputBufferGuard;
use Mnb\SecurityCore\Memory\ResourceScopeManager;
use Mnb\SecurityCore\Memory\TemporaryFileManager;
use Mnb\SecurityCore\Memory\TempStorageSweeper;
use Mnb\SecurityCore\Memory\MemoryLeakDetector;
use Mnb\SecurityCore\Memory\WorkerMemorySupervisor;
use Mnb\SecurityCore\Logging\FileLogger;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Mnb\SecurityCore\Logging\NullSecurityAuditTrail;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;
use Mnb\SecurityCore\Logging\AutoAuditLogger;
use Mnb\SecurityCore\Logging\AuditExporter;
use Mnb\SecurityCore\Logging\AuditIntegrityVerifier;
use Mnb\SecurityCore\Logging\FileLogHandler;
use Mnb\SecurityCore\Logging\JsonLogHandler;
use Mnb\SecurityCore\Logging\LogDataProtector;
use Mnb\SecurityCore\Logging\LogHandlerInterface;
use Mnb\SecurityCore\Logging\Logger;
use Mnb\SecurityCore\Logging\LogRetentionManager;
use Mnb\SecurityCore\Logging\LogRetentionPolicy;
use Mnb\SecurityCore\Monitoring\AlertManager;
use Mnb\SecurityCore\Monitoring\AlertRule;
use Mnb\SecurityCore\Monitoring\FileAlertChannel;
use Mnb\SecurityCore\Monitoring\MetricsRegistry;
use Mnb\SecurityCore\Monitoring\MonitoringSummary;
use Mnb\SecurityCore\Monitoring\WebhookAlertChannel;
use Mnb\SecurityCore\Network\OutboundHttpClient;
use Mnb\SecurityCore\Network\OutboundRequestPolicy;
use Mnb\SecurityCore\Runtime\ProcessPolicy;
use Mnb\SecurityCore\Runtime\SafeProcessRunner;
use Mnb\SecurityCore\Contracts\LoggerInterface;
use Mnb\SecurityCore\Data\DataProtectionRegistry;
use Mnb\SecurityCore\Data\ExportPolicy;
use Mnb\SecurityCore\Data\KeyRing;
use Mnb\SecurityCore\Data\SafeCsvExporter;
use Mnb\SecurityCore\Files\EncryptedStorage;
use Mnb\SecurityCore\Suggestions\AutoSuggestionEngine;
use Mnb\SecurityCore\Trust\TrustBoundaryRegistry;
use Mnb\SecurityCore\Trust\TrustBoundaryPolicy;
use Mnb\SecurityCore\Trust\TrustZoneResolver;
use Mnb\SecurityCore\Validation\InputSanitizer;
use Mnb\SecurityCore\Validation\InputValidator;
use Mnb\SecurityCore\Security\ServerIdentityHider;
use Mnb\SecurityCore\Http\Middleware\CacheControlMiddleware;
use Mnb\SecurityCore\Web\CacheControlPolicy;
use Mnb\SecurityCore\Web\HtmlSanitizer;
use Mnb\SecurityCore\Web\OutputEscaper;
use Mnb\SecurityCore\Web\SafeRedirector;
use Mnb\SecurityCore\Web\SecureCookieBuilder;
use Mnb\SecurityCore\Web\SignedUrl;
use Mnb\SecurityCore\Web\WebSecurityControls as WebControls;
use Mnb\SecurityCore\Web\WebSecurityProfile;
use Mnb\SecurityCore\Web\WebSecurityRegistry;
use Mnb\SecurityCore\Recovery\BackupIntegrityVerifier;
use Mnb\SecurityCore\Recovery\BackupPolicy;
use Mnb\SecurityCore\Recovery\BackupRetentionManager;
use Mnb\SecurityCore\Recovery\BackupRetentionPolicy;
use Mnb\SecurityCore\Recovery\BackupSigner;
use Mnb\SecurityCore\Recovery\RecoveryStatusReport;
use Mnb\SecurityCore\Recovery\RestoreManager;
use Mnb\SecurityCore\Recovery\SecureBackupManager;
use Mnb\SecurityCore\Incident\ContainmentActionRunner;
use Mnb\SecurityCore\Incident\IncidentEvidenceCollector;
use Mnb\SecurityCore\Incident\IncidentPlaybook;
use Mnb\SecurityCore\Incident\IncidentResponseManager;
use Mnb\SecurityCore\Vulnerability\VulnerabilityAdvisor;
use Mnb\SecurityCore\Vulnerability\VulnerabilityCoverageReport;
use Mnb\SecurityCore\Vulnerability\VulnerabilityMatrix;
use Mnb\SecurityCore\Vulnerability\VulnerabilityReportExporter;
use Mnb\SecurityCore\Pentest\EvidenceCollector;
use Mnb\SecurityCore\Pentest\EvidenceRedactor;
use Mnb\SecurityCore\Pentest\EvidenceStore;
use Mnb\SecurityCore\Pentest\ReleaseGatePolicy;
use Mnb\SecurityCore\Pentest\RemediationPolicy;
use Mnb\SecurityCore\Pentest\RetestGate;
use Mnb\SecurityCore\Pentest\SecurityCoverageAnalyzer;
use Mnb\SecurityCore\Pentest\SecurityReleaseGate;
use Mnb\SecurityCore\Pentest\SecurityVerificationRegistry;
use Mnb\SecurityCore\Pentest\SecurityVerificationRunner;
use Mnb\SecurityCore\Pentest\VerificationMatrix as PentestVerificationMatrix;
use Mnb\SecurityCore\Pentest\VerificationProfile;
use Mnb\SecurityCore\Errors\ErrorAlertDispatcher;
use Mnb\SecurityCore\Errors\ErrorCatalog;
use Mnb\SecurityCore\Errors\ErrorCodeRegistry;
use Mnb\SecurityCore\Errors\ErrorDeduplicator;
use Mnb\SecurityCore\Errors\ErrorEscalationPolicy;
use Mnb\SecurityCore\Errors\ErrorFingerprint;
use Mnb\SecurityCore\Errors\ErrorLogSanitizer;
use Mnb\SecurityCore\Errors\ErrorPolicy;
use Mnb\SecurityCore\Errors\SafeErrorPageRenderer;
use Mnb\SecurityCore\Errors\StackTraceSanitizer;
use Mnb\SecurityCore\Errors\ValidationErrorNormalizer;
use PDO;

class SecurityKernel
{
    public function __construct(private array $config) {}


    public function secretManager(?SecretProviderInterface $provider = null): SecretManager
    {
        return SecretManager::fromConfig($this->config, $provider);
    }

    public function secretRedactor(): SecretRedactor
    {
        return $this->secretManager()->redactor();
    }

    public function secretInventory(): SecretInventory
    {
        return $this->secretManager()->inventory();
    }

    public function secretHealthReport(): SecretHealthReport
    {
        return $this->secretInventory()->report();
    }

    public function secretRotationReport(): SecretRotationReport
    {
        return $this->secretManager()->rotationReport();
    }

    public function keyDeriver(): KeyDeriver
    {
        $manager = $this->secretManager();
        return new KeyDeriver((string)$manager->require('app.key'), (string)($this->config['secrets']['derivation']['salt'] ?? 'mnb-secure-core'));
    }

    public function environmentValidator(): EnvironmentValidator
    {
        return new EnvironmentValidator($this->config, $this->secretManager());
    }

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


    public function cacheRegistry(): CacheRegistry
    {
        return CacheRegistry::fromConfig($this->config);
    }

    public function cachePolicy(string $name): CachePolicy
    {
        return $this->cacheRegistry()->get($name);
    }

    public function cacheKeyBuilder(): CacheKeyBuilder
    {
        $caching = is_array($this->config['caching'] ?? null) ? $this->config['caching'] : [];
        return new CacheKeyBuilder((string)($caching['key_prefix'] ?? $this->config['cache']['prefix'] ?? 'mnb'));
    }

    public function safeCacheSerializer(): SafeCacheSerializer
    {
        $security = is_array($this->config['caching']['security'] ?? null) ? $this->config['caching']['security'] : [];
        return new SafeCacheSerializer((int)($security['max_value_bytes'] ?? 1048576));
    }

    public function encryptedCache(?PDO $pdo = null, ?object $redis = null): EncryptedCache
    {
        return new EncryptedCache($this->cache($pdo, $redis), $this->dataKeyRing(), $this->safeCacheSerializer());
    }

    public function taggedCache(?PDO $pdo = null, ?object $redis = null): TaggedCache
    {
        $caching = is_array($this->config['caching'] ?? null) ? $this->config['caching'] : [];
        return new TaggedCache($this->cache($pdo, $redis), (string)($caching['tag_prefix'] ?? 'mnb:tag:'));
    }

    public function secureCache(?PDO $pdo = null, ?object $redis = null, ?SecurityAuditTrail $audit = null): SecureCache
    {
        $caching = is_array($this->config['caching'] ?? null) ? $this->config['caching'] : [];
        $security = is_array($caching['security'] ?? null) ? $caching['security'] : [];
        $stampede = is_array($caching['stampede'] ?? null) ? $caching['stampede'] : [];
        return new SecureCache(
            $this->cache($pdo, $redis),
            $this->cacheRegistry(),
            $this->cacheKeyBuilder(),
            $this->safeCacheSerializer(),
            $this->dataKeyRing(),
            $audit ?: $this->auditTrail(),
            array_replace($security, ['jitter_percent' => (int)($stampede['jitter_percent'] ?? 0)]),
            $this->taggedCache($pdo, $redis)
        );
    }

    public function cacheInvalidator(?PDO $pdo = null, ?object $redis = null): CacheInvalidator
    {
        return new CacheInvalidator($this->taggedCache($pdo, $redis));
    }

    public function cacheStampedeGuard(?PDO $pdo = null, ?object $redis = null): CacheStampedeGuard
    {
        $stampede = is_array($this->config['caching']['stampede'] ?? null) ? $this->config['caching']['stampede'] : [];
        return new CacheStampedeGuard($this->cache($pdo, $redis), (int)($stampede['lock_ttl'] ?? 15));
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


    public function processPolicy(): ProcessPolicy
    {
        return ProcessPolicy::fromConfig($this->config);
    }

    public function safeProcessRunner(?SecurityAuditTrail $audit = null): SafeProcessRunner
    {
        return new SafeProcessRunner($this->processPolicy(), $audit ?: $this->auditTrail());
    }

    public function outboundRequestPolicy(): OutboundRequestPolicy
    {
        return OutboundRequestPolicy::fromConfig($this->config);
    }

    public function outboundHttpClient(?SecurityAuditTrail $audit = null): OutboundHttpClient
    {
        return new OutboundHttpClient($this->outboundRequestPolicy(), $audit ?: $this->auditTrail());
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

    public function secureFileManager(?MalwareScannerInterface $scanner = null, ?string $profile = null, ?SecurityAuditTrail $audit = null, ?DocumentInspectorInterface $inspector = null, ?DocumentSanitizerInterface $sanitizer = null): SecureFileManager
    {
        $storageConfig = is_array($this->config['data_protection']['storage'] ?? null) ? $this->config['data_protection']['storage'] : [];
        $storage = !empty($storageConfig['encrypt_files'])
            ? $this->encryptedPrivateStorage()
            : new LocalPrivateStorage($this->config['paths']['private_storage']);
        $policy = $this->uploadPolicy($profile);
        return new SecureFileManager($storage, $policy, $this->config['paths']['quarantine'], $scanner ?: $this->malwareScanner(), $audit, $inspector ?: $this->documentInspector(), $sanitizer ?: $this->documentSanitizer());
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
                (bool)($config['fail_closed'] ?? false),
                $this->safeProcessRunner()
            );
        }
        if ($driver === 'composite') {
            return new CompositeMalwareScanner([
                new HeuristicMalwareScanner((int)($config['heuristic_read_bytes'] ?? 2097152)),
                new ClamAvMalwareScanner(
                    $config['clamav_binary'] ?? ($_ENV['CLAMAV_BINARY'] ?? 'clamscan'),
                    (int)($config['timeout_seconds'] ?? 30),
                    (bool)($config['fail_closed'] ?? false),
                    $this->safeProcessRunner()
                ),
            ]);
        }
        return new HeuristicMalwareScanner((int)($config['heuristic_read_bytes'] ?? 2097152));
    }

    public function memoryPolicy(): MemoryPolicy
    {
        return MemoryPolicy::fromConfig($this->config);
    }

    public function memoryGuard(?string $profile = null): MemoryGuard
    {
        $logger = new FileLogger($this->config['paths']['logs'] . '/memory.log');
        if ($profile !== null) {
            $profileBudget = $this->memoryPolicy()->profile($profile)->budget();
            $config = new MemoryConfig($profileBudget->maxBytes(), $profileBudget->warningRatio(), $profileBudget->criticalRatio());
            return new MemoryGuard($config, $logger);
        }
        return new MemoryGuard(MemoryConfig::fromArray($this->config['memory'] ?? []), $logger);
    }

    public function streamGuard(): StreamGuard
    {
        return StreamGuard::fromConfig($this->config);
    }

    public function safeStreamReader(): SafeStreamReader
    {
        return new SafeStreamReader($this->streamGuard());
    }

    public function safeStreamWriter(): SafeStreamWriter
    {
        return new SafeStreamWriter($this->streamGuard());
    }

    public function payloadSizeGuard(): PayloadSizeGuard
    {
        return PayloadSizeGuard::fromConfig($this->config);
    }

    public function decodedPayloadGuard(): DecodedPayloadGuard
    {
        return DecodedPayloadGuard::fromConfig($this->config);
    }

    public function jsonDepthGuard(): JsonDepthGuard
    {
        return JsonDepthGuard::fromConfig($this->config);
    }

    public function arrayDepthGuard(): ArrayDepthGuard
    {
        $memory = is_array($this->config['memory'] ?? null) ? $this->config['memory'] : [];
        $payloads = is_array($memory['payloads'] ?? null) ? $memory['payloads'] : [];
        return new ArrayDepthGuard((int)($payloads['max_decoded_depth'] ?? 32));
    }

    public function outputBufferGuard(): OutputBufferGuard
    {
        return OutputBufferGuard::fromConfig($this->config);
    }

    public function resourceScopeManager(): ResourceScopeManager
    {
        return new ResourceScopeManager();
    }

    public function temporaryFileManager(): TemporaryFileManager
    {
        return TemporaryFileManager::fromConfig($this->config);
    }

    public function tempStorageSweeper(): TempStorageSweeper
    {
        return new TempStorageSweeper($this->temporaryFileManager());
    }

    public function memoryLeakDetector(): MemoryLeakDetector
    {
        return new MemoryLeakDetector();
    }

    public function workerMemorySupervisor(string $profile = 'queue_worker'): WorkerMemorySupervisor
    {
        return new WorkerMemorySupervisor($this->memoryPolicy()->profile($profile), $this->memoryLeakDetector());
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

    public function trustZoneResolver(): TrustZoneResolver
    {
        $config = is_array($this->config['trust_boundaries'] ?? null) ? $this->config['trust_boundaries'] : [];
        return new TrustZoneResolver($config);
    }

    public function trustBoundaryRegistry(?SecurityAuditTrail $audit = null): TrustBoundaryRegistry
    {
        return TrustBoundaryRegistry::fromConfig($this->config, $audit ?: $this->auditTrail());
    }

    public function trustBoundaryPolicy(string $name): TrustBoundaryPolicy
    {
        return $this->trustBoundaryRegistry()->get($name);
    }

    public function trustBoundaryMiddleware(string $policyName, ?callable $resourceResolver = null, ?string $action = null, ?string $dataClass = null, ?string $resourceName = null, ?SecurityAuditTrail $audit = null): TrustBoundaryMiddleware
    {
        $config = is_array($this->config['trust_boundaries'] ?? null) ? $this->config['trust_boundaries'] : [];
        return new TrustBoundaryMiddleware(
            $this->trustBoundaryRegistry($audit),
            $policyName,
            $resourceResolver,
            $action,
            $dataClass,
            $resourceName,
            (bool)($config['hide_denial_reasons'] ?? true)
        );
    }

    public function authorizationRegistry(?SecurityAuditTrail $audit = null): AuthorizationRegistry
    {
        return AuthorizationRegistry::fromConfig($this->config, $audit ?: $this->auditTrail(), $this->trustBoundaryRegistry($audit ?: $this->auditTrail()));
    }

    public function authorizationPolicy(string $name): AuthorizationPolicy
    {
        return $this->authorizationRegistry()->get($name);
    }

    public function authorizationMiddleware(string $policyName, mixed $resourceResolver = null, ?string $action = null, ?string $resourceName = null, ?string $dataClass = null, ?SecurityAuditTrail $audit = null): AuthorizationMiddleware
    {
        $config = is_array($this->config['authorization'] ?? null) ? $this->config['authorization'] : [];
        return new AuthorizationMiddleware(
            $this->authorizationRegistry($audit),
            $policyName,
            $resourceResolver,
            $action,
            $resourceName,
            $dataClass,
            (bool)($config['hide_denial_reasons'] ?? true)
        );
    }

    public function suggestionEngine(array $customRules = []): AutoSuggestionEngine
    {
        $suggestionConfig = is_array($this->config['suggestions'] ?? null) ? $this->config['suggestions'] : [];
        $rules = is_array($suggestionConfig['rules'] ?? null) ? $suggestionConfig['rules'] : [];
        return new AutoSuggestionEngine(array_merge($rules, $customRules));
    }


    public function dataKeyRing(): KeyRing
    {
        $dataProtection = is_array($this->config['data_protection'] ?? null) ? $this->config['data_protection'] : [];
        $encryption = is_array($dataProtection['encryption'] ?? null) ? $dataProtection['encryption'] : [];
        if (empty($encryption['keys']) || !is_array($encryption['keys'])) {
            $current = (string)($encryption['current_key_id'] ?? 'data-v1');
            $encryption['current_key_id'] = $current;
            $encryption['keys'] = [$current => (string)$this->secretManager()->get('data.key', $this->config['app']['key'] ?? '')];
        }
        return KeyRing::fromConfig($encryption, (string)$this->secretManager()->get('app.key', $this->config['app']['key'] ?? ''));
    }

    public function dataProtectionRegistry(?SecurityAuditTrail $audit = null): DataProtectionRegistry
    {
        return DataProtectionRegistry::fromConfig($this->config, $audit ?: $this->auditTrail());
    }

    public function safeCsvExporter(?SecurityAuditTrail $audit = null): SafeCsvExporter
    {
        $dp = is_array($this->config['data_protection'] ?? null) ? $this->config['data_protection'] : [];
        $export = is_array($dp['exports'] ?? null) ? $dp['exports'] : [];
        return new SafeCsvExporter($this->dataProtectionRegistry($audit), new ExportPolicy($export));
    }

    public function encryptedPrivateStorage(): EncryptedStorage
    {
        return new EncryptedStorage(new LocalPrivateStorage($this->config['paths']['private_storage']), $this->dataKeyRing());
    }

    public function fileSecurityRegistry(?SecurityAuditTrail $audit = null): FileSecurityRegistry
    {
        return FileSecurityRegistry::fromConfig($this->config, $audit ?: $this->auditTrail());
    }

    public function protectedDownloadManager(?SecurityAuditTrail $audit = null): ProtectedDownloadManager
    {
        $storageConfig = is_array($this->config['data_protection']['storage'] ?? null) ? $this->config['data_protection']['storage'] : [];
        $storage = !empty($storageConfig['encrypt_files'])
            ? $this->encryptedPrivateStorage()
            : new LocalPrivateStorage($this->config['paths']['private_storage']);
        return new ProtectedDownloadManager($storage, $this->fileSecurityRegistry($audit), $this->cacheControlPolicy(), $this->signedUrl());
    }

    public function documentInspector(): DocumentInspectorInterface
    {
        $uploads = is_array($this->config['uploads'] ?? null) ? $this->config['uploads'] : [];
        return new ArchiveInspector(
            (int)($uploads['max_archive_entries'] ?? 500),
            (int)($uploads['max_archive_uncompressed_bytes'] ?? 104857600),
            is_array($uploads['blocked_extensions'] ?? null) ? $uploads['blocked_extensions'] : ['php', 'phtml', 'phar', 'exe', 'sh']
        );
    }

    public function documentSanitizer(): DocumentSanitizerInterface
    {
        return new NullDocumentSanitizer();
    }

    public function fileRetentionManager(): FileRetentionManager
    {
        $fs = is_array($this->config['file_security'] ?? null) ? $this->config['file_security'] : [];
        $retention = is_array($fs['retention'] ?? null) ? $fs['retention'] : [];
        return new FileRetentionManager(
            (int)($retention['quarantine_ttl_hours'] ?? 24),
            (int)($retention['rejected_ttl_days'] ?? 7),
            (int)($retention['temporary_exports_ttl_hours'] ?? 24)
        );
    }



    public function outputEscaper(): OutputEscaper
    {
        return new OutputEscaper();
    }

    public function htmlSanitizer(array $override = []): HtmlSanitizer
    {
        $web = is_array($this->config['web_security'] ?? null) ? $this->config['web_security'] : [];
        $config = is_array($web['html_sanitizer'] ?? null) ? $web['html_sanitizer'] : [];
        return new HtmlSanitizer(array_replace($config, $override));
    }

    public function safeRedirector(?string $currentHost = null, array $override = []): SafeRedirector
    {
        $web = is_array($this->config['web_security'] ?? null) ? $this->config['web_security'] : [];
        $config = is_array($web['redirects'] ?? null) ? $web['redirects'] : [];
        return new SafeRedirector(array_replace($config, $override), $currentHost);
    }

    public function secureCookieBuilder(array $override = []): SecureCookieBuilder
    {
        $web = is_array($this->config['web_security'] ?? null) ? $this->config['web_security'] : [];
        $cookies = is_array($web['cookies'] ?? null) ? $web['cookies'] : [];
        if ($cookies === []) {
            $cookies = is_array($this->config['cookies'] ?? null) ? $this->config['cookies'] : [];
        }
        return new SecureCookieBuilder(array_replace($cookies, $override));
    }

    public function cacheControlPolicy(array $profiles = []): CacheControlPolicy
    {
        $web = is_array($this->config['web_security'] ?? null) ? $this->config['web_security'] : [];
        $cache = is_array($web['cache'] ?? null) ? $web['cache'] : [];
        $configured = is_array($cache['profiles'] ?? null) ? $cache['profiles'] : [];
        return new CacheControlPolicy(array_replace_recursive($configured, $profiles));
    }

    public function cacheControlMiddleware(string $profile = 'private_user'): CacheControlMiddleware
    {
        return new CacheControlMiddleware($this->cacheControlPolicy(), $profile);
    }

    public function signedUrl(array $override = []): SignedUrl
    {
        $web = is_array($this->config['web_security'] ?? null) ? $this->config['web_security'] : [];
        $signed = is_array($web['signed_urls'] ?? null) ? $web['signed_urls'] : [];
        $signed = array_replace($signed, $override);
        $key = (string)($signed['key'] ?? '');
        if ($key === '') {
            $key = (string)$this->secretManager()->get('signed_url.key', $this->config['app']['key'] ?? '');
        }
        return new SignedUrl($key, (int)($signed['default_ttl'] ?? 900));
    }

    public function webSecurityRegistry(): WebSecurityRegistry
    {
        return WebSecurityRegistry::fromConfig($this->config);
    }

    public function webSecurityProfile(string $name): WebSecurityProfile
    {
        return $this->webSecurityRegistry()->get($name);
    }

    public function webSecurityControls(string $profileName = 'browser_page'): WebControls
    {
        return new WebControls(
            $this->webSecurityProfile($profileName),
            $this->outputEscaper(),
            $this->htmlSanitizer(),
            $this->safeRedirector(),
            $this->secureCookieBuilder(),
            $this->cacheControlPolicy(),
            $this->signedUrl()
        );
    }

    public function passwordHasher(): PasswordHasher
    {
        return new PasswordHasher();
    }

    public function passwordPolicy(array $override = []): PasswordPolicy
    {
        $auth = is_array($this->config['authentication'] ?? null) ? $this->config['authentication'] : [];
        $policy = is_array($auth['password_policy'] ?? null) ? $auth['password_policy'] : [];
        return new PasswordPolicy(array_replace($policy, $override));
    }

    public function authenticationRegistry(): AuthenticationRegistry
    {
        return AuthenticationRegistry::fromConfig($this->config);
    }

    public function authenticationStrategy(string $name): AuthenticationStrategy
    {
        return $this->authenticationRegistry()->get($name);
    }

    public function authenticationMiddleware(string $strategyName = 'api_bearer', ?SecurityAuditTrail $audit = null): AuthenticationMiddleware
    {
        $strategy = $this->authenticationStrategy($strategyName);
        $signature = $strategy->type() === AuthenticationStrategy::TYPE_SIGNATURE
            ? $this->webhookSignatureVerifier(is_array($strategy->option('signature')) ? $strategy->option('signature') : [])
            : null;
        return new AuthenticationMiddleware($strategy, $this->opaqueTokenService(null, $audit ?: $this->auditTrail()), $signature, $audit ?: $this->auditTrail());
    }

    public function authWorkflow(UserProviderInterface $users, ?OpaqueTokenService $tokens = null, ?SecurityAuditTrail $audit = null, array $override = []): AuthWorkflowService
    {
        $auth = is_array($this->config['authentication'] ?? null) ? $this->config['authentication'] : [];
        $login = is_array($auth['login'] ?? null) ? $auth['login'] : [];
        return new AuthWorkflowService($users, $this->passwordHasher(), $tokens ?: $this->opaqueTokenService(null, $audit), $audit ?: $this->auditTrail(), $this->passwordPolicy(), array_replace($login, $override));
    }

    public function opaqueTokenService(?TokenStoreInterface $store = null, ?SecurityAuditTrail $audit = null): OpaqueTokenService
    {
        return new OpaqueTokenService($store ?: $this->tokenStore(), $audit ?: $this->auditTrail());
    }

    public function requestReceivingRegistry(): RequestReceivingRegistry
    {
        return RequestReceivingRegistry::fromConfig($this->config);
    }

    public function requestReceivingProfile(string $name): RequestReceivingProfile
    {
        return $this->requestReceivingRegistry()->get($name);
    }

    public function requestIdMiddleware(): RequestIdMiddleware
    {
        $config = is_array($this->config['request_receiving']['request_id'] ?? null) ? $this->config['request_receiving']['request_id'] : [];
        return new RequestIdMiddleware(
            (string)($config['header'] ?? 'X-Request-ID'),
            (bool)($config['accept_incoming'] ?? true),
            (int)($config['max_length'] ?? 80)
        );
    }

    public function requestMethodMiddleware(array $methods = []): RequestMethodMiddleware
    {
        $blocked = is_array($this->config['request_receiving']['blocked_methods'] ?? null)
            ? $this->config['request_receiving']['blocked_methods']
            : ['TRACE', 'CONNECT'];
        return new RequestMethodMiddleware($methods, $blocked);
    }

    public function contentTypeMiddleware(array $contentTypes = []): ContentTypeMiddleware
    {
        $receiving = is_array($this->config['request_receiving'] ?? null) ? $this->config['request_receiving'] : [];
        return new ContentTypeMiddleware($contentTypes, (bool)($receiving['reject_body_on_get'] ?? true));
    }

    public function jsonBodyParserMiddleware(?int $maxBytes = null): JsonBodyParserMiddleware
    {
        $receiving = is_array($this->config['request_receiving'] ?? null) ? $this->config['request_receiving'] : [];
        return new JsonBodyParserMiddleware(
            (int)($receiving['json_depth'] ?? 64),
            $maxBytes ?? (int)($receiving['json_max_bytes'] ?? $this->config['limits']['request_max_bytes'] ?? 1048576),
            (bool)($receiving['json_require_object'] ?? true)
        );
    }

    public function suspiciousRequestMiddleware(?SecurityAuditTrail $audit = null): SuspiciousRequestMiddleware
    {
        $config = is_array($this->config['request_receiving']['suspicious'] ?? null) ? $this->config['request_receiving']['suspicious'] : [];
        return new SuspiciousRequestMiddleware($config, $audit ?: $this->auditTrail());
    }

    public function webhookSignatureVerifier(array $override = []): WebhookSignatureVerifier
    {
        $config = is_array($this->config['request_receiving']['webhook'] ?? null) ? $this->config['request_receiving']['webhook'] : [];
        return new WebhookSignatureVerifier(array_replace($config, $override));
    }

    public function webhookSignatureMiddleware(array $override = []): WebhookSignatureMiddleware
    {
        return new WebhookSignatureMiddleware($this->webhookSignatureVerifier($override));
    }

    public function requestReceivingPipeline(string $profileName, array $options = []): MiddlewarePipeline
    {
        return $this->secureRequestReceiver($profileName, $options)->pipeline();
    }

    public function secureRequestReceiver(string $profileName, array $options = []): SecureRequestReceiver
    {
        $profile = $this->requestReceivingProfile($profileName);
        return new SecureRequestReceiver($profile, $this->middlewareForReceivingProfile($profile, $options));
    }

    /** @return list<\Mnb\SecurityCore\Contracts\MiddlewareInterface> */
    private function middlewareForReceivingProfile(RequestReceivingProfile $profile, array $options = []): array
    {
        $middleware = [];
        $audit = $options['audit'] ?? $this->auditTrail();

        if ($profile->requestId()) {
            $middleware[] = $this->requestIdMiddleware();
        }
        if ($profile->requestTrust()) {
            $middleware[] = $this->requestTrustMiddleware();
        }
        if ($profile->originProtection()) {
            $middleware[] = new ServerIdentityProtectionMiddleware($this->config['origin_protection'] ?? []);
        }
        if ($profile->https()) {
            $middleware[] = new HttpsMiddleware((bool)($this->config['app']['force_https'] ?? false));
        }
        if ($profile->trustedHost()) {
            $middleware[] = new TrustedHostMiddleware((array)($this->config['app']['trusted_hosts'] ?? []));
        }
        if ($profile->cors()) {
            $middleware[] = $this->corsMiddleware();
        }
        if ($profile->methods() !== []) {
            $middleware[] = $this->requestMethodMiddleware($profile->methods());
        }
        if ($profile->maxBytes() > 0) {
            $middleware[] = new RequestSizeMiddleware($profile->maxBytes());
        }
        if ($profile->contentTypes() !== []) {
            $middleware[] = $this->contentTypeMiddleware($profile->contentTypes());
        }
        if ($profile->jsonBody()) {
            $middleware[] = $this->jsonBodyParserMiddleware($profile->maxBytes() > 0 ? $profile->maxBytes() : null);
        }
        if ($profile->suspiciousDetection()) {
            $middleware[] = $this->suspiciousRequestMiddleware($audit instanceof SecurityAuditTrail ? $audit : null);
        }
        if ($profile->securityHeaders()) {
            $middleware[] = $this->securityHeadersMiddleware();
        }
        if ($profile->inputValidation()) {
            $middleware[] = $this->inputValidationMiddleware();
        }
        if ($profile->ratePolicy() !== null) {
            $middleware[] = $this->rateLimitMiddleware($profile->ratePolicy(), $profile->option('route_name'));
        }
        if ($profile->autoAudit()) {
            $middleware[] = $this->autoAuditMiddleware($audit instanceof SecurityAuditTrail ? $audit : null);
        }
        $authStrategy = $profile->option('auth_strategy');
        if (is_string($authStrategy) && trim($authStrategy) !== '') {
            $middleware[] = $this->authenticationMiddleware(trim($authStrategy), $audit instanceof SecurityAuditTrail ? $audit : null);
        } else {
            if ($profile->csrf() || $profile->auth() === 'csrf') {
                $middleware[] = new CsrfMiddleware(new Csrf((string)($profile->option('csrf_session_key') ?? '_csrf_token')));
            }
            if ($profile->auth() === 'bearer') {
                $middleware[] = new ApiTokenMiddleware($this->opaqueTokenService(null, $audit instanceof SecurityAuditTrail ? $audit : null));
            }
            if ($profile->auth() === 'signature') {
                $middleware[] = $this->webhookSignatureMiddleware(is_array($profile->option('webhook')) ? $profile->option('webhook') : []);
            }
        }
        $authorization = $profile->option('authorization');
        if (is_string($authorization) && trim($authorization) !== '') {
            $middleware[] = $this->authorizationMiddleware(
                trim($authorization),
                $options['authorization_resource_resolver'] ?? $options['resource_resolver'] ?? null,
                is_string($profile->option('authorization_action')) ? $profile->option('authorization_action') : $profile->option('action'),
                is_string($profile->option('authorization_resource')) ? $profile->option('authorization_resource') : $profile->option('resource'),
                is_string($profile->option('authorization_data_class')) ? $profile->option('authorization_data_class') : $profile->option('data_class'),
                $audit instanceof SecurityAuditTrail ? $audit : null
            );
        }
        if ($profile->trustBoundary() !== null) {
            $middleware[] = $this->trustBoundaryMiddleware(
                $profile->trustBoundary(),
                $options['resource_resolver'] ?? null,
                $profile->option('action'),
                $profile->option('data_class'),
                $profile->option('resource'),
                $audit instanceof SecurityAuditTrail ? $audit : null
            );
        }

        return $middleware;
    }

    public function logDataProtector(): LogDataProtector
    {
        $logging = is_array($this->config['logging']['redaction'] ?? null) ? $this->config['logging']['redaction'] : [];
        return new LogDataProtector($this->secretRedactor(), $logging);
    }

    public function logHandler(?string $channel = null): LogHandlerInterface
    {
        $logging = is_array($this->config['logging'] ?? null) ? $this->config['logging'] : [];
        $channelName = $channel ?: (string)($logging['default_channel'] ?? 'app');
        $channels = is_array($logging['channels'] ?? null) ? $logging['channels'] : [];
        $channelConfig = is_array($channels[$channelName] ?? null) ? $channels[$channelName] : [];
        $logPath = (string)($this->config['paths']['logs'] ?? dirname(__DIR__, 2) . '/storage/logs');
        $path = (string)($channelConfig['path'] ?? ($logPath . '/' . $channelName . '.jsonl'));
        $handler = (string)($channelConfig['handler'] ?? 'json_file');
        return match ($handler) {
            'file' => new FileLogHandler($path, $this->logDataProtector()),
            default => new JsonLogHandler($path, $this->logDataProtector()),
        };
    }

    public function logger(?string $channel = null): Logger
    {
        $logging = is_array($this->config['logging'] ?? null) ? $this->config['logging'] : [];
        $channelName = $channel ?: (string)($logging['default_channel'] ?? 'app');
        $channels = is_array($logging['channels'] ?? null) ? $logging['channels'] : [];
        $channelConfig = is_array($channels[$channelName] ?? null) ? $channels[$channelName] : [];
        return new Logger([$this->logHandler($channelName)], $channelName, (string)($channelConfig['level'] ?? 'info'));
    }

    public function securityLogger(): Logger
    {
        return $this->logger('security');
    }

    public function auditIntegrityVerifier(): AuditIntegrityVerifier
    {
        $audit = is_array($this->config['audit'] ?? null) ? $this->config['audit'] : [];
        return new AuditIntegrityVerifier((string)($audit['file'] ?? dirname(__DIR__, 2) . '/storage/audit/security-audit.log'));
    }

    public function auditExporter(): AuditExporter
    {
        $audit = is_array($this->config['audit'] ?? null) ? $this->config['audit'] : [];
        return new AuditExporter((string)($audit['file'] ?? dirname(__DIR__, 2) . '/storage/audit/security-audit.log'));
    }

    public function logRetentionPolicy(): LogRetentionPolicy
    {
        return LogRetentionPolicy::fromConfig($this->config);
    }

    public function logRetentionManager(): LogRetentionManager
    {
        return new LogRetentionManager(
            $this->logRetentionPolicy(),
            (string)($this->config['paths']['logs'] ?? dirname(__DIR__, 2) . '/storage/logs'),
            (string)($this->config['paths']['audit'] ?? dirname(__DIR__, 2) . '/storage/audit')
        );
    }

    public function metricsRegistry(): MetricsRegistry
    {
        $monitoring = is_array($this->config['monitoring'] ?? null) ? $this->config['monitoring'] : [];
        $metrics = is_array($monitoring['metrics'] ?? null) ? $monitoring['metrics'] : [];
        $path = (string)($metrics['path'] ?? (($this->config['paths']['logs'] ?? dirname(__DIR__, 2) . '/storage/logs') . '/metrics.json'));
        return new MetricsRegistry(!empty($metrics['enabled']) ? $path : null);
    }

    public function alertManager(): AlertManager
    {
        $monitoring = is_array($this->config['monitoring'] ?? null) ? $this->config['monitoring'] : [];
        $alerts = is_array($monitoring['alerts'] ?? null) ? $monitoring['alerts'] : [];
        $rules = [];
        foreach ((is_array($alerts['rules'] ?? null) ? $alerts['rules'] : []) as $name => $rule) {
            if (is_array($rule)) {
                $rules[] = AlertRule::fromArray((string)$name, $rule);
            }
        }
        $logPath = (string)($this->config['paths']['logs'] ?? dirname(__DIR__, 2) . '/storage/logs');
        $channels = [];
        foreach ((array)($alerts['channels'] ?? ['file']) as $channel) {
            if ($channel === 'webhook' && !empty($alerts['webhook_url'])) {
                $channels[] = new WebhookAlertChannel((string)$alerts['webhook_url'], (int)($alerts['webhook_timeout_seconds'] ?? 2), $this->outboundHttpClient());
                continue;
            }
            if ($channel === 'file') {
                $channels[] = new FileAlertChannel((string)($alerts['file'] ?? ($logPath . '/security-alerts.jsonl')));
            }
        }
        if ($channels === []) {
            $channels[] = new FileAlertChannel($logPath . '/security-alerts.jsonl');
        }
        $eventFile = (string)($alerts['event_file'] ?? ($logPath . '/monitoring-events.jsonl'));
        return new AlertManager($rules, $channels, !empty($alerts['enabled']) ? $eventFile : null);
    }

    public function monitoringSummary(): MonitoringSummary
    {
        return new MonitoringSummary($this->auditExporter(), $this->auditIntegrityVerifier(), $this->metricsRegistry(), $this->alertManager());
    }


    public function backupPolicy(): BackupPolicy
    {
        return BackupPolicy::fromConfig($this->config, is_array($this->config['paths'] ?? null) ? $this->config['paths'] : []);
    }

    public function backupSigner(): BackupSigner
    {
        return new BackupSigner($this->backupPolicy()->signingKey());
    }

    public function secureBackupManager(?SecurityAuditTrail $audit = null): SecureBackupManager
    {
        return new SecureBackupManager($this->backupPolicy(), $this->backupSigner(), $audit ?: $this->auditTrail());
    }

    public function backupIntegrityVerifier(): BackupIntegrityVerifier
    {
        $restore = is_array($this->config['recovery']['restore'] ?? null) ? $this->config['recovery']['restore'] : [];
        return new BackupIntegrityVerifier($this->backupSigner(), !empty($restore['require_signature']));
    }

    public function backupRetentionPolicy(): BackupRetentionPolicy
    {
        return BackupRetentionPolicy::fromConfig($this->config);
    }

    public function backupRetentionManager(): BackupRetentionManager
    {
        return new BackupRetentionManager($this->backupRetentionPolicy(), $this->backupPolicy()->path());
    }

    public function restoreManager(?SecurityAuditTrail $audit = null): RestoreManager
    {
        return new RestoreManager($this->backupIntegrityVerifier(), $this->secureBackupManager($audit ?: $this->auditTrail()), is_array($this->config['recovery']['restore'] ?? null) ? $this->config['recovery']['restore'] : [], $audit ?: $this->auditTrail());
    }

    public function recoveryStatusReport(): RecoveryStatusReport
    {
        return new RecoveryStatusReport($this->backupPolicy()->path(), $this->backupIntegrityVerifier(), $this->backupRetentionPolicy());
    }

    public function incidentPlaybook(string $name): IncidentPlaybook
    {
        $ir = is_array($this->config['incident_response']['playbooks'] ?? null) ? $this->config['incident_response']['playbooks'] : [];
        return IncidentPlaybook::fromArray($name, is_array($ir[$name] ?? null) ? $ir[$name] : ['severity' => 'medium', 'actions' => ['record_incident', 'collect_evidence', 'alert_security']]);
    }

    public function containmentActionRunner(?SecurityAuditTrail $audit = null): ContainmentActionRunner
    {
        return new ContainmentActionRunner($this->cacheInvalidator(), $audit ?: $this->auditTrail());
    }

    public function incidentEvidenceCollector(): IncidentEvidenceCollector
    {
        return new IncidentEvidenceCollector($this->auditExporter(), $this->monitoringSummary(), $this->secretHealthReport());
    }

    public function incidentResponse(?SecurityAuditTrail $audit = null): IncidentResponseManager
    {
        $trail = $audit ?: $this->auditTrail();
        return IncidentResponseManager::fromConfig($this->config, $this->containmentActionRunner($trail), $this->incidentEvidenceCollector(), $trail);
    }



    public function vulnerabilityMatrix(): VulnerabilityMatrix
    {
        return new VulnerabilityMatrix($this->config);
    }

    public function vulnerabilityCoverageReport(): VulnerabilityCoverageReport
    {
        $matrix = is_array($this->config['vulnerability_matrix'] ?? null) ? $this->config['vulnerability_matrix'] : [];
        $reporting = is_array($matrix['reporting'] ?? null) ? $matrix['reporting'] : [];
        return new VulnerabilityCoverageReport($this->vulnerabilityMatrix(), (int)($reporting['minimum_passing_score'] ?? 80));
    }

    public function vulnerabilityAdvisor(): VulnerabilityAdvisor
    {
        return new VulnerabilityAdvisor($this->vulnerabilityMatrix());
    }

    public function vulnerabilityReportExporter(): VulnerabilityReportExporter
    {
        return new VulnerabilityReportExporter($this->vulnerabilityCoverageReport());
    }


    public function errorPolicy(): ErrorPolicy
    {
        return ErrorPolicy::fromConfig($this->config);
    }

    public function errorCatalog(): ErrorCatalog
    {
        return ErrorCatalog::fromConfig($this->config);
    }

    public function errorCodeRegistry(): ErrorCodeRegistry
    {
        return new ErrorCodeRegistry($this->errorCatalog());
    }

    public function errorLogSanitizer(): ErrorLogSanitizer
    {
        return new ErrorLogSanitizer($this->errorPolicy());
    }

    public function stackTraceSanitizer(): StackTraceSanitizer
    {
        return new StackTraceSanitizer($this->errorPolicy(), $this->errorLogSanitizer());
    }

    public function validationErrorNormalizer(): ValidationErrorNormalizer
    {
        return new ValidationErrorNormalizer($this->errorPolicy());
    }

    public function safeErrorPageRenderer(): SafeErrorPageRenderer
    {
        return new SafeErrorPageRenderer();
    }

    public function errorFingerprint(): ErrorFingerprint
    {
        return new ErrorFingerprint($this->errorPolicy(), $this->errorLogSanitizer());
    }

    public function errorDeduplicator(): ErrorDeduplicator
    {
        return new ErrorDeduplicator();
    }

    public function errorEscalationPolicy(): ErrorEscalationPolicy
    {
        return ErrorEscalationPolicy::fromConfig($this->config);
    }

    public function errorAlertDispatcher(?LoggerInterface $logger = null): ErrorAlertDispatcher
    {
        return new ErrorAlertDispatcher($logger ?: $this->logger());
    }

    public function securityVerificationRegistry(): SecurityVerificationRegistry
    {
        return new SecurityVerificationRegistry();
    }

    public function verificationProfile(string $name = 'production_release'): VerificationProfile
    {
        return VerificationProfile::fromConfig($this->config, $name);
    }

    public function evidenceRedactor(): EvidenceRedactor
    {
        return new EvidenceRedactor();
    }

    public function evidenceCollector(): EvidenceCollector
    {
        return new EvidenceCollector($this->evidenceRedactor());
    }

    public function evidenceStore(): EvidenceStore
    {
        $pentest = is_array($this->config['pentest'] ?? null) ? $this->config['pentest'] : [];
        return new EvidenceStore((string)($pentest['evidence_storage'] ?? ''));
    }

    public function securityVerificationRunner(): SecurityVerificationRunner
    {
        return new SecurityVerificationRunner($this->securityVerificationRegistry(), $this->evidenceCollector());
    }

    public function remediationPolicy(): RemediationPolicy
    {
        return RemediationPolicy::fromConfig($this->config);
    }

    public function retestGate(): RetestGate
    {
        return new RetestGate($this->remediationPolicy());
    }

    public function releaseGatePolicy(): ReleaseGatePolicy
    {
        return ReleaseGatePolicy::fromConfig($this->config);
    }

    public function securityReleaseGate(): SecurityReleaseGate
    {
        return new SecurityReleaseGate($this->releaseGatePolicy());
    }

    public function securityCoverageAnalyzer(): SecurityCoverageAnalyzer
    {
        return new SecurityCoverageAnalyzer(new PentestVerificationMatrix());
    }

    public function databaseOperationPolicy(): DatabaseOperationPolicy
    {
        return DatabaseOperationPolicy::fromConfig($this->config);
    }

    public function databaseQueryCostPolicy(): QueryCostPolicy
    {
        return QueryCostPolicy::fromConfig($this->config);
    }

    public function databaseQueryGuard(): QueryComplexityGuard
    {
        return QueryComplexityGuard::fromConfig($this->config);
    }

    public function databaseFieldResultFilter(): DatabaseResultFilter
    {
        return DatabaseResultFilter::fromConfig($this->config);
    }

    public function rawQueryGuard(): RawQueryGuard
    {
        return RawQueryGuard::fromConfig($this->config);
    }

    public function databasePolicyRegistry(array $policies = []): DatabasePolicyRegistry
    {
        return new DatabasePolicyRegistry($policies);
    }

    public function schemaChangePolicy(): SchemaChangePolicy
    {
        return SchemaChangePolicy::fromConfig($this->config);
    }

    public function schemaMigrationGuard(): SchemaMigrationGuard
    {
        return SchemaMigrationGuard::fromConfig($this->config);
    }

    public function secureDatabase(DatabaseConnectionInterface $connection, ?object $audit = null, array $tablePolicies = []): SecureDatabase
    {
        return new SecureDatabase(
            $connection,
            null,
            $audit ?: $this->auditTrail(),
            new SecureQueryBuilder($this->databaseQueryGuard()),
            new \Mnb\SecurityCore\Database\SchemaGuard(),
            $this->databasePolicyRegistry($tablePolicies),
            $this->databaseQueryGuard(),
            $this->databaseFieldResultFilter(),
            $this->schemaMigrationGuard()
        );
    }

    public function databaseHealthChecker(?DatabaseConnectionInterface $connection = null): DatabaseHealthChecker
    {
        return new DatabaseHealthChecker($this->config, $connection);
    }

    public function databasePrivilegeInspector(array $grantsOrPrivileges = []): DatabasePrivilegeInspector
    {
        return new DatabasePrivilegeInspector($grantsOrPrivileges);
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
