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
use Mnb\SecurityCore\Http\Middleware\TrustBoundaryMiddleware;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Memory\MemoryConfig;
use Mnb\SecurityCore\Memory\MemoryGuard;
use Mnb\SecurityCore\Logging\FileLogger;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Mnb\SecurityCore\Logging\NullSecurityAuditTrail;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;
use Mnb\SecurityCore\Logging\AutoAuditLogger;
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
        return KeyRing::fromConfig($encryption, (string)($this->config['app']['key'] ?? ''));
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
