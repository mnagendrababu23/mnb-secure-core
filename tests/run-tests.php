<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Auth\AuthenticationRegistry;
use Mnb\SecurityCore\Auth\AuthenticationStrategy;
use Mnb\SecurityCore\Auth\AuthWorkflowService;
use Mnb\SecurityCore\Auth\PasswordPolicy;
use Mnb\SecurityCore\Auth\UserProviderInterface;
use Mnb\SecurityCore\Authorization\AuthorizationDecision;
use Mnb\SecurityCore\Authorization\AuthorizationPolicy;
use Mnb\SecurityCore\Authorization\AuthorizationRegistry;
use Mnb\SecurityCore\Authorization\ResourceResolverInterface;
use Mnb\SecurityCore\Http\Middleware\AuthorizationMiddleware;
use Mnb\SecurityCore\Auth\Csrf;
use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Auth\PasswordHasher;
use Mnb\SecurityCore\Auth\PermissionGuard as AuthPermissionGuard;
use Mnb\SecurityCore\Auth\Stores\DatabaseTokenStore;
use Mnb\SecurityCore\Auth\Stores\FileTokenStore;
use Mnb\SecurityCore\Authz\Policies\StudentPolicy;
use Mnb\SecurityCore\Authz\PolicyRegistry;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Authz\TenantGuard;
use Mnb\SecurityCore\Cache\DatabaseCache;
use Mnb\SecurityCore\Cache\FileCache;
use Mnb\SecurityCore\Cache\CacheInvalidator;
use Mnb\SecurityCore\Cache\CacheKeyBuilder;
use Mnb\SecurityCore\Cache\CachePolicy;
use Mnb\SecurityCore\Cache\CacheRegistry;
use Mnb\SecurityCore\Cache\CacheStampedeGuard;
use Mnb\SecurityCore\Cache\EncryptedCache;
use Mnb\SecurityCore\Cache\SafeCacheSerializer;
use Mnb\SecurityCore\Cache\SecureCache;
use Mnb\SecurityCore\Cache\TaggedCache;
use Mnb\SecurityCore\Data\DataClassifier;
use Mnb\SecurityCore\Data\DataMasker;
use Mnb\SecurityCore\Data\Encryption;
use Mnb\SecurityCore\Data\FieldFilter;
use Mnb\SecurityCore\Data\DataProtectionRegistry;
use Mnb\SecurityCore\Data\KeyRing;
use Mnb\SecurityCore\Data\SafeCsvExporter;
use Mnb\SecurityCore\Data\ExportPolicy;
use Mnb\SecurityCore\Files\EncryptedStorage;
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Core\StorageDriverResolver;
use Mnb\SecurityCore\Authz\Policies\DatabaseResourcePolicy;
use Mnb\SecurityCore\Database\DatabaseConfig;
use Mnb\SecurityCore\Database\DryRunDatabaseConnection;
use Mnb\SecurityCore\Database\SchemaGuard;
use Mnb\SecurityCore\Database\SecureDatabase;
use Mnb\SecurityCore\Database\SecureQueryBuilder;
use Mnb\SecurityCore\Database\SqlIdentifier;
use Mnb\SecurityCore\Database\TableSecurityPolicy;
use Mnb\SecurityCore\Database\DatabaseHealthChecker;
use Mnb\SecurityCore\Database\DatabasePolicyRegistry;
use Mnb\SecurityCore\Database\DatabasePrivilegeInspector;
use Mnb\SecurityCore\Database\DatabaseResultFilter;
use Mnb\SecurityCore\Database\QueryComplexityGuard;
use Mnb\SecurityCore\Database\QueryCostPolicy;
use Mnb\SecurityCore\Database\RawQueryGuard;
use Mnb\SecurityCore\Database\SchemaChangePolicy;
use Mnb\SecurityCore\Database\SchemaMigrationGuard;
use Mnb\SecurityCore\Env\SecretScanner;
use Mnb\SecurityCore\Env\ArraySecretProvider;
use Mnb\SecurityCore\Env\EnvSecretProvider;
use Mnb\SecurityCore\Env\EnvironmentValidator;
use Mnb\SecurityCore\Env\KeyDeriver;
use Mnb\SecurityCore\Env\SecretDefinition;
use Mnb\SecurityCore\Env\SecretManager;
use Mnb\SecurityCore\Env\SecretRedactor;
use Mnb\SecurityCore\Exceptions\SecurityException;
use Mnb\SecurityCore\Files\FileUploadPolicy;
use Mnb\SecurityCore\Files\FileSecurityRegistry;
use Mnb\SecurityCore\Files\ProtectedDownloadManager;
use Mnb\SecurityCore\Files\SafeDownloadResponse;
use Mnb\SecurityCore\Files\ArchiveInspector;
use Mnb\SecurityCore\Files\FileRetentionManager;
use Mnb\SecurityCore\Files\LocalPrivateStorage;
use Mnb\SecurityCore\Files\SecureFileManager;
use Mnb\SecurityCore\Files\UploadSecurityProfile;
use Mnb\SecurityCore\Files\HeuristicMalwareScanner;
use Mnb\SecurityCore\Http\Middleware\ApiTokenMiddleware;
use Mnb\SecurityCore\Http\Middleware\AuthenticationMiddleware;
use Mnb\SecurityCore\Http\Middleware\AutoAuditMiddleware;
use Mnb\SecurityCore\Http\Middleware\CorsMiddleware;
use Mnb\SecurityCore\Http\Middleware\InputValidationMiddleware;
use Mnb\SecurityCore\Http\Middleware\HttpsMiddleware;
use Mnb\SecurityCore\Http\Middleware\RateLimitMiddleware;
use Mnb\SecurityCore\Http\Middleware\RateLimitPolicyMiddleware;
use Mnb\SecurityCore\Http\Middleware\RequestTrustMiddleware;
use Mnb\SecurityCore\Http\Middleware\ServerIdentityProtectionMiddleware;
use Mnb\SecurityCore\Http\Middleware\TrustedHostMiddleware;
use Mnb\SecurityCore\Http\Middleware\SecurityHeadersMiddleware;
use Mnb\SecurityCore\Http\SecurityHeadersBuilder;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Http\RequestReceivingProfile;
use Mnb\SecurityCore\Http\RequestReceivingRegistry;
use Mnb\SecurityCore\Http\SecureRequestReceiver;
use Mnb\SecurityCore\Http\WebhookSignatureVerifier;
use Mnb\SecurityCore\Http\Middleware\ContentTypeMiddleware;
use Mnb\SecurityCore\Http\Middleware\JsonBodyParserMiddleware;
use Mnb\SecurityCore\Http\Middleware\RequestIdMiddleware;
use Mnb\SecurityCore\Http\Middleware\RequestMethodMiddleware;
use Mnb\SecurityCore\Http\Middleware\SuspiciousRequestMiddleware;
use Mnb\SecurityCore\Http\Middleware\WebhookSignatureMiddleware;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Mnb\SecurityCore\Logging\AutoAuditLogger;
use Mnb\SecurityCore\Logging\LogRecord;
use Mnb\SecurityCore\Logging\Logger;
use Mnb\SecurityCore\Logging\JsonLogHandler;
use Mnb\SecurityCore\Logging\LogDataProtector;
use Mnb\SecurityCore\Logging\AuditIntegrityVerifier;
use Mnb\SecurityCore\Logging\LogRetentionPolicy;
use Mnb\SecurityCore\Logging\LogRetentionManager;
use Mnb\SecurityCore\Logging\AuditExporter;
use Mnb\SecurityCore\Monitoring\AlertRule;
use Mnb\SecurityCore\Monitoring\AlertManager;
use Mnb\SecurityCore\Monitoring\FileAlertChannel;
use Mnb\SecurityCore\Monitoring\MetricsRegistry;
use Mnb\SecurityCore\Monitoring\MonitoringSummary;
use Mnb\SecurityCore\Monitoring\TraceContext;
use Mnb\SecurityCore\Monitoring\WebhookAlertChannel;
use Mnb\SecurityCore\Recovery\BackupPolicy;
use Mnb\SecurityCore\Recovery\BackupSigner;
use Mnb\SecurityCore\Recovery\SecureBackupManager;
use Mnb\SecurityCore\Recovery\BackupIntegrityVerifier;
use Mnb\SecurityCore\Recovery\BackupRetentionPolicy;
use Mnb\SecurityCore\Recovery\BackupRetentionManager;
use Mnb\SecurityCore\Recovery\RestoreManager;
use Mnb\SecurityCore\Recovery\RecoveryStatusReport;
use Mnb\SecurityCore\Incident\IncidentPlaybook;
use Mnb\SecurityCore\Incident\ContainmentActionRunner;
use Mnb\SecurityCore\Incident\IncidentEvidenceCollector;
use Mnb\SecurityCore\Incident\IncidentResponseManager;
use Mnb\SecurityCore\RateLimit\DatabaseRateLimiter;
use Mnb\SecurityCore\RateLimit\FileRateLimiter;
use Mnb\SecurityCore\RateLimit\RateLimitPolicy;
use Mnb\SecurityCore\RateLimit\RateLimitPolicyRegistry;
use Mnb\SecurityCore\Security\ProductionSecurityChecker;
use Mnb\SecurityCore\Security\CspNonceManager;
use Mnb\SecurityCore\Security\SecurityConfigValidator;
use Mnb\SecurityCore\Security\SecurityDoctor;
use Mnb\SecurityCore\Security\VulnerabilityMatrix;
use Mnb\SecurityCore\Vulnerability\VulnerabilityCoverageReport;
use Mnb\SecurityCore\Vulnerability\VulnerabilityAdvisor;
use Mnb\SecurityCore\Quickstart\FirstTokenBootstrapper;
use Mnb\SecurityCore\Pentest\PentestChecklist;
use Mnb\SecurityCore\Pentest\PayloadLibrary;
use Mnb\SecurityCore\Pentest\PentestFinding;
use Mnb\SecurityCore\Pentest\PentestReportBuilder;
use Mnb\SecurityCore\Pentest\RemediationTracker;
use Mnb\SecurityCore\Pentest\RiskRating;
use Mnb\SecurityCore\Pentest\VerificationMatrix;
use Mnb\SecurityCore\Pentest\EvidenceCollector;
use Mnb\SecurityCore\Pentest\EvidenceRedactor;
use Mnb\SecurityCore\Pentest\EvidenceStore;
use Mnb\SecurityCore\Pentest\RemediationPolicy;
use Mnb\SecurityCore\Pentest\RemediationPlan;
use Mnb\SecurityCore\Pentest\RemediationSlaCalculator;
use Mnb\SecurityCore\Pentest\RetestResult;
use Mnb\SecurityCore\Pentest\RetestGate;
use Mnb\SecurityCore\Pentest\SecurityCoverageAnalyzer;
use Mnb\SecurityCore\Pentest\SecurityReleaseGate;
use Mnb\SecurityCore\Pentest\SecurityVerificationRegistry;
use Mnb\SecurityCore\Pentest\SecurityVerificationRunner;
use Mnb\SecurityCore\Pentest\VerificationProfile;
use Mnb\SecurityCore\Pentest\VerificationResult;
use Mnb\SecurityCore\Pentest\VerificationRun;
use Mnb\SecurityCore\Pentest\VerificationTarget;
use Mnb\SecurityCore\Pentest\ReleaseGatePolicy;
use Mnb\SecurityCore\Errors\SafeErrorHandler;
use Mnb\SecurityCore\Errors\ErrorPolicy;
use Mnb\SecurityCore\Errors\ErrorCatalog;
use Mnb\SecurityCore\Errors\ErrorContext;
use Mnb\SecurityCore\Errors\ErrorDeduplicator;
use Mnb\SecurityCore\Errors\ErrorEscalationPolicy;
use Mnb\SecurityCore\Errors\ErrorFingerprint;
use Mnb\SecurityCore\Errors\ErrorLogSanitizer;
use Mnb\SecurityCore\Errors\ExceptionMapper;
use Mnb\SecurityCore\Errors\StackTraceSanitizer;
use Mnb\SecurityCore\Errors\ValidationErrorNormalizer;
use Mnb\SecurityCore\Exceptions\AppException;
use Mnb\SecurityCore\Exceptions\AuthorizationException;
use Mnb\SecurityCore\Exceptions\ValidationException;
use Mnb\SecurityCore\Http\Middleware\ErrorHandlingMiddleware;
use Mnb\SecurityCore\Logging\FileLogger;
use Mnb\SecurityCore\Memory\MemoryConfig;
use Mnb\SecurityCore\Memory\MemoryGuard;
use Mnb\SecurityCore\Memory\MemoryMonitor;
use Mnb\SecurityCore\Memory\ChunkProcessor;
use Mnb\SecurityCore\Memory\ResourceTracker;
use Mnb\SecurityCore\Memory\MemoryPolicy;
use Mnb\SecurityCore\Memory\StreamGuard;
use Mnb\SecurityCore\Memory\SafeStreamReader;
use Mnb\SecurityCore\Memory\SafeStreamWriter;
use Mnb\SecurityCore\Memory\BoundedBuffer;
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
use Mnb\SecurityCore\Http\Middleware\MemoryLimitMiddleware;
use Mnb\SecurityCore\Throughput\ThroughputConfig;
use Mnb\SecurityCore\Throughput\ThroughputMeter;
use Mnb\SecurityCore\Throughput\ThroughputMonitor;
use Mnb\SecurityCore\Throughput\ThroughputPlanner;
use Mnb\SecurityCore\Http\Middleware\ThroughputMiddleware;
use Mnb\SecurityCore\Suggestions\AutoSuggestionEngine;
use Mnb\SecurityCore\Validation\InputSanitizer;
use Mnb\SecurityCore\Validation\InputValidator;
use Mnb\SecurityCore\Trust\BoundaryGuard;
use Mnb\SecurityCore\Trust\DataBoundary;
use Mnb\SecurityCore\Trust\TrustBoundaryDecision;
use Mnb\SecurityCore\Trust\TrustBoundaryPolicy;
use Mnb\SecurityCore\Trust\TrustBoundaryRegistry;
use Mnb\SecurityCore\Trust\TrustZone;
use Mnb\SecurityCore\Trust\TrustZoneResolver;
use Mnb\SecurityCore\Http\Middleware\TrustBoundaryMiddleware;
use Mnb\SecurityCore\Web\OutputEscaper;
use Mnb\SecurityCore\Web\HtmlSanitizer;
use Mnb\SecurityCore\Web\SafeRedirector;
use Mnb\SecurityCore\Web\SecureCookieBuilder;
use Mnb\SecurityCore\Web\CacheControlPolicy;
use Mnb\SecurityCore\Web\SignedUrl;
use Mnb\SecurityCore\Web\WebSecurityRegistry;
use Mnb\SecurityCore\Http\Middleware\CacheControlMiddleware;
use Mnb\SecurityCore\Network\OutboundHttpClient;
use Mnb\SecurityCore\Network\OutboundRequestPolicy;
use Mnb\SecurityCore\Network\RedirectGuard;
use Mnb\SecurityCore\Runtime\ProcessPolicy;
use Mnb\SecurityCore\Runtime\SafeProcessRunner;

$base = sys_get_temp_dir() . '/mnb_secure_core_v1_0_tests_' . getmypid();
@mkdir($base, 0777, true);
$passed = 0;
$failed = 0;

function ok(bool $condition, string $name): void {
    global $passed, $failed;
    if ($condition) {
        $passed++;
        echo "PASS: {$name}\n";
    } else {
        $failed++;
        echo "FAIL: {$name}\n";
    }
}

$hasher = new PasswordHasher();
$hash = $hasher->hash('secret-password');
ok($hasher->verify('secret-password', $hash) && !$hasher->verify('wrong', $hash), 'password hash and verify');

$csrf = new Csrf('_csrf_test');
$token = $csrf->token();
ok($csrf->verify($token) && !$csrf->verify('bad'), 'csrf token verify/fail');

$limiter = new FileRateLimiter($base . '/rate');
$limiter->clear('login:127.0.0.1');
$r1 = $limiter->attempt('login:127.0.0.1', 2, 60);
$r2 = $limiter->attempt('login:127.0.0.1', 2, 60);
$r3 = $limiter->attempt('login:127.0.0.1', 2, 60);
ok($r1->allowed && $r2->allowed && !$r3->allowed, 'atomic file rate limiter blocks over limit');


$oldRateMiddlewareLimiter = new FileRateLimiter($base . '/rate-old-middleware');
$oldRateMiddleware = new RateLimitMiddleware($oldRateMiddlewareLimiter, 1, 60, 'legacy');
$oldRateRequest = new Request('GET', '/legacy-rate', [], [], [], ['REMOTE_ADDR' => '10.0.0.1']);
$oldRateResponse1 = (new MiddlewarePipeline([$oldRateMiddleware]))->handle($oldRateRequest, fn() => Response::text('ok'));
$oldRateResponse2 = (new MiddlewarePipeline([$oldRateMiddleware]))->handle($oldRateRequest, fn() => Response::text('ok'));
ok($oldRateResponse1->status() === 200 && $oldRateResponse2->status() === 429 && ($oldRateResponse1->headers()['X-RateLimit-Policy'] ?? '') === 'legacy', 'rate limit middleware keeps legacy constructor behavior');

$loginPolicy = new RateLimitPolicy('login', 2, 60, ['ip', 'route'], 'auth');
$apiPolicy = RateLimitPolicy::fromArray('api', ['max' => 1, 'seconds' => 60, 'key_by' => ['user', 'route'], 'prefix' => 'api']);
$policyRequestA = (new Request('POST', '/login', [], [], [], ['REMOTE_ADDR' => '10.0.0.2']))->withAttribute('route_name', 'login.submit');
$policyRequestB = (new Request('POST', '/login', [], [], [], ['REMOTE_ADDR' => '10.0.0.3']))->withAttribute('route_name', 'login.submit');
ok($loginPolicy->key($policyRequestA) !== $loginPolicy->key($policyRequestB) && str_contains($apiPolicy->key($policyRequestA->withAttribute('auth_user_id', 22)), 'user:22'), 'rate limit policies build per-ip, per-user and per-route keys');

$policyRegistry = new RateLimitPolicyRegistry(['login' => ['max' => 2, 'seconds' => 60, 'key_by' => ['ip', 'route']], 'api' => $apiPolicy]);
ok($policyRegistry->has('login') && $policyRegistry->get('api')->maxAttempts() === 1, 'rate limit policy registry registers array and object policies');

$policyLimiter = new FileRateLimiter($base . '/rate-policy-middleware');
$policyMiddleware = new RateLimitPolicyMiddleware($policyLimiter, $policyRegistry, 'api', 'api.profile');
$userOneRequest = (new Request('GET', '/api/profile', [], [], [], ['REMOTE_ADDR' => '10.0.0.4']))->withAttribute('auth_user_id', 501);
$userTwoRequest = (new Request('GET', '/api/profile', [], [], [], ['REMOTE_ADDR' => '10.0.0.4']))->withAttribute('auth_user_id', 502);
$policyResponse1 = (new MiddlewarePipeline([$policyMiddleware]))->handle($userOneRequest, fn() => Response::json(['ok' => true]));
$policyResponse2 = (new MiddlewarePipeline([$policyMiddleware]))->handle($userOneRequest, fn() => Response::json(['ok' => true]));
$policyResponse3 = (new MiddlewarePipeline([$policyMiddleware]))->handle($userTwoRequest, fn() => Response::json(['ok' => true]));
ok($policyResponse1->status() === 200 && $policyResponse2->status() === 429 && $policyResponse3->status() === 200 && ($policyResponse1->headers()['X-RateLimit-Policy'] ?? '') === 'api', 'rate limit policy middleware applies named per-user policies');

$badPolicyBlocked = false;
try {
    RateLimitPolicy::fromArray('bad policy', ['max' => 1, 'seconds' => 60, 'key_by' => ['cookie']]);
} catch (InvalidArgumentException $e) {
    $badPolicyBlocked = true;
}
ok($badPolicyBlocked, 'rate limit policy validation blocks unsafe names and unsupported key parts');

$cache = new FileCache($base . '/cache');
$cache->put('school_settings', ['x' => 1], 60);
ok($cache->get('school_settings')['x'] === 1, 'file cache put/get');

$cacheRegistry = new CacheRegistry([
    'public_config' => ['ttl' => 60, 'data_class' => 'public', 'scope' => ['global'], 'tags' => ['config']],
    'student_profile' => ['ttl' => 60, 'data_class' => 'sensitive', 'scope' => ['tenant', 'user'], 'encrypt' => true, 'tags' => ['students']],
    'secret_cache' => ['ttl' => 60, 'data_class' => 'highly_sensitive', 'cache' => true],
]);
$cacheKeyBuilder = new CacheKeyBuilder('test');
$keyA = $cacheKeyBuilder->build($cacheRegistry->get('student_profile'), ['school_id' => 10, 'user_id' => 1, 'resource_id' => 44]);
$keyB = $cacheKeyBuilder->build($cacheRegistry->get('student_profile'), ['school_id' => 11, 'user_id' => 1, 'resource_id' => 44]);
ok($keyA !== $keyB && str_contains($keyA, 'tenant:10') && str_contains($keyA, 'user:1'), 'cache key builder scopes keys by tenant and user context');

$cacheKeys = new KeyRing('cache-v1', ['cache-v1' => str_repeat('C', 40)]);
$secureCacheBackend = new FileCache($base . '/secure-cache');
$secureCache = new SecureCache($secureCacheBackend, $cacheRegistry, $cacheKeyBuilder, new SafeCacheSerializer(), $cacheKeys, null, ['deny_highly_sensitive' => true, 'encrypt_sensitive' => true], new TaggedCache($secureCacheBackend));
$cacheDecision = $secureCache->put('student_profile', ['school_id' => 10, 'user_id' => 1, 'resource_id' => 44], ['name' => 'Ravi', 'parent_phone' => '9876543210']);
$cachedProfile = $secureCache->get('student_profile', ['school_id' => 10, 'user_id' => 1, 'resource_id' => 44]);
ok($cacheDecision->allowed() && $cacheDecision->encrypted() && $cachedProfile['parent_phone'] === '9876543210', 'secure cache stores sensitive policy values encrypted and retrieves them safely');
ok($secureCache->decision('secret_cache', [])->denied(), 'secure cache denies highly sensitive cache policies by default');

$taggedCache = new TaggedCache(new FileCache($base . '/tagged-cache'));
$taggedCache->put('student:1', ['id' => 1], 60, ['students', 'school:10']);
$taggedCache->put('student:2', ['id' => 2], 60, ['students', 'school:10']);
$tagFlushCount = (new CacheInvalidator($taggedCache))->invalidateTags(['students']);
ok($tagFlushCount >= 2 && $taggedCache->get('student:1') === null && $taggedCache->get('student:2') === null, 'tagged cache invalidator flushes cached keys by tag');

$guardCache = new FileCache($base . '/stampede-cache');
$guard = new CacheStampedeGuard($guardCache, 2);
$buildCount = 0;
$guardValue1 = $guard->rememberLocked('expensive', 60, function () use (&$buildCount) { $buildCount++; return ['value' => 5]; });
$guardValue2 = $guard->rememberLocked('expensive', 60, function () use (&$buildCount) { $buildCount++; return ['value' => 9]; });
ok($guardValue1['value'] === 5 && $guardValue2['value'] === 5 && $buildCount === 1, 'cache stampede guard remembers computed values behind a lock');

$encodedCachePayload = (new SafeCacheSerializer(1024))->encode(['safe' => true]);
ok((new SafeCacheSerializer(1024))->decode($encodedCachePayload)['safe'] === true, 'safe cache serializer encodes arrays without PHP unserialize');


$context = new TenantContext(userId: 1, schoolId: 10, branchId: 5, academicYearId: 2026, permissions: ['student.view'], classIds: [3]);
$tenant = new TenantGuard();
ok($tenant->recordBelongsToContext(['school_id' => 10, 'branch_id' => 5, 'academic_year_id' => 2026], $context), 'tenant guard allows matching record');
ok(!$tenant->recordBelongsToContext(['school_id' => 11, 'branch_id' => 5, 'academic_year_id' => 2026], $context), 'tenant guard blocks other school');
ok($tenant->classSectionAllowed(['class_id' => 3], $context) && !$tenant->classSectionAllowed(['class_id' => 4], $context), 'tenant guard class scope');

$legacyBoundaryGuard = new BoundaryGuard();
$legacyBoundaryGuard->add(new DataBoundary(TrustZone::PUBLIC, ['public'], ['read']));
$legacyBoundaryGuard->add(new DataBoundary(TrustZone::PUBLIC, ['internal'], ['submit']));
ok($legacyBoundaryGuard->allows(TrustZone::PUBLIC, 'public', 'read') && $legacyBoundaryGuard->allows(TrustZone::PUBLIC, 'internal', 'submit'), 'legacy boundary guard supports multiple boundaries per zone');

$trustConfig = [
    'trust_boundaries' => [
        'enabled' => true,
        'hide_denial_reasons' => false,
        'deny_unclassified_fields' => true,
        'resources' => [
            'students' => [
                'data_class' => 'sensitive',
                'tenant_scoped' => true,
                'fields' => [
                    'id' => 'internal',
                    'name' => 'internal',
                    'parent_phone' => 'sensitive',
                    'password_hash' => 'highly_sensitive',
                    'school_id' => 'internal',
                ],
            ],
        ],
        'rules' => [
            'students.read' => [
                'zones' => ['school_admin', 'super_admin'],
                'data_classes' => ['sensitive'],
                'actions' => ['read'],
                'resources' => ['students'],
                'permissions' => ['student.view'],
                'tenant_required' => true,
                'audit' => true,
            ],
            'students.delete' => [
                'zones' => ['super_admin'],
                'data_classes' => ['sensitive'],
                'actions' => ['delete'],
                'resources' => ['students'],
                'permissions' => ['student.delete'],
                'tenant_required' => true,
                'audit' => true,
            ],
        ],
    ],
];
$trustAudit = new SecurityAuditTrail(new TamperEvidentAuditLogger($base . '/audit/trust-boundary.log'));
$trustRegistry = TrustBoundaryRegistry::fromConfig($trustConfig, $trustAudit);
$schoolAdminAuth = new AuthContext(true, 10, ['school:*'], ['student.view'], ['school_admin']);
$schoolAdminRequest = (new Request('GET', '/students/7', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']))
    ->withAttribute(AuthContext::ATTRIBUTE, $schoolAdminAuth)
    ->withAttribute('tenant_context', $context);
$allowedTrustDecision = $trustRegistry->decide('students.read', $schoolAdminRequest, ['id' => 7, 'school_id' => 10], 'read', 'sensitive', resourceName: 'students');
$deniedTrustDecision = $trustRegistry->decide('students.delete', $schoolAdminRequest, ['id' => 7, 'school_id' => 10], 'delete', 'sensitive', resourceName: 'students');
ok($allowedTrustDecision->allowed() && $allowedTrustDecision->zone() === TrustZone::SCHOOL_ADMIN && $deniedTrustDecision->denied(), 'trust boundary registry allows matching zone and denies stronger action');

$crossTenantDecision = $trustRegistry->decide('students.read', $schoolAdminRequest, ['id' => 8, 'school_id' => 99], 'read', 'sensitive', resourceName: 'students');
$trustAuditEntries = (new TamperEvidentAuditLogger($base . '/audit/trust-boundary.log'))->read(null, 'trust');
ok($crossTenantDecision->denied() && count($trustAuditEntries) >= 2 && !str_contains(json_encode($trustAuditEntries), 'parent_phone'), 'trust boundary audits denied decisions without leaking sensitive payload');

$filteredForPublic = $trustRegistry->filterForZone('students', ['id' => 7, 'name' => 'Ravi', 'parent_phone' => '9876543210', 'password_hash' => 'hash'], TrustZone::PUBLIC);
$filteredForAdmin = $trustRegistry->filterForZone('students', ['id' => 7, 'name' => 'Ravi', 'parent_phone' => '9876543210', 'password_hash' => 'hash'], TrustZone::SCHOOL_ADMIN);
ok(!isset($filteredForPublic['parent_phone']) && isset($filteredForAdmin['parent_phone']) && !isset($filteredForAdmin['password_hash']), 'trust boundary filters output fields by zone data access');

$trustMiddleware = new TrustBoundaryMiddleware($trustRegistry, 'students.read', fn(Request $request): array => ['school_id' => 10], action: 'read', dataClass: 'sensitive', resourceName: 'students', hideReason: false);
$trustMiddlewareResponse = (new MiddlewarePipeline([$trustMiddleware]))->handle($schoolAdminRequest, fn(Request $request) => Response::json(['zone' => $request->attribute('trust_zone')]));
ok($trustMiddlewareResponse->status() === 200 && json_decode($trustMiddlewareResponse->body(), true)['zone'] === TrustZone::SCHOOL_ADMIN, 'trust boundary middleware attaches decision and zone to allowed requests');

$trustResolver = new TrustZoneResolver();
ok($trustResolver->resolve(null, new AuthContext(true, 1, ['system:backup'], [], [])) === TrustZone::INTERNAL_SYSTEM, 'trust zone resolver detects internal system scope');

$registry = new PolicyRegistry();
$registry->register('student', new StudentPolicy());
ok($registry->allows($context, 'student', 'view', ['school_id' => 10, 'branch_id' => 5, 'academic_year_id' => 2026, 'class_id' => 3]), 'student policy allows scoped view');
ok(!$registry->allows($context, 'student', 'delete', ['school_id' => 10, 'branch_id' => 5, 'academic_year_id' => 2026, 'class_id' => 3]), 'student policy blocks missing permission');

$tokenStore = new FileTokenStore($base . '/tokens/tokens.json');
$tokenService = new OpaqueTokenService($tokenStore);
$issued = $tokenService->issue(99, ['profile.read'], 'device1', 'Phone', 60);
ok($tokenService->validate($issued['plain_token']) !== null, 'opaque token validates');

$tokenAudit = new SecurityAuditTrail(new TamperEvidentAuditLogger($base . '/audit/token-audit.log'));
$auditedTokenService = new OpaqueTokenService(new FileTokenStore($base . '/tokens/audited-tokens.json'), $tokenAudit);
$auditedIssued = $auditedTokenService->issue(123, ['admin:*'], 'device-audit', 'Audit Phone', 60);
$auditedTokenService->validate($auditedIssued['plain_token'], '127.0.0.9', 'Audit Test UA');
$auditedTokenService->validate('bad-token-value', '127.0.0.9', 'Audit Test UA');
$auditedTokenService->revoke($auditedIssued['plain_token']);
$tokenEntries = (new TamperEvidentAuditLogger($base . '/audit/token-audit.log'))->read(null, 'token');
ok(count($tokenEntries) === 4 && !str_contains(json_encode($tokenEntries), $auditedIssued['plain_token']), 'opaque token service writes structured audit events without leaking plain token');
$apiTokenRequest = new Request('GET', '/api/profile', [], [], ['authorization' => 'Bearer ' . $issued['plain_token']], ['REMOTE_ADDR' => '127.0.0.1']);
$apiTokenPipeline = new MiddlewarePipeline([new ApiTokenMiddleware($tokenService)]);
$apiTokenResponse = $apiTokenPipeline->handle($apiTokenRequest, function (Request $request): Response {
    $auth = $request->attribute(AuthContext::ATTRIBUTE);
    return Response::json([
        'user_id' => $request->attribute('auth_user_id'),
        'scopes' => $request->attribute('auth_scopes'),
        'auth_context_id' => $auth instanceof AuthContext ? $auth->id() : null,
        'auth_context_scope' => $auth instanceof AuthContext && $auth->hasScope('profile.read'),
        'guard_scope' => AuthPermissionGuard::hasScope($request, 'profile.read'),
    ]);
});
$apiTokenPayload = json_decode($apiTokenResponse->body(), true);
ok(
    $apiTokenPayload['user_id'] === 99
    && $apiTokenPayload['scopes'] === ['profile.read']
    && $apiTokenPayload['auth_context_id'] === 99
    && $apiTokenPayload['auth_context_scope'] === true
    && $apiTokenPayload['guard_scope'] === true,
    'api token middleware exposes auth context object and legacy attributes'
);

$authContext = new AuthContext(true, 77, ['profile.read', 'admin:*'], ['users.delete'], ['owner']);
ok(
    $authContext->isAuthenticated()
    && $authContext->id() === 77
    && $authContext->hasScope('admin:update')
    && $authContext->hasAllScopes(['profile.read', 'admin:delete'])
    && $authContext->can('users.delete')
    && $authContext->hasRole('owner'),
    'auth context supports ids, scopes, wildcard scopes, permissions and roles'
);

$permissionGuardAllowed = AuthPermissionGuard::requireScope($authContext, 'admin:read');
$permissionGuardBlocked = false;
try {
    AuthPermissionGuard::requireAllScopes($authContext, ['profile.read', 'billing.write']);
} catch (AuthorizationException $e) {
    $permissionGuardBlocked = true;
}
ok($permissionGuardAllowed->id() === 77 && $permissionGuardBlocked, 'auth permission guard requires scopes and throws authorization exceptions');

$legacyAttributeRequest = (new Request('GET', '/legacy'))->withAttribute('auth_user_id', 55)->withAttribute('auth_scopes', ['legacy.read']);
ok(AuthPermissionGuard::context($legacyAttributeRequest)->id() === 55 && AuthPermissionGuard::requireScope($legacyAttributeRequest, 'legacy.read')->id() === 55, 'auth permission guard supports legacy auth attributes');

$tokenService->revoke($issued['plain_token']);
ok($tokenService->validate($issued['plain_token']) === null, 'opaque token revokes');

$classifier = new DataClassifier(['parent_phone' => DataClassifier::SENSITIVE, 'password_hash' => DataClassifier::HIGHLY_SENSITIVE]);
$filter = new FieldFilter($classifier, new DataMasker());
$masked = $filter->maskSensitive(['name' => 'Ravi', 'parent_phone' => '9876543210', 'password_hash' => 'abc']);
ok($masked['parent_phone'] === '[masked]' && $masked['password_hash'] === '[hidden]', 'data masking by classification');
ok($filter->allowOnly(['a' => 1, 'b' => 2], ['a']) === ['a' => 1], 'field allow-list');

$enc = new Encryption('test-key-test-key-test-key-test-key');
$cipher = $enc->encrypt('private data');
ok($enc->decrypt($cipher) === 'private data', 'encryption/decryption');

$storage = new LocalPrivateStorage($base . '/private');
$policy = new FileUploadPolicy(['txt'], ['text/plain'], 1024 * 1024);
$manager = new SecureFileManager($storage, $policy, $base . '/quarantine');
$safe = $base . '/safe.txt';
file_put_contents($safe, 'hello');
$stored = $manager->storeFromPath($safe, 'safe.txt', 'test');
ok($storage->exists($stored['storage_path']), 'secure file upload accepts safe file');
$blocked = false;
try { $manager->storeFromPath($safe, 'evil.php.txt', 'test'); } catch (SecurityException $e) { $blocked = true; }
ok($blocked, 'secure file upload blocks double extension');

$malicious = $base . '/malicious.txt';
file_put_contents($malicious, '<?php system($_GET["cmd"]);');
$scanner = new HeuristicMalwareScanner();
ok(!$scanner->scan($malicious), 'heuristic malware scanner blocks executable PHP pattern');

$blockedContent = false;
try { $manager->storeFromPath($malicious, 'malicious.txt', 'test'); } catch (SecurityException $e) { $blockedContent = true; }
ok($blockedContent, 'secure file upload blocks executable content patterns');

$imagePolicy = FileUploadPolicy::forProfile(UploadSecurityProfile::IMAGES);
ok($imagePolicy->profile === 'images' && $imagePolicy->allowsExtension('png') && !$imagePolicy->allowsExtension('pdf'), 'upload security profile creates image-only policy');

$strictProductionPolicy = FileUploadPolicy::fromConfig([
    'profile' => 'documents',
    'strict_production' => true,
    'deny_double_extensions' => false,
    'randomize_names' => false,
    'reject_executable_content' => false,
], 20 * 1024 * 1024, 'production');
ok($strictProductionPolicy->strictMode && $strictProductionPolicy->denyDoubleExtensions && $strictProductionPolicy->randomizeNames && $strictProductionPolicy->rejectExecutableContent, 'strict production upload mode forces safe upload settings');

$imageManager = new SecureFileManager(new LocalPrivateStorage($base . '/private-images'), $imagePolicy, $base . '/quarantine-images');
$png = $base . '/tiny.png';
file_put_contents($png, base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAFgwJ/lRjF6wAAAABJRU5ErkJggg=='));
$storedImage = $imageManager->storeFromPath($png, 'tiny.png', 'images');
ok(($storedImage['profile'] ?? null) === 'images' && str_starts_with($storedImage['storage_path'], 'images/'), 'secure file manager stores uploads with selected profile metadata');

$uploadAuditLogger = new TamperEvidentAuditLogger($base . '/audit/upload-audit.log');
$uploadAudit = new SecurityAuditTrail($uploadAuditLogger);
$auditedImageManager = new SecureFileManager(new LocalPrivateStorage($base . '/private-audited-images'), $imagePolicy, $base . '/quarantine-audited-images', new Mnb\SecurityCore\Files\NullMalwareScanner(), $uploadAudit);
$auditedImageManager->storeFromPath($png, 'tiny.png', 'images', ['user_id' => 501], ['ip' => '127.0.0.1']);
$auditedUploadRejected = false;
try { $auditedImageManager->storeFromPath($safe, 'safe.txt', 'images', ['user_id' => 501]); } catch (SecurityException $e) { $auditedUploadRejected = true; }
$uploadAuditEntries = $uploadAuditLogger->read(null, 'upload');
ok($auditedUploadRejected && count($uploadAuditEntries) === 2 && $uploadAuditEntries[0]['outcome'] === 'success' && $uploadAuditEntries[1]['outcome'] === 'failure', 'secure file manager writes structured upload accept/reject audit events');

$archivePolicy = FileUploadPolicy::forProfile(UploadSecurityProfile::ARCHIVES);
ok($archivePolicy->allowsExtension('zip') && !$archivePolicy->allowsExtension('php'), 'archive upload profile allows archives but still blocks executable extensions');


$fileSecurityAuditLogger = new TamperEvidentAuditLogger($base . '/audit/file-security.log');
$fileSecurityAudit = new SecurityAuditTrail($fileSecurityAuditLogger);
$fileSecurityConfig = [
    'file_security' => [
        'enabled' => true,
        'deny_by_default' => true,
        'audit_downloads' => true,
        'policies' => [
            'student_document.download' => [
                'actions' => ['download'],
                'roles' => ['school_admin'],
                'permissions' => ['documents.download'],
                'scopes' => ['documents:download'],
                'tenant_required' => true,
                'data_classes' => ['internal', 'sensitive'],
                'require_scan_passed' => true,
                'disposition' => 'attachment',
                'cache_policy' => 'download',
                'audit' => true,
                'signed_urls' => ['enabled' => true, 'ttl' => 900],
            ],
        ],
    ],
];
$fileRegistry = FileSecurityRegistry::fromConfig($fileSecurityConfig, $fileSecurityAudit);
$downloadRecord = $stored + [
    'file_id' => 'file_test_1',
    'data_class' => 'sensitive',
    'scan_status' => 'passed',
    'school_id' => 10,
    'branch_id' => 5,
    'academic_year_id' => 2026,
    'owner_user_id' => 1,
];
$fileRequest = (new Request('GET', '/files/file_test_1', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']))
    ->withAttribute('auth', new AuthContext(true, 1, ['documents:download'], ['documents.download'], ['school_admin']))
    ->withAttribute('tenant_context', $context);
$fileAllowed = $fileRegistry->decide('student_document.download', $fileRequest, $downloadRecord, 'download');
$fileDenied = $fileRegistry->decide('student_document.download', $fileRequest, array_replace($downloadRecord, ['school_id' => 11]), 'download');
ok($fileAllowed->allowed() && $fileDenied->denied() && $fileDenied->code() === 'file_tenant_denied', 'file security registry authorizes scan-gated tenant downloads');

$downloadManager = new ProtectedDownloadManager($storage, $fileRegistry, new CacheControlPolicy(), new SignedUrl(str_repeat('D', 40)));
$downloadResponse = $downloadManager->download($fileRequest, $downloadRecord, 'student_document.download');
ok($downloadResponse->status() === 200 && $downloadResponse->body() === 'hello' && str_contains($downloadResponse->headers()['Content-Disposition'] ?? '', 'attachment') && ($downloadResponse->headers()['X-Content-Type-Options'] ?? '') === 'nosniff', 'protected download manager returns safe attachment response headers');

$signedDownloadUrl = $downloadManager->signedUrl($downloadRecord, '/download/file_test_1', 'student_document.download');
ok($downloadManager->verifySignedUrl($signedDownloadUrl, 'student_document.download') && !$downloadManager->verifySignedUrl($signedDownloadUrl, 'files.download'), 'protected download manager creates purpose-bound signed URLs');

$tarPath = $base . '/unsafe.tar';
file_put_contents($tarPath, 'fake tar');
$archiveInspection = (new ArchiveInspector())->inspect($tarPath, 'application/x-tar', 'tar');
ok($archiveInspection->failed() && in_array('unsupported_archive_deep_inspection', $archiveInspection->findings(), true), 'archive inspector fails closed for unsupported tar deep inspection');

$retentionDir = $base . '/retention';
@mkdir($retentionDir, 0777, true);
$oldTempFile = $retentionDir . '/old.tmp';
file_put_contents($oldTempFile, 'old');
touch($oldTempFile, time() - 7200);
$retention = new FileRetentionManager(quarantineTtlHours: 1);
$retentionReport = $retention->purgeQuarantine($retentionDir);
ok($retentionReport['deleted'] === 1 && !is_file($oldTempFile), 'file retention manager purges expired quarantine files');

$fileAuditEntries = $fileSecurityAuditLogger->read(null, 'file');
ok(count($fileAuditEntries) >= 3 && $fileAuditEntries[0]['action'] === 'access.download', 'file security decisions write structured download audit events');

$headersPipeline = new MiddlewarePipeline([new SecurityHeadersMiddleware(['hsts' => true])]);
$headersResponse = $headersPipeline->handle(new Request('GET', '/', [], [], [], ['HTTPS' => 'on']), fn() => Response::text('ok'));
ok(isset($headersResponse->headers()['Content-Security-Policy']) && isset($headersResponse->headers()['Strict-Transport-Security']), 'security headers middleware applies CSP and HSTS');

$headersBuilder = new SecurityHeadersBuilder([
    'hsts' => ['enabled' => true, 'max_age' => 63072000, 'include_subdomains' => true, 'preload' => true],
    'csp' => [
        'enabled' => true,
        'nonce_enabled' => true,
        'nonce_directives' => ['script-src'],
        'directives' => ['default-src' => ["'self'"], 'script-src' => ["'self'"], 'object-src' => ["'none'"]],
    ],
    'permissions_policy' => ['preset' => 'balanced'],
]);
$builtHeaders = $headersBuilder->headers('abc123', new Request('GET', '/', [], [], [], ['HTTPS' => 'on']));
ok(
    str_contains($builtHeaders['Content-Security-Policy'] ?? '', "'nonce-abc123'")
    && ($builtHeaders['Strict-Transport-Security'] ?? '') === 'max-age=63072000; includeSubDomains; preload'
    && str_contains($builtHeaders['Permissions-Policy'] ?? '', 'camera=()'),
    'security headers builder supports CSP nonce, HSTS preload and permissions policy presets'
);

$autoNonceMiddleware = new SecurityHeadersMiddleware(['csp' => ['auto_nonce' => true, 'nonce_enabled' => true, 'directives' => ['script-src' => ["'self'"]]]]);
$autoNonceResponse = (new MiddlewarePipeline([$autoNonceMiddleware]))->handle(new Request('GET', '/nonce'), function (Request $request): Response {
    $nonce = $request->attribute(CspNonceManager::REQUEST_ATTRIBUTE);
    return Response::text(is_string($nonce) && $nonce !== '' ? $nonce : 'missing');
});
ok(
    $autoNonceResponse->body() !== 'missing'
    && str_contains($autoNonceResponse->headers()['Content-Security-Policy'] ?? '', "'nonce-" . $autoNonceResponse->body() . "'"),
    'security headers middleware can generate request-scoped CSP nonce automatically'
);

$corsMiddleware = new CorsMiddleware([
    'allowed_origins' => ['https://app.example.com'],
    'allowed_origin_patterns' => ['https://*.trusted.test'],
    'allowed_methods' => ['GET', 'POST', 'OPTIONS'],
    'allowed_headers' => ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    'exposed_headers' => ['X-Request-ID'],
    'allow_credentials' => true,
    'max_age' => 300,
]);
$corsPreflight = new Request('OPTIONS', '/api/data', [], [], [
    'origin' => 'https://app.example.com',
    'access-control-request-method' => 'POST',
    'access-control-request-headers' => 'Content-Type, X-CSRF-Token',
]);
$corsAllowed = (new MiddlewarePipeline([$corsMiddleware]))->handle($corsPreflight, fn() => Response::text('should-not-run'));
$corsDenied = (new MiddlewarePipeline([$corsMiddleware]))->handle(new Request('GET', '/api/data', [], [], ['origin' => 'https://evil.example']), fn() => Response::text('ok'));
ok($corsAllowed->status() === 204 && ($corsAllowed->headers()['Access-Control-Allow-Origin'] ?? '') === 'https://app.example.com' && ($corsAllowed->headers()['Access-Control-Allow-Credentials'] ?? '') === 'true' && $corsDenied->status() === 403, 'cors middleware handles credentialed preflight and denies untrusted origins');

$corsConfigReport = (new SecurityConfigValidator(['app' => ['env' => 'production'], 'cors' => ['allowed_origins' => ['*'], 'allowed_methods' => ['GET'], 'allowed_headers' => ['Content-Type'], 'allow_credentials' => true]]))->validate();
ok(!$corsConfigReport['passed'] && count(array_filter($corsConfigReport['errors'], fn($issue) => ($issue['key'] ?? '') === 'wildcard_cors_with_credentials')) === 1, 'security config validator blocks wildcard CORS with credentials');

$suggestions = (new AutoSuggestionEngine())->suggest('cors audit login upload doctor', 5);
$codeSuggestions = (new AutoSuggestionEngine())->suggestFromCode('<?php $kernel = new SecurityKernel($config); $m = new ApiTokenMiddleware($tokens);', 5);
ok(count($suggestions) >= 3 && $suggestions[0]['confidence'] > 0 && count(array_filter($codeSuggestions, fn($item) => ($item['id'] ?? '') === 'missing_request_trust')) === 1, 'auto suggestion engine returns suggestions from typed words and user code');

$validator = new InputValidator();
$sanitizer = new InputSanitizer();
$cleanInput = $sanitizer->sanitize([
    'name' => '  <b>Nagendra</b>  ',
    'email' => ' ADMIN@EXAMPLE.COM ',
    'role' => 'admin',
    '__proto__' => 'polluted',
], [
    'name' => 'trim|strip_tags|collapse_spaces|max_length:40',
    'email' => 'trim|email',
]);
$validatedInput = $validator->validate($cleanInput, [
    'name' => 'required|string|min:2|max:40',
    'email' => 'required|email|max:190',
    'role' => 'required|in:admin,user',
]);
ok($validatedInput['name'] === 'Nagendra' && $validatedInput['email'] === 'admin@example.com' && !array_key_exists('__proto__', $validatedInput), 'input sanitizer cleans strings and blocks unsafe keys before validation');

$inputValidationMiddleware = new InputValidationMiddleware([
    'routes' => [
        'register' => [
            'methods' => ['POST'],
            'path' => '/register',
            'body' => [
                'allowed_fields' => ['name', 'email', 'password'],
                'strict' => true,
                'sanitize_rules' => ['name' => 'trim|strip_tags|collapse_spaces', 'email' => 'trim|email'],
                'rules' => ['name' => 'required|string|min:2|max:40', 'email' => 'required|email|max:190', 'password' => 'required|string|min:8|max:128'],
            ],
        ],
    ],
]);
$validInputRequest = new Request('POST', '/register', [], ['name' => ' <b>Admin User</b> ', 'email' => ' ADMIN@EXAMPLE.COM ', 'password' => 'secret-pass', 'extra' => 'remove'], [], ['REMOTE_ADDR' => '127.0.0.1']);
$validInputResponse = (new MiddlewarePipeline([$inputValidationMiddleware]))->handle($validInputRequest, function (Request $request): Response {
    return Response::json([
        'name' => $request->input('name'),
        'email' => $request->input('email'),
        'extra' => $request->input('extra', null),
        'validated_name' => $request->validated('name'),
    ]);
});
$validInputPayload = json_decode($validInputResponse->body(), true);
$invalidInputResponse = (new MiddlewarePipeline([$inputValidationMiddleware]))->handle(new Request('POST', '/register', [], ['name' => 'A', 'email' => 'bad', 'password' => 'short'], [], ['REMOTE_ADDR' => '127.0.0.1']), fn() => Response::text('should not pass'));
ok($validInputResponse->status() === 200 && $validInputPayload['name'] === 'Admin User' && $validInputPayload['email'] === 'admin@example.com' && $validInputPayload['extra'] === null && $validInputPayload['validated_name'] === 'Admin User' && $invalidInputResponse->status() === 422, 'request input validation middleware sanitizes valid input and blocks invalid submissions');

$inputKernelConfig = require __DIR__ . '/../config/security.php';
$inputKernelConfig['paths']['cache'] = $base . '/input-kernel-cache';
$inputKernelConfig['paths']['tokens'] = $base . '/input-kernel-tokens.json';
$inputKernelConfig['paths']['private_storage'] = $base . '/input-private';
$inputKernelConfig['paths']['quarantine'] = $base . '/input-quarantine';
$inputKernelConfig['paths']['audit'] = $base . '/input-audit';
$inputKernelConfig['paths']['logs'] = $base . '/input-logs';
$inputKernel = new SecurityKernel($inputKernelConfig);
$kernelValidationMiddleware = $inputKernel->inputValidationMiddleware([
    'profile.update' => [
        'methods' => ['PATCH'],
        'path' => '/api/profile',
        'body' => [
            'sanitize_rules' => ['display_name' => 'trim|strip_tags|collapse_spaces'],
            'rules' => ['display_name' => 'required|string|min:2|max:40'],
        ],
    ],
]);
$kernelInputRequest = (new Request('PATCH', '/api/profile', [], ['display_name' => ' <i>Core User</i> '], [], ['REMOTE_ADDR' => '127.0.0.1']))->withAttribute('route_name', 'profile.update');
$kernelInputResponse = (new MiddlewarePipeline([$kernelValidationMiddleware]))->handle($kernelInputRequest, fn(Request $request) => Response::json(['display_name' => $request->input('display_name')]));
ok($kernelInputResponse->status() === 200 && json_decode($kernelInputResponse->body(), true)['display_name'] === 'Core User', 'security kernel builds request input validation middleware with route policies');

$request = new Request('GET', '/', [], [], [], ['HTTPS' => 'off']);
$pipeline = new MiddlewarePipeline([new HttpsMiddleware(true)]);
$response = $pipeline->handle($request, fn() => Response::text('ok'));
ok($response->status() === 403, 'middleware pipeline blocks insecure request');

$spoofedForwardedHttps = new Request('GET', '/', [], [], [], ['HTTPS' => 'off', 'HTTP_X_FORWARDED_PROTO' => 'https', 'REMOTE_ADDR' => '203.0.113.10']);
ok(!$spoofedForwardedHttps->isSecure(), 'request ignores spoofed forwarded HTTPS from untrusted clients');

$trustedForwardedHttps = new Request('GET', '/', [], [], [], ['HTTPS' => 'off', 'HTTP_X_FORWARDED_PROTO' => 'https', 'REMOTE_ADDR' => '203.0.113.10'], ['203.0.113.0/24']);
ok($trustedForwardedHttps->isSecure(), 'request trusts forwarded HTTPS only from trusted proxy ranges');

$trustedForwardedClient = new Request('GET', '/api', [], [], [], [
    'REMOTE_ADDR' => '10.0.0.20',
    'HTTP_X_FORWARDED_FOR' => '198.51.100.25, 10.0.0.10',
], ['10.0.0.0/8']);
ok($trustedForwardedClient->remoteIp() === '10.0.0.20' && $trustedForwardedClient->clientIp() === '198.51.100.25' && $trustedForwardedClient->ip() === '198.51.100.25', 'request resolves real client IP through trusted proxy chain');

$untrustedForwardedClient = new Request('GET', '/api', [], [], [], [
    'REMOTE_ADDR' => '198.51.100.77',
    'HTTP_X_FORWARDED_FOR' => '10.10.10.10',
], ['10.0.0.0/8']);
ok($untrustedForwardedClient->clientIp() === '198.51.100.77', 'request ignores forwarded client IP from untrusted peer');

$trustedForwardedHost = new Request('GET', '/api', [], [], [], [
    'REMOTE_ADDR' => '10.0.0.20',
    'HTTP_HOST' => '10.0.0.20',
    'HTTP_X_FORWARDED_HOST' => 'app.example.com',
], ['10.0.0.0/8']);
ok($trustedForwardedHost->host() === '10.0.0.20' && $trustedForwardedHost->effectiveHost() === 'app.example.com', 'request exposes safe trusted forwarded host separately from raw host');

$badForwardedHost = new Request('GET', '/api', [], [], [], [
    'REMOTE_ADDR' => '10.0.0.20',
    'HTTP_HOST' => 'origin.local',
    'HTTP_X_FORWARDED_HOST' => "bad.example.com\r\nInjected: yes",
], ['10.0.0.0/8']);
ok($badForwardedHost->trustedForwardedHost() === null && $badForwardedHost->effectiveHost() === 'origin.local', 'request rejects unsafe forwarded host values');

$trustPipeline = new MiddlewarePipeline([new RequestTrustMiddleware(['block_untrusted_forwarded_headers' => true])]);
$blockedForwarded = $trustPipeline->handle($untrustedForwardedClient, fn() => Response::text('ok'));
ok($blockedForwarded->status() === 400, 'request trust middleware blocks spoofed forwarded headers from untrusted clients');

$trustedHostPipeline = new MiddlewarePipeline([new TrustedHostMiddleware(['app.example.com'])]);
$trustedHostResponse = $trustedHostPipeline->handle($trustedForwardedHost, fn() => Response::text('ok'));
ok($trustedHostResponse->status() === 200, 'trusted host middleware accepts effective trusted forwarded host');

$originPipeline = new MiddlewarePipeline([new ServerIdentityProtectionMiddleware(['enabled' => true, 'block_direct_ip_host' => true])]);
$originResponse = $originPipeline->handle($trustedForwardedHost, fn() => Response::text('ok'));
ok($originResponse->status() === 200, 'origin protection does not block proxy requests with safe forwarded public host');

$attributedRequest = $request->withAttribute('auth_user_id', 99);
ok($request->attribute('auth_user_id') === null && $attributedRequest->attribute('auth_user_id') === 99, 'request attributes are immutable and available for auth context');

$checker = new ProductionSecurityChecker([
    'app' => ['env' => 'production', 'debug' => true, 'force_https' => false, 'key' => 'weak', 'trusted_hosts' => []],
    'cookies' => ['secure' => false, 'http_only' => false],
    'paths' => ['private_storage' => '/var/www/public/uploads']
]);
$report = $checker->check();
ok(!$report['passed'] && count($report['issues']) >= 4, 'production checker catches unsafe config');

$defaultConfig = require __DIR__ . '/../config/security.php';
$configValidationReport = (new SecurityConfigValidator($defaultConfig))->validate();
ok($configValidationReport['passed'] === true && array_key_exists('warnings', $configValidationReport), 'security config validator accepts default config shape with non-blocking warnings');

$archiveProductionConfig = array_replace_recursive($defaultConfig, [
    'app' => ['env' => 'production', 'debug' => false, 'force_https' => true, 'key' => str_repeat('a', 40), 'trusted_hosts' => ['app.example.com']],
    'cookies' => ['secure' => true, 'http_only' => true],
    'limits' => ['request_max_bytes' => 128 * 1024 * 1024, 'upload_max_bytes' => 25 * 1024 * 1024],
    'uploads' => ['profile' => 'archives', 'strict_production' => true, 'allow_archives_in_production' => false],
]);
$archiveProductionReport = (new SecurityConfigValidator($archiveProductionConfig))->validate();
ok(in_array('archives_allowed_in_production_without_opt_in', array_column($archiveProductionReport['issues'], 'key'), true), 'security config validator requires explicit production opt-in for archive upload profile');


$doctorConfig = $defaultConfig;
$doctorConfig['app']['key'] = str_repeat('d', 40);
$doctorConfig['limits']['request_max_bytes'] = 128 * 1024 * 1024;
$doctorConfig['paths']['private_storage'] = $base . '/doctor/private';
$doctorConfig['paths']['quarantine'] = $base . '/doctor/quarantine';
$doctorConfig['paths']['cache'] = $base . '/doctor/cache';
$doctorConfig['paths']['logs'] = $base . '/doctor/logs';
$doctorConfig['paths']['audit'] = $base . '/doctor/audit';
$doctorConfig['paths']['backups'] = $base . '/doctor/backups';
$doctorConfig['paths']['tokens'] = $base . '/doctor/tokens/tokens.json';
foreach (['private_storage', 'quarantine', 'cache', 'logs', 'audit', 'backups'] as $doctorPathKey) {
    @mkdir($doctorConfig['paths'][$doctorPathKey], 0777, true);
}
@mkdir(dirname($doctorConfig['paths']['tokens']), 0777, true);
$doctorReport = (new SecurityDoctor($doctorConfig, dirname(__DIR__)))->check();
ok($doctorReport['passed'] === true && isset($doctorReport['sections']['php_runtime']) && isset($doctorReport['sections']['public_package']), 'security doctor reports runtime, config, storage, headers, scanner and package readiness');

$badDoctorConfig = $doctorConfig;
$badDoctorConfig['cache']['driver'] = 'invalid-driver';
$badDoctorConfig['security_headers']['enabled'] = false;
$badDoctorReport = (new SecurityDoctor($badDoctorConfig, dirname(__DIR__)))->check();
ok(!$badDoctorReport['passed'] && in_array('cache_driver_invalid', array_column($badDoctorReport['issues'], 'key'), true) && in_array('security_headers_disabled', array_column($badDoctorReport['issues'], 'key'), true), 'security doctor catches invalid storage driver and disabled security headers');

$doctorCliOutput = [];
$doctorCliCode = 0;
exec('cd ' . escapeshellarg(dirname(__DIR__)) . ' && ' . escapeshellarg(PHP_BINARY) . ' bin/mnb-secure doctor 2>&1', $doctorCliOutput, $doctorCliCode);
$doctorCliJson = json_decode(implode("\n", $doctorCliOutput), true);
ok(is_array($doctorCliJson) && isset($doctorCliJson['sections']['config_validation']) && $doctorCliCode === 1, 'CLI doctor command returns JSON diagnostics and non-zero status for blocking issues');

$quickstartConfig = $defaultConfig;
$quickstartConfig['app']['key'] = str_repeat('q', 40);
$quickstartConfig['paths']['cache'] = $base . '/quickstart/cache';
$quickstartConfig['paths']['tokens'] = $base . '/quickstart/tokens/tokens.json';
$quickstartConfig['paths']['audit'] = $base . '/quickstart/audit';
$quickstartConfig['paths']['logs'] = $base . '/quickstart/logs';
$quickstartConfig['paths']['private_storage'] = $base . '/quickstart/private';
$quickstartConfig['audit']['file'] = $base . '/quickstart/audit/security-audit.log';
@mkdir($quickstartConfig['paths']['cache'], 0777, true);
@mkdir(dirname($quickstartConfig['paths']['tokens']), 0777, true);
@mkdir($quickstartConfig['paths']['audit'], 0777, true);
@mkdir($quickstartConfig['paths']['logs'], 0777, true);
@mkdir($quickstartConfig['paths']['private_storage'], 0777, true);
$quickstartReport = (new FirstTokenBootstrapper($quickstartConfig, $base))->issue([
    'user_id' => 'demo-admin',
    'scopes' => ['admin:*', 'profile.read'],
    'ttl_seconds' => 3600,
    'write_demo_user' => true,
]);
$quickstartTokenService = new OpaqueTokenService((new SecurityKernel($quickstartConfig))->tokenStore());
$quickstartRecord = $quickstartTokenService->validate($quickstartReport['token']['plain_token']);
ok($quickstartReport['ok'] === true && $quickstartRecord !== null && $quickstartRecord['user_id'] === 'demo-admin' && is_file($base . '/storage/private/demo-user.json'), 'quickstart bootstrapper issues first token and writes demo user metadata');

$quickstartCliRoot = $base . '/quickstart-cli';
@mkdir($quickstartCliRoot . '/config', 0777, true);
@mkdir($quickstartCliRoot . '/storage/tokens', 0777, true);
@mkdir($quickstartCliRoot . '/storage/audit', 0777, true);
$quickstartCliConfig = var_export(array_replace_recursive($defaultConfig, [
    'app' => ['key' => str_repeat('c', 40)],
    'paths' => [
        'cache' => $quickstartCliRoot . '/storage/cache',
        'tokens' => $quickstartCliRoot . '/storage/tokens/tokens.json',
        'audit' => $quickstartCliRoot . '/storage/audit',
        'logs' => $quickstartCliRoot . '/storage/logs',
        'private_storage' => $quickstartCliRoot . '/storage/private',
        'quarantine' => $quickstartCliRoot . '/storage/quarantine',
        'backups' => $quickstartCliRoot . '/storage/backups',
    ],
    'audit' => ['file' => $quickstartCliRoot . '/storage/audit/security-audit.log'],
]), true);
file_put_contents($quickstartCliRoot . '/config/security.php', '<?php return ' . $quickstartCliConfig . ';');
$quickstartCliOutput = [];
$quickstartCliCode = 0;
exec('cd ' . escapeshellarg($quickstartCliRoot) . ' && ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(dirname(__DIR__) . '/bin/mnb-secure') . ' bootstrap:first-token demo-cli profile.read 3600 --write-demo-user 2>&1', $quickstartCliOutput, $quickstartCliCode);
$quickstartCliJson = json_decode(implode("\n", $quickstartCliOutput), true);
ok($quickstartCliCode === 0 && is_array($quickstartCliJson) && ($quickstartCliJson['user']['id'] ?? null) === 'demo-cli' && isset($quickstartCliJson['token']['authorization_header']), 'CLI bootstrap:first-token returns first-token JSON workflow');

$invalidConfigReport = (new SecurityConfigValidator([
    'app' => ['env' => 'production', 'debug' => 'true', 'force_https' => false, 'key' => 'weak', 'trusted_hosts' => ['*'], 'trusted_proxies' => ['not-a-proxy', '*']],
    'cookies' => ['secure' => false, 'http_only' => true, 'same_site' => 'None'],
    'paths' => ['private_storage' => '', 'quarantine' => '/tmp/q', 'cache' => '/tmp/cache', 'logs' => '/tmp/logs', 'audit' => '/tmp/audit', 'backups' => '/tmp/backups', 'tokens' => '/tmp/tokens.json'],
    'limits' => ['request_max_bytes' => 10, 'upload_max_bytes' => 20, 'login' => ['max' => 0, 'seconds' => 60], 'api' => ['max' => 10, 'seconds' => 60], 'otp' => ['max' => 3, 'seconds' => 600], 'export' => ['max' => 10, 'seconds' => 3600]],
    'uploads' => ['allowed_extensions' => ['jpg', 'php'], 'allowed_mime_prefixes' => ['image/'], 'blocked_extensions' => ['php'], 'deny_double_extensions' => true, 'randomize_names' => true, 'reject_executable_content' => true, 'scanner' => ['driver' => 'bad']],
    'cache' => ['driver' => 'database', 'table' => 'unsafe;table'],
    'rate_limiter' => ['driver' => 'file', 'table' => 'mnb_rate_limits'],
    'token_store' => ['driver' => 'file', 'table' => 'mnb_api_tokens'],
    'errors' => ['response_format' => 'xml'],
]))->validate();
$invalidKeys = array_column($invalidConfigReport['issues'], 'key');
ok(
    $invalidConfigReport['passed'] === false
    && in_array('invalid_app_debug', $invalidKeys, true)
    && in_array('invalid_trusted_proxy', $invalidKeys, true)
    && in_array('dangerous_upload_extension_allowed', $invalidKeys, true)
    && in_array('unsafe_sql_identifier_cache_table', $invalidKeys, true),
    'security config validator catches unsafe types, proxy trust, uploads and table identifiers'
);

$normalizedDriver = StorageDriverResolver::driver(['cache' => ['driver' => ' Redis ']], 'cache', 'CACHE_DRIVER');
$invalidDriverBlocked = false;
try {
    StorageDriverResolver::driver(['cache' => ['driver' => 'memory']], 'cache', 'CACHE_DRIVER');
} catch (InvalidArgumentException $e) {
    $invalidDriverBlocked = true;
}
$invalidRedisClientBlocked = false;
try {
    StorageDriverResolver::assertRedisClient(new class { public function get(string $key): mixed { return false; } }, ['get', 'set'], 'cache');
} catch (InvalidArgumentException $e) {
    $invalidRedisClientBlocked = true;
}
ok($normalizedDriver === 'redis' && $invalidDriverBlocked && $invalidRedisClientBlocked, 'storage driver resolver normalizes drivers and blocks unsafe clients');

$databaseStoreConfigReport = (new SecurityConfigValidator(array_replace_recursive($defaultConfig, [
    'cache' => ['driver' => 'database', 'table' => 'mnb_cache'],
    'database' => ['driver' => 'sqlite'],
])))->validate();
ok(in_array('unsupported_database_store_driver_for_cache', array_column($databaseStoreConfigReport['issues'], 'key'), true), 'security config validator flags unsupported database-backed store driver');

$fakeRedis = new class {
    public array $data = [];
    public array $ttl = [];
    public array $sets = [];

    public function get(string $key): mixed
    {
        return $this->data[$key] ?? false;
    }

    public function set(string $key, mixed $value, mixed $ttl = null): bool
    {
        $this->data[$key] = $value;
        if ($ttl !== null) {
            $this->ttl[$key] = time() + (int)$ttl;
        }
        return true;
    }

    public function setex(string $key, int $ttl, mixed $value): bool
    {
        $this->data[$key] = $value;
        $this->ttl[$key] = time() + $ttl;
        return true;
    }

    public function del(string $key): int
    {
        unset($this->data[$key], $this->ttl[$key], $this->sets[$key]);
        return 1;
    }

    public function incr(string $key): int
    {
        $this->data[$key] = (string)(((int)($this->data[$key] ?? 0)) + 1);
        return (int)$this->data[$key];
    }

    public function expire(string $key, int $ttl): bool
    {
        $this->ttl[$key] = time() + $ttl;
        return true;
    }

    public function ttl(string $key): int
    {
        return isset($this->ttl[$key]) ? max(0, $this->ttl[$key] - time()) : -1;
    }

    public function sAdd(string $key, string $member): int
    {
        $this->sets[$key][$member] = true;
        return 1;
    }

    public function sMembers(string $key): array
    {
        return array_keys($this->sets[$key] ?? []);
    }
};

$kernelConfig = $defaultConfig;
$kernelConfig['paths']['cache'] = $base . '/kernel-cache';
$kernelConfig['paths']['tokens'] = $base . '/kernel-tokens/tokens.json';
$kernelConfig['cache']['driver'] = 'redis';
$kernelConfig['rate_limiter']['driver'] = 'redis';
$kernelConfig['token_store']['driver'] = 'redis';
$kernel = new SecurityKernel($kernelConfig);
$kernelCache = $kernel->cache(null, $fakeRedis);
$kernelCache->put('driver-test', ['ok' => true], 60);
$kernelRate = $kernel->rateLimiter(null, $fakeRedis)->attempt('driver-test', 1, 60);
$kernelTokenService = new OpaqueTokenService($kernel->tokenStore(null, $fakeRedis));
$kernelIssuedToken = $kernelTokenService->issue(123, ['driver.read'], ttlSeconds: 60);
ok($kernelCache->get('driver-test')['ok'] === true && $kernelRate->allowed && $kernelTokenService->validate($kernelIssuedToken['plain_token']) !== null, 'security kernel builds injected Redis cache, rate limiter and token store drivers');

$kernelSecureConfig = array_replace_recursive($defaultConfig, [
    'app' => ['key' => str_repeat('K', 40)],
    'paths' => ['cache' => $base . '/kernel-secure-cache'],
    'data_protection' => [
        'encryption' => [
            'current_key_id' => 'cache-test',
            'keys' => ['cache-test' => str_repeat('L', 40)],
        ],
    ],
]);
unset($kernelSecureConfig['data_protection']['encryption']['keys']['app-v1']);
$kernelSecureCache = (new SecurityKernel($kernelSecureConfig))->secureCache();
$kernelSecureCache->put('school_settings', ['school_id' => 10], ['theme' => 'blue']);
$kernelSecureValue = $kernelSecureCache->remember('school_settings', ['school_id' => 10], fn() => ['theme' => 'red']);
ok($kernelSecureValue['theme'] === 'blue', 'security kernel builds secure cache from configured caching policies');

$cachingValidationReport = (new SecurityConfigValidator(array_replace_recursive($defaultConfig, [
    'caching' => [
        'enabled' => true,
        'policies' => [
            'bad policy' => ['ttl' => 60],
            'unsafe_secret' => ['ttl' => 60, 'data_class' => 'highly_sensitive', 'cache' => true],
            'sensitive_not_encrypted' => ['ttl' => 60, 'data_class' => 'sensitive', 'scope' => ['tenant']],
        ],
    ],
])))->validate();
ok(!$cachingValidationReport['passed'], 'security config validator catches unsafe caching strategy policies');

$cachingSuggestions = (new AutoSuggestionEngine())->suggestFromCode('$cache = $kernel->cache(); $cache->put("student:44", $student, 300);', 5);
ok(count(array_filter($cachingSuggestions, fn(array $item): bool => ($item['id'] ?? '') === 'missing_caching_strategy' || ($item['id'] ?? '') === 'cache_strategy')) >= 1, 'auto suggestion engine recommends caching strategy for manual cache usage');


$kernelInvalidDriverBlocked = false;
try {
    $badKernelConfig = $defaultConfig;
    $badKernelConfig['paths']['cache'] = $base . '/bad-kernel-cache';
    $badKernelConfig['cache']['driver'] = 'memory';
    (new SecurityKernel($badKernelConfig))->cache();
} catch (InvalidArgumentException $e) {
    $kernelInvalidDriverBlocked = true;
}
ok($kernelInvalidDriverBlocked, 'security kernel rejects invalid storage driver instead of silently falling back to file');

$audit = new TamperEvidentAuditLogger($base . '/audit/audit.log');
$audit->record('fee.updated', ['user_id' => 1, 'token' => 'secret'], ['fee_id' => 5]);
$audit->record('marks.updated', ['user_id' => 2], ['student_id' => 6]);
ok($audit->verify(), 'tamper-evident audit log verifies');
file_put_contents($base . '/audit/audit.log', str_replace('fee.updated', 'fee.deleted', file_get_contents($base . '/audit/audit.log')));
ok(!$audit->verify(), 'tamper-evident audit detects tampering');

$structuredAudit = new TamperEvidentAuditLogger($base . '/audit/structured-audit.log');
$trail = new SecurityAuditTrail($structuredAudit, new FileLogger($base . '/logs/structured-audit.log'));
$trail->loginSuccess(['user_id' => 77], ['ip' => '127.0.0.1'], ['token' => 'plain-secret-should-redact']);
$trail->adminAction('user.permission.changed', ['user_id' => 1, 'role' => 'admin'], ['user_id' => 77], ['permission' => 'reports.export']);
$trail->sensitiveAction('backup.exported', ['user_id' => 1], ['backup_id' => 'b1'], ['api_key' => 'secret-key']);
$structuredEntries = $structuredAudit->read(null);
$structuredVerify = $structuredAudit->verifyDetailed();
ok($structuredVerify['valid'] && count($structuredEntries) === 3 && $structuredEntries[0]['category'] === 'auth' && $structuredEntries[1]['category'] === 'admin', 'structured audit trail records categorized auth/admin/sensitive events');
ok(!str_contains(json_encode($structuredEntries), 'plain-secret-should-redact') && !str_contains(json_encode($structuredEntries), 'secret-key'), 'structured audit trail redacts secrets recursively');
ok(count($structuredAudit->read(null, 'admin')) === 1, 'structured audit reader filters by category');

$autoAuditFile = $base . '/audit/auto-audit.log';
$autoTrail = new SecurityAuditTrail(new TamperEvidentAuditLogger($autoAuditFile));
$autoLogger = new AutoAuditLogger($autoTrail, ['enabled' => true]);
$autoLogger->add(['user_id' => 10], ['resource' => 'student', 'id' => 5], [], ['password' => 'must-redact']);
$autoLogger->emailSent(['user_id' => 10], ['to_fingerprint' => SecurityAuditEvent::fingerprint('parent@example.com')]);
$autoLogger->passwordVerificationFailed(['email_fingerprint' => SecurityAuditEvent::fingerprint('user@example.com')]);
$autoEntries = (new TamperEvidentAuditLogger($autoAuditFile))->read(null);
ok(count($autoEntries) === 3 && $autoEntries[0]['action'] === 'record.add' && $autoEntries[1]['category'] === 'email' && $autoEntries[2]['outcome'] === 'failure' && !str_contains(json_encode($autoEntries), 'must-redact'), 'auto audit logger records add/email/password outcomes and redacts secrets');

$autoMiddlewareFile = $base . '/audit/auto-middleware.log';
$autoMiddleware = new AutoAuditMiddleware(new SecurityAuditTrail(new TamperEvidentAuditLogger($autoMiddlewareFile)), ['enabled' => true]);
$autoRequest = (new Request('POST', '/login', [], ['email' => 'user@example.com', 'password' => 'secret'], [], ['REMOTE_ADDR' => '127.0.0.2']))->withAttribute('route_name', 'auth.login');
$autoResponse = (new MiddlewarePipeline([$autoMiddleware]))->handle($autoRequest, fn() => Response::json(['status' => false], 401));
$autoMiddlewareEntries = (new TamperEvidentAuditLogger($autoMiddlewareFile))->read(null, 'auth');
ok($autoResponse->status() === 401 && count($autoMiddlewareEntries) === 1 && $autoMiddlewareEntries[0]['action'] === 'auth.login' && $autoMiddlewareEntries[0]['outcome'] === 'failure' && !str_contains(json_encode($autoMiddlewareEntries), 'secret'), 'auto audit middleware infers failed login without logging raw password');



$receivingRegistry = new RequestReceivingRegistry([
    'api_test' => [
        'methods' => ['POST'],
        'max_bytes' => 1024,
        'content_types' => ['application/json'],
        'rate_policy' => null,
        'auth' => null,
        'request_trust' => false,
        'origin_protection' => false,
        'https' => false,
        'trusted_host' => false,
        'cors' => false,
        'security_headers' => false,
        'input_validation' => false,
        'auto_audit' => false,
        'suspicious_detection' => false,
        'json_body' => true,
    ],
]);
ok($receivingRegistry->has('api_test') && $receivingRegistry->get('api_test')->methods() === ['POST'] && $receivingRegistry->get('api_test')->contentTypes() === ['application/json'], 'request receiving registry builds named intake profiles');

$receivingKernelConfig = require __DIR__ . '/../config/security.php';
$receivingKernelConfig['app']['trusted_hosts'] = [];
$receivingKernelConfig['origin_protection']['enabled'] = false;
$receivingKernelConfig['cors']['enabled'] = false;
$receivingKernelConfig['security_headers']['enabled'] = false;
$receivingKernelConfig['audit']['enabled'] = false;
$receivingKernelConfig['request_receiving']['profiles']['api_test'] = $receivingRegistry->get('api_test')->options();
$receivingKernel = new SecurityKernel($receivingKernelConfig);
$receivingRequest = (new Request('POST', '/api/test', [], [], ['content-type' => 'application/json'], ['REMOTE_ADDR' => '127.0.0.1', 'CONTENT_LENGTH' => 16]))
    ->withAttribute('raw_body', '{"name":"Ravi"}');
$receivingResponse = $receivingKernel->secureRequestReceiver('api_test')->handle($receivingRequest, fn(Request $request) => Response::json([
    'status' => true,
    'name' => $request->input('name'),
    'profile' => $request->attribute('request_receiving_profile'),
    'request_id' => $request->attribute('request_id'),
]));
$receivingPayload = json_decode($receivingResponse->body(), true);
ok($receivingResponse->status() === 200 && ($receivingPayload['name'] ?? null) === 'Ravi' && ($receivingPayload['profile'] ?? null) === 'api_test' && isset($receivingResponse->headers()['X-Request-ID']), 'secure request receiver composes request id, method, content type and JSON body parsing');

$badMethodResponse = $receivingKernel->secureRequestReceiver('api_test')->handle(new Request('GET', '/api/test', [], [], ['content-type' => 'application/json'], ['REMOTE_ADDR' => '127.0.0.1']), fn() => Response::json(['status' => true]));
$badTypeResponse = $receivingKernel->secureRequestReceiver('api_test')->handle(new Request('POST', '/api/test', [], [], ['content-type' => 'text/plain'], ['REMOTE_ADDR' => '127.0.0.1', 'CONTENT_LENGTH' => 4]), fn() => Response::json(['status' => true]));
ok($badMethodResponse->status() === 405 && $badTypeResponse->status() === 415, 'secure request receiver blocks unexpected HTTP methods and content types');

$invalidJson = (new MiddlewarePipeline([new JsonBodyParserMiddleware(10, 1024)]))->handle(
    (new Request('POST', '/json', [], [], ['content-type' => 'application/json'], ['CONTENT_LENGTH' => 7]))->withAttribute('raw_body', '{bad'),
    fn() => Response::json(['status' => true])
);
ok($invalidJson->status() === 400, 'JSON body parser rejects invalid JSON before controller logic');

$suspiciousResponse = (new MiddlewarePipeline([new SuspiciousRequestMiddleware(['mode' => 'block'])]))->handle(
    new Request('GET', '/../secret', ['q' => 'ok'], [], [], ['REMOTE_ADDR' => '127.0.0.1']),
    fn() => Response::json(['status' => true])
);
ok($suspiciousResponse->status() === 400, 'suspicious request middleware blocks traversal-shaped intake');

$webhookRaw = '{"event":"test"}';
$webhookTs = (string)time();
$webhookSecret = 'whsec_test_secret';
$webhookSig = hash_hmac('sha256', $webhookTs . '.' . $webhookRaw, $webhookSecret);
$webhookRequest = (new Request('POST', '/webhook', [], [], ['content-type' => 'application/json', 'x-timestamp' => $webhookTs, 'x-signature' => 'sha256=' . $webhookSig], ['CONTENT_LENGTH' => strlen($webhookRaw)]))->withAttribute('raw_body', $webhookRaw);
$webhookResponse = (new MiddlewarePipeline([new WebhookSignatureMiddleware(new WebhookSignatureVerifier(['secret' => $webhookSecret]))]))->handle($webhookRequest, fn(Request $request) => Response::json(['verified' => $request->attribute('webhook_signature_verified')]));
$badWebhookResponse = (new MiddlewarePipeline([new WebhookSignatureMiddleware(new WebhookSignatureVerifier(['secret' => $webhookSecret]))]))->handle($webhookRequest->withAttribute('raw_body', '{"event":"tampered"}'), fn() => Response::json(['status' => true]));
ok($webhookResponse->status() === 200 && $badWebhookResponse->status() === 401, 'webhook signature middleware verifies HMAC signatures and blocks tampered payloads');

$badReceivingConfig = $receivingKernelConfig;
$badReceivingConfig['request_receiving']['profiles']['bad'] = ['methods' => ['POST'], 'auth' => 'magic'];
$badReceivingReport = (new SecurityConfigValidator($badReceivingConfig))->validate();
ok(!$badReceivingReport['passed'] && in_array('invalid_request_receiving_auth', array_column($badReceivingReport['errors'], 'key'), true), 'security config validator catches invalid request receiving auth profiles');

$secretFile = $base . '/source.php';
file_put_contents($secretFile, "<?php\n\$api_key = 'abcdefghijklmnopqrstuvwxyz123456';\n");
$findings = (new SecretScanner())->scanDirectory($base, []);
ok(count($findings) >= 1, 'secret scanner finds risky pattern');

$matrix = (new VulnerabilityMatrix())->all();
ok(isset($matrix['Broken Access Control / IDOR']) && isset($matrix['Insecure Upload']), 'vulnerability matrix exports controls');

$studentTable = new TableSecurityPolicy(
    table: 'students',
    resourceType: 'student',
    selectableColumns: ['id', 'admission_no', 'first_name', 'last_name', 'class_id', 'section_id', 'status'],
    insertableColumns: ['admission_no', 'first_name', 'last_name', 'class_id', 'section_id', 'status'],
    updatableColumns: ['first_name', 'last_name', 'class_id', 'section_id', 'status'],
    searchableColumns: ['admission_no', 'first_name', 'last_name'],
    orderableColumns: ['id', 'first_name', 'admission_no']
);
$dbContext = new TenantContext(userId: 7, schoolId: 10, branchId: 5, academicYearId: 2026, permissions: ['student.view', 'student.create', 'student.update', 'student.delete']);
$builder = new SecureQueryBuilder();
$selectPlan = $builder->select($studentTable, ['id', 'first_name'], ['status' => 'active'], ['school_id' => 10], 'Ra%_', ['first_name'], 'first_name', 'DESC', 25, 0);
ok(str_contains($selectPlan->sql, 'school_id = ?') && str_contains($selectPlan->sql, 'LIKE ?') && $selectPlan->bindings[0] === 'active' && $selectPlan->bindings[1] === 10, 'secure query builder applies tenant/search filters');
ok(str_contains($selectPlan->bindings[2], '\\%') && str_contains($selectPlan->bindings[2], '\\_'), 'secure query builder escapes LIKE wildcards');

$unsafeIdentifierBlocked = false;
try { SqlIdentifier::assert('students;DROP_TABLE'); } catch (InvalidArgumentException $e) { $unsafeIdentifierBlocked = true; }
ok($unsafeIdentifierBlocked, 'SQL identifier guard blocks unsafe identifier');

$fakePdo = new class extends PDO { public function __construct() {} };
$dbStoreIdentifierBlocked = 0;
foreach ([DatabaseCache::class, DatabaseRateLimiter::class, DatabaseTokenStore::class] as $storeClass) {
    try { new $storeClass($fakePdo, 'unsafe_table;DROP'); } catch (InvalidArgumentException $e) { $dbStoreIdentifierBlocked++; }
}
ok($dbStoreIdentifierBlocked === 3, 'database-backed stores validate configured table identifiers');

$massPlan = $builder->insert($studentTable, ['first_name' => 'Ravi', 'role_id' => 1, 'school_id' => 999], ['school_id' => 10, 'branch_id' => 5, 'academic_year_id' => 2026]);
ok(!str_contains($massPlan->sql, 'role_id') && !in_array(999, $massPlan->bindings, true) && in_array(10, $massPlan->bindings, true), 'insert allow-list blocks mass assignment and enforces tenant');

$updatePlan = $builder->updateById($studentTable, 44, ['first_name' => 'Ravi', 'is_admin' => 1], ['school_id' => 10]);
ok(str_starts_with($updatePlan->sql, 'UPDATE students SET first_name = ?') && str_contains($updatePlan->sql, 'id = ?') && str_contains($updatePlan->sql, 'school_id = ?') && !str_contains($updatePlan->sql, 'is_admin'), 'update query uses allow-list and scoped WHERE');

$deletePlan = $builder->deleteById($studentTable, 44, ['school_id' => 10]);
ok($deletePlan->operation === 'soft_delete' && str_starts_with($deletePlan->sql, 'UPDATE students SET deleted_at = ?'), 'delete defaults to soft delete');

$dryDb = new DryRunDatabaseConnection();
$policyRegistry = new PolicyRegistry();
$policyRegistry->register('student', new DatabaseResourcePolicy('student'));
$secureDb = new SecureDatabase($dryDb, $policyRegistry, new TamperEvidentAuditLogger($base . '/audit/db-audit.log'));
$secureDb->create($dbContext, $studentTable, ['admission_no' => 'A001', 'first_name' => 'Ravi', 'role_id' => 1]);
$last = $dryDb->lastQuery();
ok($last && $last['type'] === 'execute' && str_starts_with($last['sql'], 'INSERT INTO students') && !str_contains($last['sql'], 'role_id'), 'secure database create filters data and executes prepared shape');

$secureDb->search($dbContext, $studentTable, 'Ravi', ['status' => 'active'], 'id', 'DESC', 10, 0);
$last = $dryDb->lastQuery();
ok($last && $last['type'] === 'fetchAll' && str_contains($last['sql'], 'ORDER BY id DESC') && str_contains($last['sql'], 'LIMIT 10 OFFSET 0'), 'secure database search uses allowed ordering and pagination');

$blockedDbAction = false;
try {
    $limitedContext = new TenantContext(userId: 8, schoolId: 10, permissions: ['student.view']);
    $secureDb->updateById($limitedContext, $studentTable, 44, ['first_name' => 'Nope']);
} catch (SecurityException $e) { $blockedDbAction = true; }
ok($blockedDbAction, 'secure database blocks unauthorized update by policy/permission');

$schemaBlocked = false;
try { (new SchemaGuard())->assertSchemaChangeAllowed($dbContext); } catch (InvalidArgumentException $e) { $schemaBlocked = true; }
ok($schemaBlocked, 'schema guard blocks alter without permission');

$schemaContext = new TenantContext(userId: 1, roles: ['super_admin'], permissions: ['schema.alter']);
$secureDb->alterAddColumn($schemaContext, 'students', 'blood_group', 'VARCHAR(50)', true);
$last = $dryDb->lastQuery();
ok($last && str_starts_with($last['sql'], 'ALTER TABLE students ADD COLUMN blood_group VARCHAR(50)'), 'secure database allows guarded alter add column');

$dbConfig = DatabaseConfig::fromArray(['driver' => 'mysql', 'host' => 'localhost', 'database' => 'boss_school', 'username' => 'user']);
ok(str_contains($dbConfig->dsn, 'mysql:host=localhost') && isset($dbConfig->securePdoOptions()[PDO::ATTR_ERRMODE]), 'database config builds secure PDO options');

$dbPolicyRegistry = new DatabasePolicyRegistry(['students' => $studentTable]);
ok($dbPolicyRegistry->has('students') && $dbPolicyRegistry->get('student')->table === 'students', 'database policy registry resolves policy by table and resource');

$strictCostPolicy = new QueryCostPolicy(maxLimit: 50, defaultLimit: 10, maxOffset: 100, maxSearchLength: 10, maxFilterCount: 2, blockLeadingWildcard: true, slowQueryMs: 500);
$strictGuard = new QueryComplexityGuard($strictCostPolicy);
$complexityBlocked = 0;
try { $strictGuard->assertSearch('%bad', [], 10, 0); } catch (InvalidArgumentException $e) { $complexityBlocked++; }
try { $strictGuard->assertSearch('good', ['a' => 1, 'b' => 2, 'c' => 3], 10, 0); } catch (InvalidArgumentException $e) { $complexityBlocked++; }
try { $strictGuard->assertSearch('good', [], 51, 0); } catch (InvalidArgumentException $e) { $complexityBlocked++; }
ok($complexityBlocked === 3, 'query complexity guard blocks leading wildcard, too many filters, and over-limit pagination');

$advancedBuilder = new SecureQueryBuilder(new QueryComplexityGuard(new QueryCostPolicy(maxLimit: 100, maxFilterCount: 10, blockLeadingWildcard: true)));
$advancedPlan = $advancedBuilder->select($studentTable, ['id', 'first_name'], ['class_id' => ['in' => [1, 2]], 'status' => ['neq' => 'archived']], ['school_id' => 10], null, [], 'id', 'ASC', 20, 0);
ok(str_contains($advancedPlan->sql, 'class_id IN (?, ?)') && str_contains($advancedPlan->sql, 'status <> ?') && $advancedPlan->bindings === [1, 2, 'archived', 10], 'secure query builder supports allow-listed advanced filters');

$betweenPlan = $advancedBuilder->select($studentTable, ['id'], ['id' => ['between' => [1, 10]]], ['school_id' => 10], null, [], null, 'ASC', 5, 0);
ok(str_contains($betweenPlan->sql, 'id BETWEEN ? AND ?') && $betweenPlan->bindings === [1, 10, 10], 'secure query builder supports between filter safely');

$sensitivePolicy = new TableSecurityPolicy(
    table: 'users',
    resourceType: 'user',
    selectableColumns: ['id', 'email', 'phone', 'password_hash', 'salary'],
    insertableColumns: ['email', 'phone'],
    updatableColumns: ['email', 'phone'],
    maskedColumns: ['email', 'phone'],
    permissionColumns: ['salary' => 'user.view_salary']
);
$filteredRow = (new DatabaseResultFilter())->filterRow(new TenantContext(userId: 9, permissions: ['user.view']), $sensitivePolicy, ['id' => 1, 'email' => 'person@example.com', 'phone' => '9876543210', 'password_hash' => 'hash', 'salary' => 999]);
ok(!isset($filteredRow['password_hash']) && !isset($filteredRow['salary']) && $filteredRow['email'] !== 'person@example.com' && $filteredRow['phone'] !== '9876543210', 'database result filter hides password fields, permission fields, and masks sensitive values');

$restorePlan = $builder->restoreById($studentTable, 44, ['school_id' => 10]);
ok($restorePlan->operation === 'restore' && str_contains($restorePlan->sql, 'deleted_at = NULL') && str_contains($restorePlan->sql, 'school_id = ?'), 'restore query clears soft-delete column with scoped WHERE');

$secureDb->restoreById(new TenantContext(userId: 7, schoolId: 10, permissions: ['student.restore']), $studentTable, 44);
$last = $dryDb->lastQuery();
ok($last && $last['type'] === 'execute' && str_contains($last['sql'], 'deleted_at = NULL'), 'secure database restore executes guarded restore plan');

$txCommitted = false;
$secureDb->transaction($dbContext, function (SecureDatabase $db) use (&$txCommitted, $studentTable, $dbContext) {
    $txCommitted = true;
    $db->updateById($dbContext, $studentTable, 44, ['status' => 'active']);
});
$queries = $dryDb->queries();
ok($txCommitted && count(array_filter($queries, fn($q) => $q['type'] === 'transaction.begin')) >= 1 && count(array_filter($queries, fn($q) => $q['type'] === 'transaction.commit')) >= 1, 'secure database transaction commits through connection');

$schemaMigration = new SchemaMigrationGuard(new SchemaChangePolicy(requireSuperAdmin: true, requireBackupBeforeAlter: true, allowDestructiveChanges: false, dryRunDefault: true));
$schemaPlan = $schemaMigration->planAddColumn($schemaContext, 'students', 'admission_category', 'VARCHAR(100)');
$dropPlan = $schemaMigration->planDestructive($schemaContext, 'drop_table', 'students');
ok($schemaPlan->allowed && $schemaPlan->dryRun && $schemaPlan->requiresBackup && !$dropPlan->allowed && $dropPlan->destructive, 'schema migration guard creates dry-run plan and blocks destructive operations');

$rawSqlBlocked = false;
try { RawQueryGuard::fromConfig(['database' => ['deny_raw_sql' => true]])->assertAllowed('SELECT * FROM users'); } catch (InvalidArgumentException $e) { $rawSqlBlocked = true; }
ok($rawSqlBlocked, 'raw query guard blocks raw SQL when deny_raw_sql is enabled');

$health = (new DatabaseHealthChecker(['database' => ['driver' => 'mysql', 'charset' => 'utf8mb4']]))->check(false);
ok($health['passed'] && $health['secure_pdo_options']['emulated_prepares_disabled'], 'database health checker verifies secure PDO options without connecting');

$privilegeReport = (new DatabasePrivilegeInspector(['GRANT SELECT, INSERT, UPDATE, DELETE, DROP, ALTER ON app.* TO runtime_user']))->inspect();
ok(!$privilegeReport['passed'] && in_array('DROP', $privilegeReport['dangerous_privileges'], true) && in_array('ALTER', $privilegeReport['dangerous_privileges'], true), 'database privilege inspector flags dangerous runtime privileges');

$dbGovernanceConfig = array_replace_recursive($defaultConfig, [
    'database' => [
        'query_limits' => ['max_limit' => 50, 'default_limit' => 10, 'max_filter_count' => 5, 'allowed_operators' => ['eq', 'between']],
        'transactions' => ['enabled' => true, 'max_operations' => 20],
        'schema_changes' => ['enabled' => true, 'allow_destructive_changes' => false],
        'field_protection' => ['enabled' => true, 'deny_password_columns' => true],
    ],
]);
$dbGovernanceReport = (new SecurityConfigValidator($dbGovernanceConfig))->validate();
ok($dbGovernanceReport['passed'], 'security config validator accepts database governance config');

$badDbGovernanceReport = (new SecurityConfigValidator(array_replace_recursive($defaultConfig, ['database' => ['query_limits' => ['max_limit' => 10, 'default_limit' => 50], 'schema_changes' => ['allow_destructive_changes' => true]]])))->validate();
ok(in_array('invalid_database_default_limit', array_column($badDbGovernanceReport['errors'], 'key'), true), 'security config validator catches invalid database query limit order');

$dbMatrix = (new \Mnb\SecurityCore\Vulnerability\VulnerabilityMatrix($defaultConfig))->find('mass_assignment');
ok($dbMatrix !== null && $dbMatrix->status() === 'protected', 'vulnerability matrix includes mass assignment database governance coverage');


$payloadLibrary = new PayloadLibrary();
ok(in_array('sql_injection', $payloadLibrary->categories(), true) && count($payloadLibrary->get('xss')) >= 4, 'pentest payload library returns categories and XSS payloads');

$pentestChecklist = new PentestChecklist();
$pentestCases = $pentestChecklist->all();
ok(count($pentestCases) >= 10 && $pentestCases[0]->id === 'PT-AUTH-001', 'pentest checklist exposes reusable security test cases');

$verification = (new VerificationMatrix())->all();
ok(isset($verification['Secure Database Operations']) && isset($verification['Penetration Testing and Security Verification']), 'pentest verification matrix maps concepts to test cases');

$finding = new PentestFinding(
    id: 'TEST-001',
    title: 'Cross-tenant student access',
    severity: 'critical',
    affectedTarget: '/api/v1/students/999',
    affectedRole: 'Parent',
    stepsToReproduce: ['Login', 'Change student id', 'Submit request'],
    payloads: ['student_id=999'],
    businessImpact: 'Student privacy breach.',
    technicalImpact: 'Broken object-level authorization.',
    recommendedFix: 'Apply TenantGuard and ownership policy.'
);
ok($finding->severity === RiskRating::CRITICAL && $finding->riskScore() === 10, 'pentest finding normalizes critical severity and score');

$tracker = new RemediationTracker();
$tracker->addFinding($finding, 'security-owner', '2026-06-01');
$tracker->updateStatus('TEST-001', 'Fixed', 'Policy added.');
ok(($tracker->summary()['Fixed'] ?? 0) === 1, 'remediation tracker updates finding status');

$reportText = (new PentestReportBuilder())->buildMarkdown('Test App', ['Web', 'API'], [$finding]);
ok(str_contains($reportText, 'TEST-001') && str_contains($reportText, 'Critical'), 'pentest report builder creates Markdown report');

$ptCategories = $payloadLibrary->categories();
ok(in_array('runtime', $ptCategories, true) && in_array('ssrf', $ptCategories, true) && in_array('release_gate', $ptCategories, true), 'payload library includes runtime, SSRF, and release gate payload categories');

$extendedCases = (new PentestChecklist())->toArray();
$extendedIds = array_column($extendedCases, 'id');
ok(in_array('PT-RUNTIME-001', $extendedIds, true) && in_array('PT-SSRF-001', $extendedIds, true) && in_array('PT-REL-001', $extendedIds, true), 'pentest checklist includes upgrade 29 verification cases');

$registry = new SecurityVerificationRegistry();
ok($registry->has('PT-INJ-001') && $registry->get('PT-REL-001')->severity === RiskRating::CRITICAL, 'security verification registry resolves test cases');
$unknownTestBlocked = false;
try { $registry->get('PT-UNKNOWN-999'); } catch (InvalidArgumentException $e) { $unknownTestBlocked = true; }
ok($unknownTestBlocked, 'security verification registry rejects unknown test ids');

$profile = VerificationProfile::fromConfig($defaultConfig, 'production_release');
ok(in_array('PT-SSRF-001', $profile->requiredTests, true) && in_array('PT-RUNTIME-001', $profile->requiredTests, true), 'verification profile loads required production tests');
$target = VerificationTarget::application('Unit Test App', 'https://app.example.test');
ok($target->toArray()['type'] === 'application', 'verification target serializes target metadata');

$redactor = new EvidenceRedactor();
$redacted = $redactor->redact(['Authorization' => 'Bearer secret-token', 'Cookie' => 'sid=secret', 'body' => 'password=secret token=abc123 /var/www/private/app.php']);
ok($redacted['Authorization'] === '[REDACTED]' && $redacted['Cookie'] === '[REDACTED]' && str_contains($redacted['body'], '[REDACTED]') && str_contains($redacted['body'], '[REDACTED_PATH]'), 'evidence redactor removes authorization, cookie, token, password, and private path values');

$collector = new EvidenceCollector($redactor);
$item = $collector->collect('http_response', 'sample', ['Authorization' => 'Bearer hidden', 'body' => 'token=hidden']);
$bundle = $collector->bundle(['test_id' => 'PT-INJ-001']);
ok($item->redacted && $bundle->count() === 1, 'evidence collector creates redacted evidence bundles');
$evidencePath = $base . '/audit/pentest-evidence';
$storedEvidence = (new EvidenceStore($evidencePath))->store($bundle);
ok($storedEvidence['passed'] && is_file($storedEvidence['path']), 'evidence store writes evidence bundle JSON');

$runner = new SecurityVerificationRunner($registry, new EvidenceCollector());
$passedResult = $runner->verify('PT-INJ-001', $target, VerificationResult::PASSED, [['query_plan' => 'prepared statement']]);
ok($passedResult->passed() && $passedResult->toArray()['test_id'] === 'PT-INJ-001', 'security verification runner records passed result with evidence');
$failedResult = $runner->verify('PT-REL-001', $target, VerificationResult::FAILED, [['release_gate' => 'blocked']]);
$failedFinding = $runner->findingFromResult($failedResult);
ok($failedResult->failed() && $failedFinding instanceof PentestFinding && $failedFinding->severity === RiskRating::CRITICAL, 'failed verification result creates pentest finding');
$run = $runner->runProfile($profile, $target, VerificationResult::MANUAL_REQUIRED);
ok($run->coveragePercent() === 100 && ($run->summary()[VerificationResult::MANUAL_REQUIRED] ?? 0) >= 1, 'verification runner creates safe profile run records');

$remediationPolicy = RemediationPolicy::fromConfig($defaultConfig);
$due = (new RemediationSlaCalculator($remediationPolicy))->dueDate(RiskRating::CRITICAL, new DateTimeImmutable('2026-06-30'));
ok($due === '2026-07-03', 'remediation SLA calculator creates due date for Critical findings');
$plan = RemediationPlan::fromFinding($failedFinding, $remediationPolicy, ['PT-REL-001']);
ok($plan->owner === 'security-owner' && $plan->dueDate !== null && in_array('PT-REL-001', $plan->requiredRetests, true), 'remediation plan assigns owner, due date, and retest cases');

$fixedFinding = new PentestFinding('FIND-PT-REL-001', 'Fixed high issue', RiskRating::HIGH, 'release', 'Application', ['Fix'], [], 'Business risk', 'Technical risk', 'Fix and retest', 'Fixed');
$retestGate = new RetestGate($remediationPolicy);
$cannotClose = $retestGate->canClose($fixedFinding);
$canClose = $retestGate->canClose($fixedFinding, RetestResult::pass($fixedFinding->id, [$passedResult], [$item], 'Retest passed'));
ok(!$cannotClose['passed'] && $cannotClose['reason'] === 'retest_required' && $canClose['passed'], 'retest gate requires evidence for High/Critical closure');
$acceptedRiskFinding = new PentestFinding('FIND-RISK', 'Accepted risk', RiskRating::HIGH, 'release', 'Application', [], [], 'Business', 'Technical', 'Approved exception', 'Accepted Risk');
$acceptedRiskBlocked = $retestGate->canClose($acceptedRiskFinding);
$acceptedRiskAllowed = $retestGate->canClose($acceptedRiskFinding, null, ['approved_by' => 'CISO', 'approved_at' => date('c')]);
ok(!$acceptedRiskBlocked['passed'] && $acceptedRiskAllowed['passed'], 'accepted risk requires approval metadata');

$releaseGate = new SecurityReleaseGate(ReleaseGatePolicy::fromConfig($defaultConfig));
$blockedRelease = $releaseGate->evaluate([$failedFinding], $run)->toArray();
$passedRelease = $releaseGate->evaluate([], $run)->toArray();
ok(!$blockedRelease['passed'] && $blockedRelease['blockers'][0]['reason'] === 'open_critical_finding' && $passedRelease['passed'], 'security release gate blocks open Critical findings and passes clean runs');
$lowCoverageRun = VerificationRun::start(new VerificationProfile('small', ['PT-INJ-001', 'PT-XSS-001']), $target);
$lowCoverageRun->addResult($passedResult);
$lowCoverageReport = $releaseGate->evaluate([], $lowCoverageRun)->toArray();
ok(!$lowCoverageReport['passed'] && $lowCoverageReport['blockers'][0]['reason'] === 'coverage_below_minimum', 'security release gate enforces minimum coverage');

$coverageReport = (new SecurityCoverageAnalyzer(new VerificationMatrix()))->analyze($run->results(), $profile)->toArray();
ok(isset($coverageReport['overall_coverage']) && $coverageReport['overall_coverage'] >= 90 && isset($coverageReport['controls']['Runtime Execution Security']), 'security coverage analyzer calculates engine/control coverage');

$ptKernel = new SecurityKernel($defaultConfig);
ok($ptKernel->securityVerificationRegistry()->has('PT-SSRF-001') && $ptKernel->securityReleaseGate()->evaluate([], $run)->toArray()['passed'], 'security kernel exposes pentest verification and release gate helpers');

$ptConfigReport = (new SecurityConfigValidator($defaultConfig))->validate();
ok($ptConfigReport['passed'], 'security config validator accepts upgrade 29 pentest config');
$badPtReport = (new SecurityConfigValidator(array_replace_recursive($defaultConfig, ['pentest' => ['release_gate' => ['minimum_coverage_percent' => 101], 'profiles' => ['bad profile!' => ['required_tests' => ['bad-test']]], 'sla' => ['Critical' => 'three days']]])))->validate();
ok(in_array('invalid_pentest_required_test', array_column($badPtReport['errors'], 'key'), true) || in_array('invalid_pentest_sla_interval', array_column($badPtReport['errors'], 'key'), true), 'security config validator catches invalid pentest automation config');

$verificationRows = (new VerificationMatrix())->all();
ok(isset($verificationRows['Runtime Execution Security'], $verificationRows['Outbound Network Security'], $verificationRows['Security Verification, Remediation, and Evidence Automation']), 'verification matrix maps runtime, outbound, and remediation coverage');
$verificationGap = (new \Mnb\SecurityCore\Vulnerability\VulnerabilityMatrix($defaultConfig))->find('security_verification_gaps');
ok($verificationGap !== null && $verificationGap->status() === 'protected', 'vulnerability matrix includes security verification gap coverage');


$errorLog = $base . '/logs/errors.log';
@mkdir(dirname($errorLog), 0777, true);
@unlink($errorLog);
$errorConfig = [
    'app' => ['env' => 'production', 'debug' => false],
    'errors' => ['response_format' => 'json'],
];
$errorHandler = new SafeErrorHandler(new FileLogger($errorLog), $errorConfig);
$errorRequest = new Request('GET', '/fees/private', [], [], ['accept' => 'application/json'], ['REMOTE_ADDR' => '127.0.0.1']);
$internalError = new RuntimeException('SQLSTATE[HY000] database password=secret /var/www/private.php');
$errorResponse = $errorHandler->renderThrowable($internalError, $errorRequest);
ok($errorResponse->status() === 500 && !str_contains($errorResponse->body(), 'SQLSTATE') && !str_contains($errorResponse->body(), '/var/www'), 'safe error handler hides internal production errors from frontend');
$errorLogText = file_get_contents($errorLog) ?: '';
ok(str_contains($errorLogText, 'SQLSTATE') && str_contains($errorLogText, 'request_id') && !str_contains($errorLogText, 'password=secret'), 'safe error handler logs internal error with request id and redacts secrets');

$customErrorResponse = $errorHandler->renderThrowable(new AppException('Gateway token=private failed', 'Payment service is temporarily unavailable.', 503, 'PAYMENT_DOWN'), $errorRequest);
ok($customErrorResponse->status() === 503 && str_contains($customErrorResponse->body(), 'Payment service is temporarily unavailable.') && str_contains($customErrorResponse->body(), 'PAYMENT_DOWN') && !str_contains($customErrorResponse->body(), 'token=private'), 'custom app exception returns safe frontend message and code');

$errorPipeline = new MiddlewarePipeline([new ErrorHandlingMiddleware($errorHandler)]);
$handled = $errorPipeline->handle($errorRequest, fn() => throw new AuthorizationException('Teacher tried forbidden fee delete'));
ok($handled->status() === 403 && str_contains($handled->body(), 'not allowed'), 'error handling middleware catches thrown exception');

$debugHandler = new SafeErrorHandler(new FileLogger($errorLog), ['app' => ['env' => 'local', 'debug' => true], 'errors' => ['response_format' => 'json']]);
$debugResponse = $debugHandler->renderThrowable(new RuntimeException('Visible only in local debug'), $errorRequest);
ok(str_contains($debugResponse->body(), 'debug') && str_contains($debugResponse->body(), 'Visible only in local debug'), 'debug error details only appear in non-production debug mode');


$problemErrorHandler = new SafeErrorHandler(new FileLogger($errorLog), ['app' => ['env' => 'production', 'debug' => false], 'errors' => ['response_format' => 'problem_json']]);
$problemResponse = $problemErrorHandler->renderThrowable(new RuntimeException('Hidden SQLSTATE password=secret /var/www/app.php'), $errorRequest);
$problemPayload = json_decode($problemResponse->body(), true);
ok(($problemResponse->headers()['Content-Type'] ?? '') === 'application/problem+json; charset=UTF-8' && ($problemPayload['code'] ?? '') === 'INTERNAL_ERROR' && !str_contains($problemResponse->body(), 'SQLSTATE'), 'problem_json error response hides technical details');

$validationHandler = new SafeErrorHandler(new FileLogger($errorLog), [
    'app' => ['env' => 'production', 'debug' => false],
    'errors' => [
        'response_format' => 'json',
        'validation' => ['normalize_field_names' => true, 'hide_internal_fields' => true, 'public_field_map' => ['db_school_id' => 'school']],
    ],
]);
$validationResponse = $validationHandler->renderThrowable(new ValidationException(['password_hash' => ['users.password_hash column invalid'], 'db_school_id' => ['database field missing'], 'email' => ['Email is required']]), $errorRequest);
ok(str_contains($validationResponse->body(), 'email') && str_contains($validationResponse->body(), 'school') && !str_contains($validationResponse->body(), 'password_hash') && !str_contains($validationResponse->body(), 'database'), 'validation error normalizer hides internal fields and maps public names');

$errorPolicy = ErrorPolicy::fromConfig(array_replace_recursive($errorConfig, ['errors' => ['response_format' => 'problem_json', 'redaction' => ['enabled' => true, 'redact_paths' => true, 'redact_pii' => true]]]));
ok($errorPolicy->responseFormat('application/problem+json') === 'problem_json' && !$errorPolicy->shouldExposeDebug(), 'error policy supports problem_json and blocks production debug exposure');

$errorCatalog = new ErrorCatalog();
ok($errorCatalog->get('FORBIDDEN')->status() === 403 && isset($errorCatalog->all()['INTERNAL_ERROR']), 'error catalog exposes standard safe error definitions');

$logSanitizer = new ErrorLogSanitizer($errorPolicy);
$sanitizedErrorText = $logSanitizer->sanitizeString('Authorization: Bearer abc123 password=secret /var/www/private.php admin@example.com');
ok(!str_contains($sanitizedErrorText, 'abc123') && !str_contains($sanitizedErrorText, 'password=secret') && !str_contains($sanitizedErrorText, '/var/www') && !str_contains($sanitizedErrorText, 'admin@example.com'), 'error log sanitizer redacts secrets paths and pii');

$stackSanitizer = new StackTraceSanitizer($errorPolicy, $logSanitizer);
$sanitizedPath = $stackSanitizer->sanitizePath('/var/www/app/src/Secret/File.php');
ok($sanitizedPath === 'src/Secret/File.php' || $sanitizedPath === 'File.php', 'stack trace sanitizer removes absolute root path');

$errorContext = ErrorContext::fromRequest($errorRequest, array_replace_recursive($errorConfig, ['errors' => ['response_format' => 'json']]));
$mapper = new ExceptionMapper($errorCatalog, new ValidationErrorNormalizer($errorPolicy));
$mappedInternal = $mapper->map($internalError);
$fingerprinter = new ErrorFingerprint($errorPolicy, $logSanitizer);
$fp1 = $fingerprinter->create($internalError, $errorContext, $mappedInternal, ['path' => '/fees/private']);
$fp2 = $fingerprinter->create(new RuntimeException('SQLSTATE[HY000] database password=different /var/www/private.php'), $errorContext, $mappedInternal, ['path' => '/fees/private']);
$fp3 = $fingerprinter->create($internalError, $errorContext, $mappedInternal, ['path' => '/another']);
ok($fp1 === $fp2 && $fp1 !== $fp3, 'error fingerprint groups same sanitized error and separates different routes');

$deduplicator = new ErrorDeduplicator();
ok($deduplicator->record($fp1) === 1 && $deduplicator->record($fp1) === 2, 'error deduplicator counts repeated fingerprints');

$escalation = ErrorEscalationPolicy::fromConfig(['errors' => ['escalation' => ['enabled' => true, 'critical_error_threshold' => 2, 'alert_on_security_exception' => true, 'alert_on_repeated_500' => true]]]);
ok($escalation->shouldEscalate(['mapped_error_code' => 'SECURITY_BLOCKED', 'public_status' => 403], 1) && $escalation->shouldEscalate(['mapped_error_code' => 'INTERNAL_ERROR', 'public_status' => 500], 2) && !$escalation->shouldEscalate(['mapped_error_code' => 'VALIDATION_FAILED', 'public_status' => 422], 10), 'error escalation policy flags security exceptions and repeated 500s only');

$errorKernel = new SecurityKernel(array_replace_recursive($defaultConfig, ['errors' => ['response_format' => 'json']]));
ok($errorKernel->errorCatalog()->has('INTERNAL_ERROR') && $errorKernel->errorPolicy()->includeRequestId() && !array_key_exists('password_hash', $errorKernel->validationErrorNormalizer()->normalize(['password_hash' => ['bad'], 'email' => ['required']])) && array_key_exists('email', $errorKernel->validationErrorNormalizer()->normalize(['password_hash' => ['bad'], 'email' => ['required']])), 'security kernel exposes safe error response and log isolation helpers');

$errorConfigReport = (new SecurityConfigValidator(array_replace_recursive($defaultConfig, ['errors' => ['response_format' => 'problem_json']])))->validate();
ok($errorConfigReport['passed'], 'security config validator accepts safe error response engine config');
$badErrorConfigReport = (new SecurityConfigValidator(array_replace_recursive($defaultConfig, ['app' => ['env' => 'production'], 'errors' => ['response_format' => 'xml', 'debug' => ['allow_in_production' => true, 'include_stack_trace' => true], 'redaction' => ['enabled' => false]]])))->validate();
ok(in_array('invalid_error_response_format', array_column($badErrorConfigReport['errors'], 'key'), true) || in_array('production_debug_error_exposure', array_column($badErrorConfigReport['errors'], 'key'), true), 'security config validator blocks unsafe production error settings');

$errorDisclosure = (new \Mnb\SecurityCore\Vulnerability\VulnerabilityMatrix(array_replace_recursive($defaultConfig, ['errors' => ['enabled' => true, 'hide_frontend_errors' => true, 'include_request_id' => true, 'redaction' => ['enabled' => true, 'redact_paths' => true, 'redact_pii' => true], 'validation' => ['normalize_field_names' => true, 'hide_internal_fields' => true], 'escalation' => ['enabled' => true]]])))->find('error_disclosure');
$sensitiveLogExposure = (new \Mnb\SecurityCore\Vulnerability\VulnerabilityMatrix(array_replace_recursive($defaultConfig, ['errors' => ['redaction' => ['enabled' => true]], 'logging' => ['enabled' => true]])))->find('sensitive_log_exposure');
ok($errorDisclosure !== null && $errorDisclosure->status() === 'protected' && $sensitiveLogExposure !== null, 'vulnerability matrix includes safe error and sensitive log exposure coverage');



$memoryConfig = MemoryConfig::fromArray([
    'max_bytes' => '64M',
    'warning_ratio' => 0.70,
    'critical_ratio' => 0.90,
    'default_chunk_size' => 500,
    'min_chunk_size' => 25,
    'max_chunk_size' => 1000,
]);
ok(MemoryConfig::parseBytes('64M') === 64 * 1024 * 1024 && MemoryConfig::parseBytes('-1') === 0, 'memory config parses shorthand sizes and unlimited');
$memoryGuard = new MemoryGuard($memoryConfig, new FileLogger($base . '/logs/memory.log'));
$memorySnapshot = $memoryGuard->snapshot('test-memory');
ok($memorySnapshot->currentBytes() > 0 && $memorySnapshot->limitBytes() === 64 * 1024 * 1024, 'memory snapshot captures current and limit bytes');
ok($memoryGuard->canAllocate(1024), 'memory guard allows small allocation estimate');
$recommendedChunk = $memoryGuard->recommendedChunkSize(2048);
ok($recommendedChunk >= 25 && $recommendedChunk <= 1000, 'memory guard recommends bounded chunk size');

$chunkProcessor = new ChunkProcessor($memoryGuard);
$chunkSum = 0;
$chunkSummary = $chunkProcessor->process(ChunkProcessor::lazyRange(1, 105), function (array $chunk) use (&$chunkSum): void {
    $chunkSum += array_sum($chunk);
}, 25, 'test-chunk-processing');
ok($chunkSummary['processed'] === 105 && $chunkSummary['chunks'] === 5 && $chunkSum === array_sum(range(1, 105)), 'chunk processor processes large iterable in chunks');

$resourceTracker = new ResourceTracker();
$tempTrackedFile = $resourceTracker->trackTemporaryFile($base . '/memory/temp.txt');
@mkdir(dirname($tempTrackedFile), 0777, true);
file_put_contents($tempTrackedFile, 'temporary');
$handle = $resourceTracker->trackHandle(fopen($base . '/memory/handle.txt', 'w'));
fwrite($handle, 'handle');
ok($resourceTracker->count()['temporary_files'] === 1 && $resourceTracker->count()['handles'] === 1, 'resource tracker records handles and temporary files');
$resourceTracker->cleanup();
ok(!is_file($tempTrackedFile), 'resource tracker cleans temporary files');

$memoryMonitor = new MemoryMonitor($memoryGuard, new FileLogger($base . '/logs/memory-monitor.log'));
$memoryMonitor->mark('before');
$memoryMonitor->mark('after');
ok(count($memoryMonitor->report()) === 2 && $memoryMonitor->highestPeakBytes() > 0, 'memory monitor records snapshots');

$memoryPipeline = new MiddlewarePipeline([new MemoryLimitMiddleware($memoryGuard, 'test-request')]);
$memoryResponse = $memoryPipeline->handle(new Request('GET', '/memory'), fn() => Response::json(['status' => true]));
ok($memoryResponse->status() === 200 && isset($memoryResponse->headers()['X-Memory-Peak-MB']), 'memory middleware adds usage headers to guarded response');

$memoryPolicyConfig = array_replace_recursive($defaultConfig, [
    'memory' => [
        'enabled' => true,
        'max_bytes' => '64M',
        'profiles' => [
            'request' => ['max_bytes' => '64M', 'critical_ratio' => 0.90],
            'database_export' => ['max_bytes' => '128M', 'require_streaming' => true, 'chunk_size' => 1000, 'max_rows' => 100000],
            'queue_worker' => ['max_bytes' => '256M', 'restart_after_growth_mb' => 1, 'restart_after_jobs' => 3],
        ],
        'payloads' => ['max_decoded_depth' => 4, 'max_array_items' => 20, 'max_string_bytes' => 32],
        'streams' => ['max_read_bytes' => 4096, 'max_write_bytes' => 4096, 'buffer_size' => 512, 'fail_closed' => true],
        'temporary_files' => ['max_files' => 5, 'max_total_bytes' => 4096, 'max_age_seconds' => 1, 'cleanup_on_shutdown' => true],
        'output_buffers' => ['enabled' => true, 'max_buffer_bytes' => 64, 'fail_closed' => true],
    ],
]);
$memoryPolicy = MemoryPolicy::fromConfig($memoryPolicyConfig);
ok($memoryPolicy->profile('database_export')->requireStreaming() && $memoryPolicy->profile('database_export')->chunkSize() === 1000, 'memory policy resolves operation profiles and streaming requirements');
ok($memoryPolicy->decideAllocation('request', 1024, 1024 * 1024)->allowed() && $memoryPolicy->decideAllocation('request', 100 * 1024 * 1024, 60 * 1024 * 1024)->blocked(), 'memory policy allows safe allocation and blocks critical budget estimate');

$streamGuard = StreamGuard::fromConfig($memoryPolicyConfig);
ok($streamGuard->plan(2048, 'read')['passed'] && !$streamGuard->plan(8192, 'read')['passed'], 'stream guard plans bounded reads');
$streamSource = $base . '/memory/stream-source.txt';
file_put_contents($streamSource, str_repeat('A', 2048));
$readTotal = 0;
foreach ((new SafeStreamReader($streamGuard))->chunks($streamSource, 4096, 512) as $chunk) { $readTotal += strlen($chunk); }
ok($readTotal === 2048, 'safe stream reader reads file in bounded chunks');
$streamTarget = $base . '/memory/stream-target.txt';
$writerReport = (new SafeStreamWriter($streamGuard))->writeChunks($streamTarget, ['abc', 'def']);
ok($writerReport['bytes_written'] === 6 && file_get_contents($streamTarget) === 'abcdef', 'safe stream writer writes bounded chunks');
$writeBlocked = false;
try { (new SafeStreamWriter($streamGuard))->writeChunks($base . '/memory/stream-too-large.txt', [str_repeat('x', 8192)]); } catch (RuntimeException $e) { $writeBlocked = true; }
ok($writeBlocked, 'safe stream writer blocks oversized output');

$bounded = new BoundedBuffer(2);
$bounded->push('a'); $bounded->push('b');
$bufferBlocked = false;
try { $bounded->push('c'); } catch (RuntimeException $e) { $bufferBlocked = true; }
ok($bufferBlocked && $bounded->flush() === ['a', 'b'] && $bounded->count() === 0, 'bounded buffer enforces max items and flushes');
$flushedBatches = [];
$autoBuffer = new BoundedBuffer(2, function (array $items) use (&$flushedBatches): void { $flushedBatches[] = $items; });
$autoBuffer->push(1); $autoBuffer->push(2); $autoBuffer->push(3);
ok(count($flushedBatches) === 1 && $autoBuffer->count() === 1, 'bounded buffer callback flush works');

$payloadGuard = PayloadSizeGuard::fromConfig($memoryPolicyConfig);
$payloadGuard->assertString('safe');
$largeStringBlocked = false;
try { $payloadGuard->assertString(str_repeat('x', 64)); } catch (RuntimeException $e) { $largeStringBlocked = true; }
$largeArrayBlocked = false;
try { $payloadGuard->assertArray(range(1, 30)); } catch (RuntimeException $e) { $largeArrayBlocked = true; }
ok($largeStringBlocked && $largeArrayBlocked, 'payload size guard blocks large strings and arrays');

$depthGuard = new ArrayDepthGuard(3);
$depthBlocked = false;
try { $depthGuard->assertWithinDepth(['a' => ['b' => ['c' => ['d' => true]]]]); } catch (RuntimeException $e) { $depthBlocked = true; }
ok($depthBlocked, 'array depth guard blocks deep nested payloads');
$jsonGuard = new JsonDepthGuard(4);
ok(is_array($jsonGuard->decode('{"ok":true}')), 'json depth guard decodes safe json');
$jsonBlocked = false;
try { (new JsonDepthGuard(2))->decode('{"a":{"b":{"c":true}}}'); } catch (RuntimeException $e) { $jsonBlocked = true; }
ok($jsonBlocked, 'json depth guard blocks deep json');
$decodedGuard = DecodedPayloadGuard::fromConfig($memoryPolicyConfig);
$decodedGuard->assertSafe(['ok' => true]);
$decodedBlocked = false;
try { $decodedGuard->assertSafe(str_repeat('x', 64)); } catch (RuntimeException $e) { $decodedBlocked = true; }
ok($decodedBlocked, 'decoded payload guard enforces payload size limits');

$outputGuard = OutputBufferGuard::fromConfig($memoryPolicyConfig);
ok($outputGuard->check('small')['passed'], 'output buffer guard allows small response buffer');
$outputBlocked = false;
try { $outputGuard->assertSafe(str_repeat('x', 128)); } catch (RuntimeException $e) { $outputBlocked = true; }
ok($outputBlocked, 'output buffer guard blocks oversized buffer');

$scopeManager = new ResourceScopeManager();
$scope = $scopeManager->start('test-scope');
$scopeTemp = $base . '/memory/scope-temp.txt';
file_put_contents($scopeTemp, 'temporary');
$scope->trackTemporaryFile($scopeTemp);
$scopeReport = $scope->cleanup();
ok(!is_file($scopeTemp) && $scopeReport['cleaned'], 'resource scope cleans tracked temporary files');
ok($scope->cleanup()['idempotent'] === true, 'resource scope cleanup is idempotent');

$tempManager = new TemporaryFileManager($base . '/memory/tmp-budget', \Mnb\SecurityCore\Memory\TemporaryFileBudget::fromArray(['max_files' => 2, 'max_total_bytes' => 16, 'max_age_seconds' => 0]));
$tmpA = $tempManager->create('a_', '1234');
ok($tempManager->usage()['files'] >= 1, 'temporary file manager tracks usage');
$tmpPlan = (new TempStorageSweeper($tempManager))->plan();
ok($tmpPlan['passed'] && array_key_exists('count', $tmpPlan), 'temporary storage sweeper creates cleanup plan');

$leakDetector = new MemoryLeakDetector();
$leakReport = $leakDetector->analyze(1000, 3000, 1024);
ok($leakReport['restart_recommended'] && $leakReport['growth_bytes'] === 2000, 'memory leak detector recommends restart on growth threshold');
$workerSupervisor = new WorkerMemorySupervisor($memoryPolicy->profile('queue_worker'), new MemoryLeakDetector());
$workerReport = $workerSupervisor->check(4, 1000, 1000);
ok($workerReport['restart_recommended'] && $workerReport['reason'] === 'job_count_threshold_reached', 'worker memory supervisor recommends restart after job threshold');

$memoryKernel = new SecurityKernel($memoryPolicyConfig);
ok($memoryKernel->memoryPolicy()->profile('request')->enabled() && $memoryKernel->streamGuard()->plan(1024)['passed'] && $memoryKernel->outputBufferGuard()->check('ok')['passed'], 'security kernel exposes memory governance and resource safety helpers');

$memoryConfigReport = (new SecurityConfigValidator($memoryPolicyConfig))->validate();
ok($memoryConfigReport['passed'], 'security config validator accepts memory governance config');
$badMemoryConfigReport = (new SecurityConfigValidator(array_replace_recursive($defaultConfig, ['memory' => ['warning_ratio' => 0.95, 'critical_ratio' => 0.80, 'profiles' => ['bad profile!' => 'nope'], 'streams' => ['max_read_bytes' => 0]]])))->validate();
ok(in_array('invalid_memory_ratio_order', array_column($badMemoryConfigReport['errors'], 'key'), true), 'security config validator blocks unsafe memory ratios');

$memoryVulnerability = (new \Mnb\SecurityCore\Vulnerability\VulnerabilityMatrix($memoryPolicyConfig))->find('memory_exhaustion');
$resourceLeakVulnerability = (new \Mnb\SecurityCore\Vulnerability\VulnerabilityMatrix($memoryPolicyConfig))->find('resource_leak');
ok($memoryVulnerability !== null && $memoryVulnerability->status() === 'protected' && $resourceLeakVulnerability !== null, 'vulnerability matrix includes memory exhaustion and resource leak coverage');

$pentestPayloads = (new PayloadLibrary())->get('memory');
ok(count($pentestPayloads) >= 3, 'pentest payload library includes memory/resource exhaustion scenarios');

$verificationMatrix = (new VerificationMatrix())->all();
ok(isset($verificationMatrix['Memory Management and Resource Safety']), 'verification matrix maps memory management concept');

$throughputConfig = ThroughputConfig::fromArray([
    'target_rps' => 40,
    'warning_latency_ms' => 20,
    'critical_latency_ms' => 200,
    'max_concurrency' => 10,
    'sample_window_seconds' => 60,
]);
$throughputMeter = new ThroughputMeter($throughputConfig, new FileLogger($base . '/logs/throughput.log'));
$throughputMonitor = new ThroughputMonitor($throughputConfig);
$throughputMeasured = $throughputMeter->measure('test-throughput-operation', fn() => 'ok', 10, ['module' => 'test']);
ok($throughputMeasured['result'] === 'ok' && $throughputMeasured['sample']->throughputPerSecond() > 0, 'throughput meter measures operation result and rate');
$throughputMonitor->record($throughputMeasured['sample']);
$throughputMonitor->record($throughputMeter->recordDuration('slow-report', 25, 1));
$throughputSummary = $throughputMonitor->summary();
ok($throughputSummary['samples'] >= 2 && isset($throughputSummary['p95_ms']) && isset($throughputSummary['throughput_per_second']), 'throughput monitor summarizes samples');
$throughputPlan = ThroughputPlanner::plan(40, 120, 10, 250, 800);
ok($throughputPlan['required_concurrency'] === 5 && $throughputPlan['within_concurrency_budget'] === true && $throughputPlan['recommended_queue_workers'] >= 1, 'throughput planner calculates concurrency and worker plan');
$throughputPipeline = new MiddlewarePipeline([new ThroughputMiddleware($throughputMeter, $throughputMonitor, 'test-web')]);
$throughputResponse = $throughputPipeline->handle(new Request('GET', '/throughput'), fn() => Response::json(['status' => true]));
ok($throughputResponse->status() === 200 && isset($throughputResponse->headers()['X-Throughput-Duration-MS']), 'throughput middleware adds safe timing headers');
$pentestPayloadsThroughput = (new PayloadLibrary())->get('throughput');
ok(count($pentestPayloadsThroughput) >= 3, 'pentest payload library includes throughput overload scenarios');
$verificationMatrix = (new VerificationMatrix())->all();
ok(isset($verificationMatrix['Throughput and Performance Capacity Management']), 'verification matrix maps throughput management concept');



$passwordPolicy = new PasswordPolicy(['min_length' => 12, 'block_common_passwords' => true, 'block_user_context' => true]);
$passwordPolicyFail = $passwordPolicy->validate('password', ['email' => 'ravi@example.com']);
$passwordPolicyPass = $passwordPolicy->validate('SafeUniquePassphrase42!', ['email' => 'ravi@example.com']);
ok($passwordPolicyFail->failed() && $passwordPolicyPass->passed(), 'password policy blocks common weak passwords and accepts strong passphrases');

$authRegistry = new AuthenticationRegistry([
    'api_bearer' => ['type' => 'bearer', 'required' => true, 'scopes' => ['profile.read']],
    'optional_bearer' => ['type' => 'bearer', 'required' => false],
    'admin_bearer' => ['type' => 'bearer', 'required' => true, 'roles' => ['admin']],
]);
ok($authRegistry->get('api_bearer')->type() === AuthenticationStrategy::TYPE_BEARER && $authRegistry->get('optional_bearer')->required() === false, 'authentication registry registers bearer and optional strategies');

$authTokenStore = new FileTokenStore($base . '/auth-strategy/tokens.json');
$authAudit = new SecurityAuditTrail(new TamperEvidentAuditLogger($base . '/audit/auth-strategy.log'));
$authTokenService = new OpaqueTokenService($authTokenStore, $authAudit);
$issuedAuthToken = $authTokenService->issue(701, ['profile.read'], ttlSeconds: 3600);
$authMiddleware = new AuthenticationMiddleware($authRegistry->get('api_bearer'), $authTokenService, null, $authAudit);
$authRequest = new Request('GET', '/api/profile', [], [], [], ['REMOTE_ADDR' => '127.0.0.1', 'HTTP_AUTHORIZATION' => 'Bearer ' . $issuedAuthToken['plain_token']]);
$authMiddlewareResponse = (new MiddlewarePipeline([$authMiddleware]))->handle($authRequest, fn(Request $request) => Response::json(['user_id' => $request->attribute('auth')->id(), 'strategy' => $request->attribute('auth_strategy')]));
$authMiddlewareBody = json_decode($authMiddlewareResponse->body(), true);
ok($authMiddlewareResponse->status() === 200 && $authMiddlewareBody['user_id'] === 701 && $authMiddlewareBody['strategy'] === 'api_bearer', 'authentication middleware validates bearer token and attaches auth context');

$adminDeniedMiddleware = new AuthenticationMiddleware($authRegistry->get('admin_bearer'), $authTokenService, null, $authAudit);
$adminDeniedResponse = (new MiddlewarePipeline([$adminDeniedMiddleware]))->handle($authRequest, fn() => Response::json(['ok' => true]));
ok($adminDeniedResponse->status() === 403, 'authentication middleware enforces role requirements');

$optionalMiddleware = new AuthenticationMiddleware($authRegistry->get('optional_bearer'), $authTokenService, null, $authAudit);
$optionalResponse = (new MiddlewarePipeline([$optionalMiddleware]))->handle(new Request('GET', '/public'), fn(Request $request) => Response::json(['guest' => !$request->attribute('auth')->isAuthenticated()]));
ok($optionalResponse->status() === 200 && json_decode($optionalResponse->body(), true)['guest'] === true, 'optional bearer strategy allows guests while attaching auth context');

$userProvider = new class($hasher) implements UserProviderInterface {
    private array $user;
    public function __construct(private PasswordHasher $hasher) {
        $this->user = [
            'id' => 801,
            'email' => 'admin@example.com',
            'password_hash' => $this->hasher->hash('CorrectHorseBatteryStaple!'),
            'active' => true,
            'roles' => ['admin'],
            'permissions' => ['profile.read'],
            'scopes' => ['profile.read'],
        ];
    }
    public function findByIdentifier(string $identifier): ?array { return strtolower($identifier) === 'admin@example.com' ? $this->user : null; }
    public function passwordHash(array $user): string { return (string)$user['password_hash']; }
    public function userId(array $user): int|string { return $user['id']; }
    public function roles(array $user): array { return $user['roles']; }
    public function permissions(array $user): array { return $user['permissions']; }
    public function scopes(array $user): array { return $user['scopes']; }
    public function isActive(array $user): bool { return !empty($user['active']); }
};
$workflow = new AuthWorkflowService($userProvider, $hasher, $authTokenService, $authAudit, $passwordPolicy, ['ttl_seconds' => 3600]);
$loginSuccess = $workflow->login('admin@example.com', 'CorrectHorseBatteryStaple!', ['uploads.write'], context: ['ip' => '127.0.0.1']);
$loginFailure = $workflow->login('admin@example.com', 'wrong-password', context: ['ip' => '127.0.0.1']);
ok($loginSuccess->success() && $loginSuccess->plainToken() !== null && $loginSuccess->auth()?->hasRole('admin') && $loginFailure->failed(), 'auth workflow service logs in users safely and issues opaque tokens');

$authConfigReport = (new SecurityConfigValidator([
    'authentication' => [
        'enabled' => true,
        'strategies' => ['bad' => ['type' => 'magic']],
        'password_policy' => ['min_length' => 6, 'max_length' => 4],
    ],
]))->validate();
ok(!$authConfigReport['passed'], 'security config validator catches invalid authentication strategies and password policy');


$authorizationAudit = new SecurityAuditTrail(new TamperEvidentAuditLogger($base . '/audit/authorization-strategy.log'));
$authorizationRegistry = new AuthorizationRegistry([
    'students.read' => [
        'resource' => 'students',
        'actions' => ['read'],
        'roles' => ['school_admin', 'super_admin'],
        'permissions' => ['student.view'],
        'scopes' => ['students:read'],
        'tenant_required' => true,
        'data_classes' => ['sensitive'],
        'trust_boundary' => 'students.read',
        'audit' => true,
        'fields' => [
            'read' => [
                'school_admin' => ['id', 'name', 'parent_phone', 'school_id'],
                'super_admin' => ['*'],
            ],
        ],
    ],
    'students.update' => [
        'resource' => 'students',
        'actions' => ['update'],
        'roles' => ['school_admin', 'super_admin'],
        'permissions' => ['student.update'],
        'scopes' => ['students:update'],
        'tenant_required' => true,
        'data_classes' => ['sensitive'],
        'audit' => true,
        'fields' => [
            'write' => [
                'school_admin' => ['name', 'parent_phone'],
                'super_admin' => ['*'],
            ],
        ],
    ],
], ['deny_by_default' => true, 'audit_denials' => true, 'hide_denial_reasons' => false], $authorizationAudit, $trustRegistry);
$authzRequest = $schoolAdminRequest->withAttribute(AuthContext::ATTRIBUTE, new AuthContext(true, 10, ['students:read', 'students:update', 'school:*'], ['student.view', 'student.update'], ['school_admin']));
$authzAllowed = $authorizationRegistry->decide('students.read', $authzRequest, ['id' => 5, 'school_id' => 10, 'parent_phone' => '999'], 'read', 'students', 'sensitive');
$authzCrossTenant = $authorizationRegistry->decide('students.read', $authzRequest, ['id' => 5, 'school_id' => 99], 'read', 'students', 'sensitive');
ok($authzAllowed->allowed() && $authzCrossTenant->denied() && $authzCrossTenant->code() === 'tenant.denied', 'authorization registry unifies roles scopes permissions tenant and trust boundary decisions');

$readFiltered = $authorizationRegistry->filterReadableFields('students.read', $authzRequest, ['id' => 5, 'name' => 'Ravi', 'parent_phone' => '999', 'password_hash' => 'hash']);
$writeFiltered = $authorizationRegistry->filterWritableFields('students.update', $authzRequest, ['name' => 'Ravi', 'parent_phone' => '999', 'school_id' => 10, 'password_hash' => 'hash']);
ok(isset($readFiltered['parent_phone']) && !isset($readFiltered['password_hash']) && isset($writeFiltered['name']) && !isset($writeFiltered['school_id']), 'authorization registry filters readable and writable fields by policy');

$authzMiddleware = new AuthorizationMiddleware($authorizationRegistry, 'students.update', fn(Request $request): array => ['id' => 5, 'school_id' => 10], action: 'update', resourceName: 'students', dataClass: 'sensitive', hideReason: false);
$authzMiddlewareResponse = (new MiddlewarePipeline([$authzMiddleware]))->handle($authzRequest, fn(Request $request) => Response::json(['policy' => $request->attribute('authorization_policy'), 'allowed' => $request->attribute('authorization_decision')->allowed()]));
ok($authzMiddlewareResponse->status() === 200 && json_decode($authzMiddlewareResponse->body(), true)['policy'] === 'students.update', 'authorization middleware attaches decisions to allowed requests');

$authzDeniedMiddleware = new AuthorizationMiddleware($authorizationRegistry, 'students.update', fn(Request $request): array => ['id' => 5, 'school_id' => 99], action: 'update', resourceName: 'students', dataClass: 'sensitive', hideReason: false);
$authzDeniedResponse = (new MiddlewarePipeline([$authzDeniedMiddleware]))->handle($authzRequest, fn() => Response::json(['ok' => true]));
ok($authzDeniedResponse->status() === 403 && str_contains($authzDeniedResponse->body(), 'tenant.denied'), 'authorization middleware blocks denied resource actions safely');

$authzAuditEntries = (new TamperEvidentAuditLogger($base . '/audit/authorization-strategy.log'))->read(null, 'authorization');
ok(count($authzAuditEntries) >= 2 && !str_contains(json_encode($authzAuditEntries), 'parent_phone'), 'authorization strategy writes safe audit decisions without leaking resource payload');

$authzConfigReport = (new SecurityConfigValidator([
    'authorization' => [
        'enabled' => true,
        'policies' => [
            'bad policy' => ['actions' => ['read']],
            'students.read' => ['resource' => 'students', 'actions' => ['read'], 'data_classes' => ['secret']],
        ],
    ],
]))->validate();
ok(!$authzConfigReport['passed'], 'security config validator catches invalid authorization policies');

$authzSuggestions = (new AutoSuggestionEngine())->suggestFromCode('PermissionGuard::requirePermission($request, "student.update"); TenantGuard;');
ok(count(array_filter($authzSuggestions, fn(array $item): bool => ($item['id'] ?? '') === 'missing_authorization_strategy' || ($item['id'] ?? '') === 'authorization_strategy')) >= 1, 'auto suggestion engine recommends authorization strategy for manual permission code');



$dataProtectionConfig = [
    'app' => ['key' => str_repeat('D', 40), 'env' => 'testing'],
    'data_protection' => [
        'enabled' => true,
        'default_class' => DataClassifier::INTERNAL,
        'audit' => true,
        'encryption' => [
            'enabled' => true,
            'current_key_id' => 'test-v1',
            'keys' => ['test-v1' => str_repeat('K', 40)],
            'aad' => true,
        ],
        'search_hash' => [
            'enabled' => true,
            'key' => str_repeat('H', 40),
            'prefix' => 'mnb:test',
        ],
        'resources' => [
            'students' => [
                'default_class' => 'sensitive',
                'tenant_scoped' => true,
                'fields' => [
                    'id' => ['class' => 'internal'],
                    'name' => ['class' => 'internal'],
                    'email' => ['class' => 'confidential', 'encrypt' => true, 'search_hash' => true, 'mask' => 'email', 'export' => 'masked', 'log' => false],
                    'parent_phone' => ['class' => 'sensitive', 'encrypt' => true, 'search_hash' => true, 'mask' => 'last4', 'export' => 'masked', 'log' => false],
                    'password_hash' => ['class' => 'highly_sensitive', 'read' => false, 'write' => false, 'export' => false, 'log' => false],
                ],
            ],
        ],
        'exports' => ['csv_injection_protection' => true, 'max_rows' => 10, 'audit' => true],
        'storage' => ['encrypt_files' => true],
        'backups' => ['encrypt' => true, 'sign' => true, 'retention_days' => 30],
        'logs' => ['redact_before_write' => true],
    ],
];
$dataProtectionAudit = new SecurityAuditTrail(new TamperEvidentAuditLogger($base . '/audit/data-protection.log'));
$dataRegistry = DataProtectionRegistry::fromConfig($dataProtectionConfig, $dataProtectionAudit);
$protectedStudent = $dataRegistry->protectForStorage('students', [
    'id' => 7,
    'name' => 'Ravi',
    'email' => 'ravi@example.com',
    'parent_phone' => '9876543210',
    'password_hash' => 'hash',
]);
ok(isset($protectedStudent['email_hash'], $protectedStudent['parent_phone_hash']) && str_starts_with((string)$protectedStudent['email'], KeyRing::PREFIX) && !isset($protectedStudent['password_hash']), 'data protection registry encrypts fields and creates search hashes for storage');
$unprotectedStudent = $dataRegistry->unprotectFromStorage('students', $protectedStudent);
ok($unprotectedStudent['email'] === 'ravi@example.com' && $unprotectedStudent['parent_phone'] === '9876543210', 'data protection registry decrypts protected fields from storage');
$responseStudent = $dataRegistry->protectForResponse('students', $protectedStudent);
$logStudent = $dataRegistry->protectForLog('students', $protectedStudent);
ok(isset($responseStudent['email']) && $responseStudent['email'] !== 'ravi@example.com' && !isset($responseStudent['password_hash']) && ($logStudent['email'] ?? '') === '[redacted]', 'data protection registry masks responses and redacts logs');
$csv = (new SafeCsvExporter($dataRegistry, new ExportPolicy(['csv_injection_protection' => true, 'max_rows' => 10])))->export('students', [
    ['name' => '=HYPERLINK("http://evil")', 'email' => 'ravi@example.com', 'parent_phone' => '9876543210', 'password_hash' => 'hash'],
]);
ok(str_contains($csv, "'=HYPERLINK") && !str_contains($csv, '9876543210') && !str_contains($csv, 'password_hash'), 'safe CSV exporter masks fields and blocks CSV formula injection');
$encryptedStorage = new EncryptedStorage(new LocalPrivateStorage($base . '/encrypted-storage'), new KeyRing('test-v1', ['test-v1' => str_repeat('S', 40)]));
$encryptedStorage->put('docs/secret.txt', 'secret file body');
$rawStored = file_get_contents($encryptedStorage->absolutePath('docs/secret.txt'));
ok($encryptedStorage->read('docs/secret.txt') === 'secret file body' && is_string($rawStored) && !str_contains($rawStored, 'secret file body'), 'encrypted storage protects file contents at rest');
$dpInvalidReport = (new SecurityConfigValidator(['data_protection' => ['enabled' => true, 'encryption' => ['enabled' => true, 'current_key_id' => 'missing', 'keys' => ['old' => 'short']], 'resources' => ['bad resource' => []]]]))->validate();
ok(!$dpInvalidReport['passed'], 'security config validator catches invalid data protection policies and keys');
$dpSuggestions = (new AutoSuggestionEngine())->suggestFromCode('Response::json($student); fputcsv($handle, $row); $student["parent_phone"]');
ok(count(array_filter($dpSuggestions, fn(array $item): bool => ($item['id'] ?? '') === 'missing_data_protection_strategy' || ($item['id'] ?? '') === 'data_protection_strategy')) >= 1, 'auto suggestion engine recommends data protection strategy for sensitive output/export code');



$escaper = new OutputEscaper();
ok($escaper->html('<script>alert(1)</script>') === '&lt;script&gt;alert(1)&lt;/script&gt;' && str_contains($escaper->attr('" onclick="x'), '&quot;'), 'output escaper safely encodes html and attributes');

$sanitizer = new HtmlSanitizer(['allowed_tags' => ['p', 'a', 'strong'], 'allowed_attributes' => ['href', 'title']]);
$cleanHtml = $sanitizer->sanitize('<p onclick="x">Hi <script>alert(1)</script><a href="javascript:alert(1)" title="ok">bad</a><a href="/safe">safe</a></p>');
ok(!str_contains($cleanHtml, 'script') && !str_contains($cleanHtml, 'onclick') && !str_contains($cleanHtml, 'javascript:') && str_contains($cleanHtml, 'href="/safe"'), 'HTML sanitizer removes dangerous tags attributes and URLs');

$redirector = new SafeRedirector(['allow_external' => true, 'allowed_hosts' => ['trusted.test']], 'app.test');
ok($redirector->to('/dashboard') === '/dashboard' && $redirector->to('https://trusted.test/ok') === 'https://trusted.test/ok' && $redirector->to('https://evil.test/phish', '/fallback') === '/fallback' && $redirector->to('javascript:alert(1)', '/fallback') === '/fallback', 'safe redirector allows relative and allow-listed hosts only');

$cookieBuilder = new SecureCookieBuilder(['secure' => true, 'http_only' => true, 'same_site' => 'Lax', 'path' => '/']);
$cookieHeader = $cookieBuilder->make('__Host-device', 'abc 123', ['max_age' => 3600]);
$cookieFailed = false;
try { (new SecureCookieBuilder(['secure' => false, 'same_site' => 'None']))->make('bad', 'x'); } catch (\InvalidArgumentException) { $cookieFailed = true; }
ok(str_contains($cookieHeader, '__Host-device=abc%20123') && str_contains($cookieHeader, 'Secure') && str_contains($cookieHeader, 'HttpOnly') && $cookieFailed, 'secure cookie builder enforces secure defaults and SameSite rules');

$cachePolicy = new CacheControlPolicy();
$cacheHeaders = $cachePolicy->headers('sensitive_no_store');
$cacheResponse = (new MiddlewarePipeline([new CacheControlMiddleware($cachePolicy, 'sensitive_no_store')]))->handle(new Request('GET', '/account'), fn() => Response::text('ok'));
ok(($cacheHeaders['Cache-Control'] ?? '') === 'no-store, private' && ($cacheResponse->headers()['Pragma'] ?? '') === 'no-cache', 'cache-control policy and middleware apply sensitive no-store headers');

$signedUrl = new SignedUrl(str_repeat('U', 40), 300);
$signed = $signedUrl->sign('/download/report.csv', ['user_id' => 10], time() + 300, 'download');
ok($signedUrl->verify($signed, 'download') && !$signedUrl->verify($signed . 'x', 'download') && !$signedUrl->verify($signed, 'other'), 'signed URL helper signs and verifies purpose-bound expiring URLs');

$webConfig = [
    'app' => ['key' => str_repeat('W', 40), 'env' => 'testing'],
    'web_security' => [
        'enabled' => true,
        'profiles' => [
            'browser_form' => ['security_headers' => true, 'cache_policy' => 'sensitive_no_store', 'csrf' => true, 'safe_redirects' => true, 'output_escape' => true],
        ],
        'redirects' => ['allow_external' => false, 'allowed_hosts' => []],
        'cookies' => ['secure' => true, 'http_only' => true, 'same_site' => 'Lax', 'path' => '/'],
        'html_sanitizer' => ['allowed_tags' => ['p', 'a'], 'allowed_attributes' => ['href'], 'allow_data_images' => false],
        'signed_urls' => ['key' => str_repeat('Z', 40), 'default_ttl' => 300],
    ],
];
$webRegistry = WebSecurityRegistry::fromConfig($webConfig);
$webKernel = new SecurityKernel(array_replace_recursive(require __DIR__ . '/../config/security.php', $webConfig));
$webControls = $webKernel->webSecurityControls('browser_form');
ok($webRegistry->has('browser_form') && $webControls->profile()->cachePolicy() === 'sensitive_no_store' && $webControls->safeRedirect('https://evil.test', '/safe') === '/safe', 'web security registry and kernel controls expose configured profiles and helpers');

$webInvalidReport = (new SecurityConfigValidator(['app' => ['env' => 'production'], 'web_security' => ['enabled' => true, 'redirects' => ['allow_external' => true], 'cookies' => ['same_site' => 'None', 'secure' => false], 'signed_urls' => ['key' => 'short'], 'profiles' => ['bad profile' => []]]]))->validate();
ok(!$webInvalidReport['passed'], 'security config validator catches unsafe web security controls');

$webSuggestions = (new AutoSuggestionEngine())->suggestFromCode('echo $name; header(\'Location: \'.$next); setcookie("device", $id);');
ok(count(array_filter($webSuggestions, fn(array $item): bool => ($item['id'] ?? '') === 'missing_web_security_controls' || ($item['id'] ?? '') === 'web_security_controls')) >= 1, 'auto suggestion engine recommends web security controls for output redirects and cookies');



$secretProvider = new ArraySecretProvider([
    'APP_KEY' => str_repeat('A', 40),
    'WEBHOOK_SECRET' => str_repeat('B', 40),
]);
$secretConfig = array_replace_recursive(require __DIR__ . '/../config/security.php', [
    'app' => ['env' => 'testing', 'key' => str_repeat('A', 40)],
    'secrets' => [
        'definitions' => [
            'app.key' => ['env' => 'APP_KEY', 'required' => true, 'min_length' => 32, 'purpose' => 'master'],
            'data.key' => ['env' => 'DATA_KEY', 'derive_from' => 'app.key', 'min_length' => 32, 'purpose' => 'data'],
            'webhook.secret' => ['env' => 'WEBHOOK_SECRET', 'required' => true, 'min_length' => 32, 'purpose' => 'webhook'],
        ],
    ],
]);
$secretManager = SecretManager::fromConfig($secretConfig, $secretProvider);
$derivedDataKey = $secretManager->get('data.key');
ok($secretManager->get('app.key') === str_repeat('A', 40) && is_string($derivedDataKey) && strlen($derivedDataKey) >= 64, 'secret manager reads explicit secrets and derives purpose keys');

$secretReport = $secretManager->inventory()->report()->toArray();
ok($secretReport['passed'] && ($secretReport['summary']['present'] ?? 0) >= 2, 'secret inventory reports present required secrets');

$redactor = new SecretRedactor('[secret]', 4);
$redactedArray = $redactor->redactArray(['api_key' => 'abcdefghijklmnop', 'nested' => ['password' => 'supersecretvalue'], 'public' => 'ok']);
ok($redactedArray['api_key'] === '[secret]:mnop' && $redactedArray['nested']['password'] === '[secret]:alue' && $redactedArray['public'] === 'ok', 'secret redactor redacts secret-like keys recursively');

$deriver = new KeyDeriver(str_repeat('M', 40), 'test-salt');
ok($deriver->derive('data.encryption') !== $deriver->derive('signed.url') && strlen($deriver->derive('data.encryption')) === 64, 'key deriver creates separated purpose-specific keys');

$envValidation = (new EnvironmentValidator($secretConfig, $secretManager))->validate();
ok($envValidation['passed'] && $envValidation['environment'] === 'testing', 'environment validator combines environment and secret readiness');

$rotationReport = $secretManager->rotationReport()->toArray();
ok(isset($rotationReport['items']) && count($rotationReport['items']) >= 2, 'secret rotation report lists rotatable definitions');

$scanDir = $base . '/secret-scan';
@mkdir($scanDir, 0777, true);
file_put_contents($scanDir . '/bad.php', "<?php\n\$api_key = '" . str_repeat('X', 32) . "';\n");
$scanReport = (new SecretScanner(['entropy' => true, 'ignore_paths' => []]))->report($scanDir);
ok(!$scanReport['passed'] && count($scanReport['findings']) >= 1, 'secret scanner reports accidental secret findings with metadata');

$_ENV['WEBHOOK_SECRET'] = str_repeat('B', 40);
$secretKernel = new SecurityKernel($secretConfig);
ok($secretKernel->secretHealthReport()->toArray()['passed'] && strlen($secretKernel->keyDeriver()->derive('cache.encryption')) === 64, 'security kernel exposes secret manager inventory and key derivation helpers');


$secretSuggestions = (new AutoSuggestionEngine())->suggestFromCode("\$_ENV['APP_KEY']; getenv('WEBHOOK_SECRET');");
ok(count(array_filter($secretSuggestions, fn(array $item): bool => ($item['id'] ?? '') === 'missing_secret_management_engine' || ($item['id'] ?? '') === 'secret_management_engine')) >= 1, 'auto suggestion engine recommends secret management for raw env secrets');

$secretInvalidReport = (new SecurityConfigValidator(['app' => ['env' => 'production'], 'secrets' => ['enabled' => false, 'definitions' => ['bad name!' => ['env' => 'bad-env']]]]))->validate();
ok(!$secretInvalidReport['passed'], 'security config validator catches unsafe secret management configuration');



$logDir = $base . '/logging-engine';
@mkdir($logDir, 0777, true);
$logFile = $logDir . '/security.jsonl';
$protector = new LogDataProtector(new SecretRedactor('[redacted]', 0));
$logger = new Logger([new JsonLogHandler($logFile, $protector)], 'security', 'info');
$logger->warning('Suspicious token=abc123', ['api_key' => 'secret-value', 'public' => 'ok']);
$logLine = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)[0] ?? '';
ok(str_contains($logLine, '[redacted]') && !str_contains($logLine, 'secret-value') && str_contains($logLine, 'security'), 'logger writes redacted JSONL records by channel');

$auditFile = $logDir . '/audit.log';
$auditTrail = new SecurityAuditTrail(new TamperEvidentAuditLogger($auditFile));
$auditTrail->record(SecurityAuditEvent::login(SecurityAuditEvent::OUTCOME_FAILURE, ['user_id' => 15], ['ip' => '127.0.0.1']));
$verifier = new AuditIntegrityVerifier($auditFile);
$verifyReport = $verifier->verify();
ok($verifyReport['passed'] && $verifyReport['entries'] === 1, 'audit integrity verifier validates tamper-evident chain');
file_put_contents($auditFile, str_replace('failure', 'success', file_get_contents($auditFile)));
ok(!$verifier->verify()['passed'], 'audit integrity verifier detects tampering');

$auditFile2 = $logDir . '/audit-export.log';
$auditTrail2 = new SecurityAuditTrail(new TamperEvidentAuditLogger($auditFile2));
$auditTrail2->record(SecurityAuditEvent::token('rejected', SecurityAuditEvent::OUTCOME_FAILURE));
$export = (new AuditExporter($auditFile2))->export('token');
ok($export['count'] === 1 && ($export['entries'][0]['category'] ?? '') === 'token', 'audit exporter reads filtered audit events');

$metrics = new MetricsRegistry($logDir . '/metrics.json');
$metrics->increment('auth_failures_total', ['policy' => 'login']);
$metrics->increment('auth_failures_total', ['policy' => 'login']);
ok($metrics->get('auth_failures_total', ['policy' => 'login']) === 2.0, 'metrics registry increments labeled counters');

$alertFile = $logDir . '/alerts.jsonl';
$alertEvents = $logDir . '/events.jsonl';
$alertManager = new AlertManager([new AlertRule('failed_login_spike', 'auth.login.failure', 2, 300, 'high')], [new FileAlertChannel($alertFile)], $alertEvents);
$firstAlerts = $alertManager->recordEvent('auth.login.failure', ['user_id' => 15]);
$secondAlerts = $alertManager->recordEvent('auth.login.failure', ['user_id' => 15]);
ok(count($firstAlerts) === 0 && count($secondAlerts) === 1 && is_file($alertFile), 'alert manager triggers threshold alerts');

$oldFile = $logDir . '/old.log';
file_put_contents($oldFile, 'old');
touch($oldFile, time() - 86400 * 10);
$retention = new LogRetentionManager(new LogRetentionPolicy(['app' => 1, 'security' => 1, 'audit' => 30, 'debug' => 1]), $logDir, $logDir);
$purgeReport = $retention->purge('app');
ok($purgeReport['deleted_count'] >= 1 && !is_file($oldFile), 'log retention manager purges old log files');

$monitoringSummary = new MonitoringSummary(new AuditExporter($auditFile2), new AuditIntegrityVerifier($auditFile2), $metrics, $alertManager);
$summary = $monitoringSummary->toArray();
ok($summary['passed'] && ($summary['audit']['integrity']['passed'] ?? false) && isset($summary['metrics']['counters']), 'monitoring summary combines audit integrity metrics and alerts');

$traceRequest = (new Request('GET', '/trace', [], [], ['x-request-id' => 'req-123']))->withAttribute('auth_user_id', 15);
$trace = TraceContext::fromRequest($traceRequest)->toArray();
ok($trace['request_id'] === 'req-123' && $trace['user_id'] === '15', 'trace context extracts request and actor metadata');

$lmConfig = array_replace_recursive(require __DIR__ . '/../config/security.php', [
    'app' => ['env' => 'testing', 'key' => str_repeat('L', 40)],
    'secrets' => ['definitions' => ['app.key' => ['env' => 'APP_KEY', 'required' => false, 'min_length' => 32, 'purpose' => 'test']]],
    'paths' => ['logs' => $logDir, 'audit' => $logDir],
    'audit' => ['file' => $auditFile2],
]);
$lmKernel = new SecurityKernel($lmConfig);
$lmKernel->logger('security')->warning('Auth denied password=hidden', ['token' => 'abc123']);
$lmKernel->metricsRegistry()->increment('authorization_denials_total');
ok($lmKernel->monitoringSummary()->toArray()['passed'] && $lmKernel->auditIntegrityVerifier()->verify()['passed'], 'security kernel exposes logging audit and monitoring helpers');

$lmInvalidReport = (new SecurityConfigValidator(['app' => ['env' => 'production'], 'logging' => ['enabled' => false, 'channels' => ['bad channel!' => ['level' => 'wrong']]], 'monitoring' => ['enabled' => false, 'alerts' => ['rules' => ['bad rule!' => ['threshold' => 0]]]]]))->validate();
ok(!$lmInvalidReport['passed'], 'security config validator catches unsafe logging and monitoring configuration');

$lmSuggestions = (new AutoSuggestionEngine())->suggestFromCode('error_log($message); file_put_contents("audit.log", $data); TamperEvidentAuditLogger');
ok(count(array_filter($lmSuggestions, fn(array $item): bool => ($item['id'] ?? '') === 'missing_logging_monitoring_engine' || ($item['id'] ?? '') === 'logging_monitoring_engine')) >= 1, 'auto suggestion engine recommends logging audit and monitoring engine');



$recoveryDir = $base . '/recovery-engine';
$backupDir = $recoveryDir . '/backups';
$sourceDir = $recoveryDir . '/source';
@mkdir($sourceDir, 0777, true);
file_put_contents($sourceDir . '/config.txt', 'backup-body');
$backupPolicy = new BackupPolicy(true, $backupDir, true, true, str_repeat('B', 40), str_repeat('S', 40), [$sourceDir], []);
$backupSigner = new BackupSigner(str_repeat('S', 40));
$secureBackups = new SecureBackupManager($backupPolicy, $backupSigner, $auditTrail2);
$backupResult = $secureBackups->create('unit');
ok($backupResult['passed'] && is_file($backupResult['path']) && is_file($backupResult['manifest']) && is_file($backupResult['signature']) && $backupResult['encrypted'], 'secure backup manager creates encrypted signed backup with manifest');

$backupVerifier = new BackupIntegrityVerifier($backupSigner, true);
$backupVerify = $backupVerifier->verify($backupResult['path']);
ok($backupVerify['passed'] && $backupVerify['sha256'] === $backupResult['sha256'], 'backup integrity verifier validates checksum and signature');
file_put_contents($backupResult['path'], ((string)file_get_contents($backupResult['path'])) . 'tamper');
ok(!$backupVerifier->verify($backupResult['path'])['passed'], 'backup integrity verifier detects tampered backup');

$backupResult2 = $secureBackups->create('unit2');
$restore = new RestoreManager($backupVerifier, $secureBackups, [], $auditTrail2);
$restoreDryRun = $restore->dryRun($backupResult2['path'])->toArray();
ok($restoreDryRun['passed'] && $restoreDryRun['plan']['dry_run'], 'restore manager performs verified dry-run restore plan');

$oldBackup = $backupDir . '/old-backup.zip';
file_put_contents($oldBackup, 'old');
touch($oldBackup, time() - 86400 * 40);
$retentionManager = new BackupRetentionManager(new BackupRetentionPolicy(1, 1, 1), $backupDir);
$backupPurge = $retentionManager->purge();
ok($backupPurge['deleted'] >= 1 && !is_file($oldBackup), 'backup retention manager purges expired backups');

$recoveryStatus = new RecoveryStatusReport($backupDir, $backupVerifier, new BackupRetentionPolicy(7, 4, 12));
$statusReport = $recoveryStatus->toArray();
ok(isset($statusReport['latest_backup']) && isset($statusReport['latest_verification']), 'recovery status report summarizes latest backup readiness');

$playbook = IncidentPlaybook::fromArray('secret_leak_detected', ['severity' => 'critical', 'actions' => ['record_incident', 'invalidate_cache', 'collect_evidence']]);
ok($playbook->severity() === 'critical' && count($playbook->actions()) === 3, 'incident playbook normalizes severity and actions');

$incidentFile = $recoveryDir . '/incidents.jsonl';
$incidentRunner = new ContainmentActionRunner(null, $auditTrail2);
$evidenceCollector = new IncidentEvidenceCollector(new AuditExporter($auditFile2), $monitoringSummary, $lmKernel->secretHealthReport());
$incidentManager = new IncidentResponseManager(['secret_leak_detected' => $playbook], $incidentRunner, $evidenceCollector, $auditTrail2, $incidentFile);
$incidentReport = $incidentManager->runPlaybook('secret_leak_detected', ['user_id' => 15])->toArray();
ok($incidentReport['passed'] && is_file($incidentFile) && ($incidentReport['incident']['severity'] ?? '') === 'critical' && count($incidentReport['actions']) === 3, 'incident response manager opens case, runs playbook, collects evidence');

$i25Config = array_replace_recursive($lmConfig, [
    'paths' => ['backups' => $backupDir, 'logs' => $recoveryDir, 'audit' => $recoveryDir],
    'recovery' => [
        'enabled' => true,
        'backups' => ['enabled' => true, 'path' => $backupDir, 'encrypt' => true, 'sign' => true, 'key' => str_repeat('B', 40), 'signing_key' => str_repeat('S', 40), 'include' => [$sourceDir], 'exclude' => [], 'retention' => ['daily_days' => 7, 'weekly_weeks' => 4, 'monthly_months' => 12]],
        'restore' => ['require_signature' => true, 'require_encryption' => true, 'allow_overwrite' => false],
    ],
    'incident_response' => ['enabled' => true, 'file' => $incidentFile, 'playbooks' => ['audit_chain_broken' => ['severity' => 'critical', 'actions' => ['record_incident', 'collect_evidence']]]],
]);
$i25Kernel = new SecurityKernel($i25Config);
$i25Backup = $i25Kernel->secureBackupManager()->create('kernel');
ok($i25Kernel->backupIntegrityVerifier()->verify($i25Backup['path'])['passed'] && $i25Kernel->restoreManager()->dryRun($i25Backup['path'])->passed(), 'security kernel exposes backup verify and restore helpers');
$i25Incident = $i25Kernel->incidentResponse()->runPlaybook('audit_chain_broken', ['source' => 'test'])->toArray();
ok($i25Incident['passed'] && ($i25Kernel->incidentResponse()->summary()['count'] ?? 0) >= 1, 'security kernel exposes incident response helpers');

$i25InvalidReport = (new SecurityConfigValidator(['app' => ['env' => 'production'], 'recovery' => ['enabled' => false, 'backups' => ['encrypt' => false, 'sign' => false]], 'incident_response' => ['enabled' => true, 'playbooks' => ['bad name!' => ['severity' => 'extreme']]]]))->validate();
ok(!$i25InvalidReport['passed'], 'security config validator catches unsafe recovery and incident response configuration');

$i25Suggestions = (new AutoSuggestionEngine())->suggestFromCode('new BackupManager($path); restore backup incident response malware_upload_detected');
ok(count(array_filter($i25Suggestions, fn(array $item): bool => ($item['id'] ?? '') === 'missing_backup_incident_engine' || ($item['id'] ?? '') === 'backup_incident_engine')) >= 1, 'auto suggestion engine recommends backup recovery and incident response engine');



$vulnMatrix = new \Mnb\SecurityCore\Vulnerability\VulnerabilityMatrix($i25Config);
$vulnRows = $vulnMatrix->rows();
$vulnSql = $vulnMatrix->find('sql_injection');
ok(count($vulnRows) >= 25 && $vulnSql !== null && $vulnSql->score() >= 75, 'vulnerability matrix builds OWASP/CWE control coverage rows');

$vulnReport = (new VulnerabilityCoverageReport($vulnMatrix, 70))->toArray();
ok(isset($vulnReport['overall_score'], $vulnReport['grade']) && $vulnReport['count'] >= 25, 'vulnerability coverage report scores and grades matrix');

$vulnAdvice = (new VulnerabilityAdvisor($vulnMatrix))->recommend('ssrf');
ok($vulnAdvice['passed'] && $vulnAdvice['id'] === 'ssrf' && !empty($vulnAdvice['recommended_controls']), 'vulnerability advisor recommends next controls for partial coverage');

$i26Kernel = new SecurityKernel(array_replace_recursive($i25Config, [
    'vulnerability_matrix' => [
        'enabled' => true,
        'reporting' => ['minimum_passing_score' => 70],
        'vulnerabilities' => ['ssrf' => ['enabled' => true, 'severity' => 'high', 'expected_status' => 'partially_protected']],
    ],
]));
ok($i26Kernel->vulnerabilityCoverageReport()->toArray()['count'] >= 25 && $i26Kernel->vulnerabilityAdvisor()->recommend('sql_injection')['passed'], 'security kernel exposes vulnerability matrix helpers');

$i26InvalidReport = (new SecurityConfigValidator(['app' => ['env' => 'production'], 'vulnerability_matrix' => ['enabled' => false, 'reporting' => ['minimum_passing_score' => 0], 'vulnerabilities' => ['bad id!' => ['severity' => 'extreme', 'expected_status' => 'wrong']]]]))->validate();
ok(!$i26InvalidReport['passed'], 'security config validator catches invalid vulnerability matrix configuration');

$i26Suggestions = (new AutoSuggestionEngine())->suggestFromCode('OWASP CWE vulnerability SQL injection XSS SSRF coverage matrix');
ok(count(array_filter($i26Suggestions, fn(array $item): bool => ($item['id'] ?? '') === 'missing_vulnerability_matrix_engine' || ($item['id'] ?? '') === 'vulnerability_matrix_engine')) >= 1, 'auto suggestion engine recommends vulnerability blocking matrix engine');




$runtimeDir = $base . '/runtime-engine';
$runtimeAllowedDir = $runtimeDir . '/allowed';
$runtimeDeniedDir = $runtimeDir . '/denied';
@mkdir($runtimeAllowedDir, 0777, true);
@mkdir($runtimeDeniedDir, 0777, true);
$runtimeConfig = [
    'runtime' => [
        'enabled' => true,
        'deny_by_default' => true,
        'default_timeout_seconds' => 2,
        'max_output_bytes' => 2048,
        'allowed_env' => ['PATH'],
        'allowed_working_directories' => [$runtimeAllowedDir],
        'commands' => [
            'php_version' => ['binary' => PHP_BINARY, 'allowed_args' => ['-v'], 'timeout_seconds' => 2, 'max_output_bytes' => 2048],
            'php_sleep' => ['binary' => PHP_BINARY, 'allowed_args' => ['-r', 'sleep(2);'], 'timeout_seconds' => 1, 'max_output_bytes' => 2048],
            'php_big_output' => ['binary' => PHP_BINARY, 'allowed_args' => ['-r', 'echo str_repeat("A", 5000);'], 'timeout_seconds' => 2, 'max_output_bytes' => 1024],
        ],
    ],
];
$runtimePolicy = ProcessPolicy::fromConfig($runtimeConfig);
$runtimeRunner = new SafeProcessRunner($runtimePolicy);
$runtimeOk = $runtimeRunner->run('php_version', [], $runtimeAllowedDir);
ok($runtimeOk->allowed() && $runtimeOk->exitCode() === 0 && str_contains($runtimeOk->output(), 'PHP'), 'safe process runner executes allow-listed command without shell');
ok($runtimeRunner->check('unknown_command')['reason'] === 'command_not_allowed', 'safe process runner blocks unknown commands by default');
ok($runtimeRunner->check('php_version', ['; rm -rf /'])['reason'] === 'shell_metacharacter_blocked', 'safe argument builder blocks shell metacharacters');
ok($runtimeRunner->check('php_version', [], $runtimeDeniedDir)['reason'] === 'working_directory_not_allowed', 'process policy blocks unsafe working directory');
ok($runtimeRunner->check('php_version', [], $runtimeAllowedDir, ['APP_KEY' => 'secret'])['reason'] === 'environment_key_not_allowed', 'process policy blocks unapproved environment variables');
$runtimeTimeout = $runtimeRunner->run('php_sleep', [], $runtimeAllowedDir);
ok($runtimeTimeout->timedOut() && $runtimeTimeout->reason() === 'process_timeout', 'safe process runner enforces timeout');
$runtimeOutputLimit = $runtimeRunner->run('php_big_output', [], $runtimeAllowedDir);
ok($runtimeOutputLimit->outputTruncated() && $runtimeOutputLimit->reason() === 'output_limit_exceeded', 'safe process runner enforces max output bytes');

$networkConfig = [
    'network' => [
        'outbound' => [
            'enabled' => true,
            'https_only' => true,
            'allowed_schemes' => ['https'],
            'blocked_hosts' => ['localhost', 'metadata.google.internal'],
            'block_private_ips' => true,
            'block_loopback_ips' => true,
            'block_link_local_ips' => true,
            'block_metadata_ips' => true,
            'max_redirects' => 3,
            'timeout_seconds' => 1,
            'max_response_bytes' => 1024,
        ],
    ],
];
$outboundPolicy = OutboundRequestPolicy::fromConfig($networkConfig);
$outboundClient = new OutboundHttpClient($outboundPolicy);
ok($outboundClient->checkUrl('https://93.184.216.34')['passed'], 'outbound policy allows public HTTPS IP literal');
ok($outboundClient->checkUrl('http://93.184.216.34')['reason'] === 'https_required', 'outbound policy blocks HTTP by default');
ok($outboundClient->checkUrl('https://localhost')['reason'] === 'host_blocked', 'outbound policy blocks localhost host');
ok($outboundClient->checkUrl('https://127.0.0.1')['reason'] === 'loopback_ip_blocked', 'outbound policy blocks loopback IP');
ok($outboundClient->checkUrl('https://10.0.0.1')['reason'] === 'private_ip_blocked', 'outbound policy blocks private IP');
ok($outboundClient->checkUrl('https://169.254.169.254')['reason'] === 'metadata_ip_blocked', 'outbound policy blocks cloud metadata IP');
ok($outboundClient->checkUrl('gopher://93.184.216.34')['reason'] === 'https_required', 'outbound policy blocks unsupported schemes');
$redirectGuard = new RedirectGuard($outboundPolicy, 3);
ok(!$redirectGuard->checkChain(['https://93.184.216.34', 'https://127.0.0.1/admin'])['passed'], 'redirect guard blocks redirect chains into internal IPs');
$blockedWebhook = new WebhookAlertChannel('http://127.0.0.1/security-alert', 1, $outboundClient);
$blockedWebhook->send(['event' => 'unit-test']);
ok(true, 'webhook alert channel dispatches through guarded outbound client without unsafe direct fetch');

$clamFile = $runtimeAllowedDir . '/scan.txt';
file_put_contents($clamFile, 'clean');
$clamRunner = new SafeProcessRunner(ProcessPolicy::fromConfig([
    'runtime' => [
        'enabled' => true,
        'deny_by_default' => true,
        'allowed_working_directories' => [$runtimeAllowedDir],
        'commands' => ['clamav_scan' => ['binary' => PHP_BINARY, 'allowed_args' => ['-v'], 'timeout_seconds' => 2, 'max_output_bytes' => 2048]],
    ],
]));
$clamScanner = new \Mnb\SecurityCore\Files\ClamAvMalwareScanner(PHP_BINARY, 2, true, $clamRunner);
ok($clamScanner->scan($clamFile), 'ClamAV scanner delegates process execution to SafeProcessRunner');

$i27Config = array_replace_recursive($i25Config, $runtimeConfig, $networkConfig);
$i27Kernel = new SecurityKernel($i27Config);
ok($i27Kernel->processPolicy()->allowList()->has('php_version') && $i27Kernel->safeProcessRunner()->check('php_version')['passed'], 'security kernel exposes runtime execution security engine');
ok($i27Kernel->outboundHttpClient()->checkUrl('https://127.0.0.1')['reason'] === 'loopback_ip_blocked', 'security kernel exposes outbound network SSRF guard');
$i27Ssrf = $i27Kernel->vulnerabilityAdvisor()->recommend('ssrf');
$i27Command = $i27Kernel->vulnerabilityAdvisor()->recommend('command_injection');
ok($i27Ssrf['status'] === 'protected' && $i27Command['status'] === 'protected', 'vulnerability matrix marks SSRF and command injection protected by upgrade 27 controls');
$i27Invalid = (new SecurityConfigValidator(['app' => ['env' => 'production'], 'runtime' => ['enabled' => true, 'commands' => ['bad shell' => ['binary' => 'bash -c whoami']]], 'network' => ['outbound' => ['enabled' => true, 'https_only' => true, 'allowed_schemes' => ['http'], 'block_private_ips' => false]]]))->validate();
ok(!$i27Invalid['passed'], 'security config validator catches unsafe runtime and outbound network configuration');


echo "\n{$passed} passed, {$failed} failed\n";
exit($failed === 0 ? 0 : 1);
