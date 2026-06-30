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
use Mnb\SecurityCore\Env\SecretScanner;
use Mnb\SecurityCore\Exceptions\SecurityException;
use Mnb\SecurityCore\Files\FileUploadPolicy;
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
use Mnb\SecurityCore\RateLimit\DatabaseRateLimiter;
use Mnb\SecurityCore\RateLimit\FileRateLimiter;
use Mnb\SecurityCore\RateLimit\RateLimitPolicy;
use Mnb\SecurityCore\RateLimit\RateLimitPolicyRegistry;
use Mnb\SecurityCore\Security\ProductionSecurityChecker;
use Mnb\SecurityCore\Security\CspNonceManager;
use Mnb\SecurityCore\Security\SecurityConfigValidator;
use Mnb\SecurityCore\Security\SecurityDoctor;
use Mnb\SecurityCore\Security\VulnerabilityMatrix;
use Mnb\SecurityCore\Quickstart\FirstTokenBootstrapper;
use Mnb\SecurityCore\Pentest\PentestChecklist;
use Mnb\SecurityCore\Pentest\PayloadLibrary;
use Mnb\SecurityCore\Pentest\PentestFinding;
use Mnb\SecurityCore\Pentest\PentestReportBuilder;
use Mnb\SecurityCore\Pentest\RemediationTracker;
use Mnb\SecurityCore\Pentest\RiskRating;
use Mnb\SecurityCore\Pentest\VerificationMatrix;
use Mnb\SecurityCore\Errors\SafeErrorHandler;
use Mnb\SecurityCore\Exceptions\AppException;
use Mnb\SecurityCore\Exceptions\AuthorizationException;
use Mnb\SecurityCore\Http\Middleware\ErrorHandlingMiddleware;
use Mnb\SecurityCore\Logging\FileLogger;
use Mnb\SecurityCore\Memory\MemoryConfig;
use Mnb\SecurityCore\Memory\MemoryGuard;
use Mnb\SecurityCore\Memory\MemoryMonitor;
use Mnb\SecurityCore\Memory\ChunkProcessor;
use Mnb\SecurityCore\Memory\ResourceTracker;
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

echo "\n{$passed} passed, {$failed} failed\n";
exit($failed === 0 ? 0 : 1);
