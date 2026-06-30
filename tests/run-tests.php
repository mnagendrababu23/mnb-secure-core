<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Auth\AuthContext;
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
use Mnb\SecurityCore\Files\HeuristicMalwareScanner;
use Mnb\SecurityCore\Http\Middleware\ApiTokenMiddleware;
use Mnb\SecurityCore\Http\Middleware\HttpsMiddleware;
use Mnb\SecurityCore\Http\Middleware\SecurityHeadersMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;
use Mnb\SecurityCore\RateLimit\DatabaseRateLimiter;
use Mnb\SecurityCore\RateLimit\FileRateLimiter;
use Mnb\SecurityCore\Security\ProductionSecurityChecker;
use Mnb\SecurityCore\Security\VulnerabilityMatrix;
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

$cache = new FileCache($base . '/cache');
$cache->put('school_settings', ['x' => 1], 60);
ok($cache->get('school_settings')['x'] === 1, 'file cache put/get');

$context = new TenantContext(userId: 1, schoolId: 10, branchId: 5, academicYearId: 2026, permissions: ['student.view'], classIds: [3]);
$tenant = new TenantGuard();
ok($tenant->recordBelongsToContext(['school_id' => 10, 'branch_id' => 5, 'academic_year_id' => 2026], $context), 'tenant guard allows matching record');
ok(!$tenant->recordBelongsToContext(['school_id' => 11, 'branch_id' => 5, 'academic_year_id' => 2026], $context), 'tenant guard blocks other school');
ok($tenant->classSectionAllowed(['class_id' => 3], $context) && !$tenant->classSectionAllowed(['class_id' => 4], $context), 'tenant guard class scope');

$registry = new PolicyRegistry();
$registry->register('student', new StudentPolicy());
ok($registry->allows($context, 'student', 'view', ['school_id' => 10, 'branch_id' => 5, 'academic_year_id' => 2026, 'class_id' => 3]), 'student policy allows scoped view');
ok(!$registry->allows($context, 'student', 'delete', ['school_id' => 10, 'branch_id' => 5, 'academic_year_id' => 2026, 'class_id' => 3]), 'student policy blocks missing permission');

$tokenStore = new FileTokenStore($base . '/tokens/tokens.json');
$tokenService = new OpaqueTokenService($tokenStore);
$issued = $tokenService->issue(99, ['profile.read'], 'device1', 'Phone', 60);
ok($tokenService->validate($issued['plain_token']) !== null, 'opaque token validates');
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

$headersPipeline = new MiddlewarePipeline([new SecurityHeadersMiddleware(['hsts' => true])]);
$headersResponse = $headersPipeline->handle(new Request('GET', '/', [], [], [], ['HTTPS' => 'on']), fn() => Response::text('ok'));
ok(isset($headersResponse->headers()['Content-Security-Policy']) && isset($headersResponse->headers()['Strict-Transport-Security']), 'security headers middleware applies CSP and HSTS');

$request = new Request('GET', '/', [], [], [], ['HTTPS' => 'off']);
$pipeline = new MiddlewarePipeline([new HttpsMiddleware(true)]);
$response = $pipeline->handle($request, fn() => Response::text('ok'));
ok($response->status() === 403, 'middleware pipeline blocks insecure request');

$spoofedForwardedHttps = new Request('GET', '/', [], [], [], ['HTTPS' => 'off', 'HTTP_X_FORWARDED_PROTO' => 'https', 'REMOTE_ADDR' => '203.0.113.10']);
ok(!$spoofedForwardedHttps->isSecure(), 'request ignores spoofed forwarded HTTPS from untrusted clients');

$trustedForwardedHttps = new Request('GET', '/', [], [], [], ['HTTPS' => 'off', 'HTTP_X_FORWARDED_PROTO' => 'https', 'REMOTE_ADDR' => '203.0.113.10'], ['203.0.113.0/24']);
ok($trustedForwardedHttps->isSecure(), 'request trusts forwarded HTTPS only from trusted proxy ranges');

$attributedRequest = $request->withAttribute('auth_user_id', 99);
ok($request->attribute('auth_user_id') === null && $attributedRequest->attribute('auth_user_id') === 99, 'request attributes are immutable and available for auth context');

$checker = new ProductionSecurityChecker([
    'app' => ['env' => 'production', 'debug' => true, 'force_https' => false, 'key' => 'weak', 'trusted_hosts' => []],
    'cookies' => ['secure' => false, 'http_only' => false],
    'paths' => ['private_storage' => '/var/www/public/uploads']
]);
$report = $checker->check();
ok(!$report['passed'] && count($report['issues']) >= 4, 'production checker catches unsafe config');

$audit = new TamperEvidentAuditLogger($base . '/audit/audit.log');
$audit->record('fee.updated', ['user_id' => 1, 'token' => 'secret'], ['fee_id' => 5]);
$audit->record('marks.updated', ['user_id' => 2], ['student_id' => 6]);
ok($audit->verify(), 'tamper-evident audit log verifies');
file_put_contents($base . '/audit/audit.log', str_replace('fee.updated', 'fee.deleted', file_get_contents($base . '/audit/audit.log')));
ok(!$audit->verify(), 'tamper-evident audit detects tampering');

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

echo "\n{$passed} passed, {$failed} failed\n";
exit($failed === 0 ? 0 : 1);
