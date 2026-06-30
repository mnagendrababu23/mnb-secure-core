<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Session\InMemorySessionRegistry;
use Mnb\SecurityCore\Session\SessionContext;
use Mnb\SecurityCore\Token\InMemoryTokenRevocationStore;
use Mnb\SecurityCore\Token\TokenRecord;
use Mnb\SecurityCore\Token\TokenRevocationReason;
use Mnb\SecurityCore\Token\TokenType;
use Mnb\SecurityCore\Vulnerability\VulnerabilityControlMapper;

$config = require __DIR__ . '/../config/security.php';
$config['tokens']['revocation']['store'] = 'memory';
$config['sessions']['registry']['store'] = 'memory';
$config['sessions']['concurrency']['max_sessions_per_user'] = 2;

$kernel = new SecurityKernel($config);
$tokenStore = new InMemoryTokenRevocationStore();
$sessionRegistry = new InMemorySessionRegistry();

$access = TokenRecord::issue(TokenType::ACCESS, 'demo-user', $kernel->tokenPolicy()->accessTtl());
$activeBefore = $kernel->tokenValidator($tokenStore)->validate($access)->allowed();
$kernel->tokenRevocationService($tokenStore)->revoke($access, TokenRevocationReason::LOGOUT, 'demo');
$activeAfter = $kernel->tokenValidator($tokenStore)->validate($access)->allowed();

$refresh = TokenRecord::issue(TokenType::REFRESH, 'demo-user', $kernel->tokenPolicy()->refreshTtl(), 'fam_demo');
$rotation = $kernel->refreshTokenRotator($tokenStore)->rotate($refresh);
$reuse = $kernel->refreshTokenReuseDetector($tokenStore)->detect($refresh);

$context = new SessionContext('198.51.100.10', 'DemoBrowser/1.0');
$manager = $kernel->sessionManager($sessionRegistry);
$session = $manager->create('demo-user', $context);
$rotated = $kernel->sessionRotationService($sessionRegistry)->rotate($session, 'login', $context);
$manager->create('demo-user', $context);
$manager->create('demo-user', $context);
$concurrency = $kernel->concurrentSessionLimiter($sessionRegistry)->enforce('demo-user');
$forced = $kernel->forcedLogoutService($sessionRegistry)->forceUser('demo-user', 'password_changed');

$remember = $kernel->rememberMeTokenManager();
$rememberIssued = $remember->issue('demo-user', $kernel->sessionPolicy()->rememberMeTimeout());
$rememberRotated = $remember->rotate($rememberIssued['id'], $rememberIssued['token'], $kernel->sessionPolicy()->rememberMeTimeout());

$matrix = (new VulnerabilityControlMapper($config))->definitions();

$report = [
    'title' => 'MNB Secure Core v1.0.1 — Token Revocation and Session Control Engine',
    'token_policy_loaded' => $kernel->tokenPolicy()->toArray(),
    'access_token_active_before_revoke' => $activeBefore,
    'access_token_active_after_revoke' => $activeAfter,
    'refresh_token_rotated' => $rotation['rotated'],
    'refresh_reuse_detected' => $reuse,
    'session_created' => $session->toArray(),
    'session_rotated' => ['rotated' => $rotated['rotated'], 'old_session_id' => $rotated['old_session_id'], 'new_session_id' => $rotated['new_session']->id()],
    'concurrent_session_limit' => $concurrency,
    'forced_logout' => $forced,
    'remember_me_rotated' => is_array($rememberRotated),
    'device_sessions' => $kernel->deviceSessionTracker($sessionRegistry)->devices('demo-user'),
    'matrix' => [
        'stolen_token_reuse' => $matrix['stolen_token_reuse']->status() ?? 'missing',
        'refresh_token_replay' => $matrix['refresh_token_replay']->status() ?? 'missing',
        'session_fixation' => $matrix['session_fixation']->status() ?? 'missing',
        'unrevoked_session' => $matrix['unrevoked_session']->status() ?? 'missing',
    ],
];

echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
