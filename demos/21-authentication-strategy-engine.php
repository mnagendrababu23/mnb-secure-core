<?php
require __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Auth\AuthWorkflowService;
use Mnb\SecurityCore\Auth\AuthenticationRegistry;
use Mnb\SecurityCore\Auth\PasswordHasher;
use Mnb\SecurityCore\Auth\PasswordPolicy;
use Mnb\SecurityCore\Auth\UserProviderInterface;
use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Auth\Stores\FileTokenStore;
use Mnb\SecurityCore\Http\Middleware\AuthenticationMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;

$base = demo_storage_path('auth-strategy');
$hasher = new PasswordHasher();
$users = new class($hasher) implements UserProviderInterface {
    private array $user;
    public function __construct(private PasswordHasher $hasher) {
        $this->user = [
            'id' => 1001,
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

$audit = new SecurityAuditTrail(new TamperEvidentAuditLogger($base . '/audit.log'));
$tokens = new OpaqueTokenService(new FileTokenStore($base . '/tokens.json'), $audit);
$workflow = new AuthWorkflowService($users, $hasher, $tokens, $audit, new PasswordPolicy(['min_length' => 12]), ['ttl_seconds' => 3600]);
$login = $workflow->login('admin@example.com', 'CorrectHorseBatteryStaple!', ['uploads.write']);

$registry = new AuthenticationRegistry([
    'api_bearer' => ['type' => 'bearer', 'required' => true, 'scopes' => ['profile.read']],
    'admin_bearer' => ['type' => 'bearer', 'required' => true, 'roles' => ['admin']],
    'optional_bearer' => ['type' => 'bearer', 'required' => false],
]);

$request = new Request('GET', '/api/profile', [], [], [], [
    'REMOTE_ADDR' => '127.0.0.1',
    'HTTP_AUTHORIZATION' => 'Bearer ' . $login->plainToken(),
]);
$response = (new MiddlewarePipeline([
    new AuthenticationMiddleware($registry->get('admin_bearer'), $tokens, null, $audit),
]))->handle($request, fn(Request $request) => Response::json([
    'status' => true,
    'user_id' => $request->attribute('auth')->id(),
    'strategy' => $request->attribute('auth_strategy'),
]));

$optional = (new MiddlewarePipeline([
    new AuthenticationMiddleware($registry->get('optional_bearer'), $tokens, null, $audit),
]))->handle(new Request('GET', '/public'), fn(Request $request) => Response::json([
    'guest' => !$request->attribute('auth')->isAuthenticated(),
]));

demo_result($login->success(), 'Login workflow authenticates and issues a token.');
demo_result($response->status() === 200, 'Admin bearer authentication strategy allows admin token.');
demo_result(json_decode($optional->body(), true)['guest'] === true, 'Optional bearer strategy allows public guest requests.');

echo "Authentication Strategy Engine demo passed\n";
