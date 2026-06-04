<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Auth\PasswordHasher;
use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Auth\Stores\FileTokenStore;
use Mnb\SecurityCore\Auth\Csrf;

demo_title('03. Authentication Strategy');

$hasher = new PasswordHasher();
$hash = $hasher->hash('StrongPassword@123');
demo_step('Password hash created', substr($hash, 0, 20) . '...');
demo_step('Correct password verifies', $hasher->verify('StrongPassword@123', $hash));
demo_step('Wrong password verifies', $hasher->verify('wrong-password', $hash));

$store = new FileTokenStore(demo_storage_path('tokens/auth-demo.json'));
$tokens = new OpaqueTokenService($store);
$issued = $tokens->issue(userId: 101, scopes: ['profile.read', 'attendance.read'], deviceId: 'device-1', deviceName: 'Parent Mobile', ttlSeconds: 3600);
$valid = $tokens->validate($issued['plain_token'], '127.0.0.1', 'Demo Agent');
$tokens->revoke($issued['plain_token']);
$revoked = $tokens->validate($issued['plain_token']);

demo_step('Opaque token issued one time', substr($issued['plain_token'], 0, 16) . '...');
demo_step('Token record stored as hash', substr($issued['record']['token_hash'], 0, 16) . '...');
demo_step('Token validates before revoke', $valid !== null);
demo_step('Token validates after revoke', $revoked !== null);

$csrf = new Csrf('_demo_csrf');
$csrfToken = $csrf->token();
demo_step('CSRF token verifies', $csrf->verify($csrfToken));

demo_result($hasher->verify('StrongPassword@123', $hash) && $valid !== null && $revoked === null && $csrf->verify($csrfToken), 'Password hashing, API token validation/revocation, and CSRF token flow are working.');
