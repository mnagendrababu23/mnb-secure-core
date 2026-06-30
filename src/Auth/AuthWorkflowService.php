<?php
namespace Mnb\SecurityCore\Auth;

use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Throwable;

class AuthWorkflowService
{
    public function __construct(
        private UserProviderInterface $users,
        private ?PasswordHasher $passwords = null,
        private ?OpaqueTokenService $tokens = null,
        private ?SecurityAuditTrail $audit = null,
        private ?PasswordPolicy $passwordPolicy = null,
        private array $config = []
    ) {
        $this->passwords ??= new PasswordHasher();
    }

    /** @param list<string> $scopes @param array<string,mixed> $context */
    public function login(string $identifier, string $password, array $scopes = [], ?int $ttlSeconds = null, ?string $deviceId = null, ?string $deviceName = null, array $context = []): AuthenticationResult
    {
        $generic = (string)($this->config['generic_failure_message'] ?? 'Invalid credentials');
        $fingerprint = SecurityAuditEvent::fingerprint(strtolower($identifier));
        $user = $this->users->findByIdentifier($identifier);
        if (!$user || !$this->users->isActive($user) || !$this->passwords->verify($password, $this->users->passwordHash($user))) {
            $this->audit?->loginFailure(['identifier_fingerprint' => $fingerprint], $context, ['reason' => !$user ? 'not_found' : (!$this->users->isActive($user) ? 'inactive' : 'password_mismatch')]);
            return AuthenticationResult::failure($generic, 'invalid_credentials', 401);
        }

        $providerScopes = $this->users->scopes($user);
        $issuedScopes = $scopes !== [] ? array_values(array_unique(array_merge($providerScopes, $scopes))) : $providerScopes;
        $token = null;
        $record = null;
        if ($this->tokens !== null) {
            $issued = $this->tokens->issue($this->users->userId($user), $issuedScopes, $deviceId, $deviceName, $ttlSeconds ?? (int)($this->config['ttl_seconds'] ?? 2592000), $this->users->permissions($user), $this->users->roles($user));
            $token = $issued['plain_token'];
            $record = $issued['record'];
            $record['permissions'] = $this->users->permissions($user);
            $record['roles'] = $this->users->roles($user);
        }

        $auth = new AuthContext(
            true,
            $this->users->userId($user),
            $issuedScopes,
            $this->users->permissions($user),
            $this->users->roles($user),
            $record,
            ['source' => 'login']
        );
        $this->audit?->loginSuccess(['user_id' => $auth->id()], $context, ['scope_count' => count($issuedScopes)]);
        return AuthenticationResult::authenticated($auth, $token, $record, ['expires_at' => $record['expires_at'] ?? null]);
    }

    /** @param array<string,mixed> $data @param callable(array<string,mixed>):array<string,mixed> $creator @param array<string,mixed> $context */
    public function register(array $data, callable $creator, array $context = []): AuthenticationResult
    {
        try {
            if ($this->passwordPolicy && isset($data['password']) && is_string($data['password'])) {
                $policy = $this->passwordPolicy->validate($data['password'], $data);
                if ($policy->failed()) {
                    $this->audit?->record(SecurityAuditEvent::make(SecurityAuditEvent::CATEGORY_AUTH, 'register', SecurityAuditEvent::OUTCOME_FAILURE, SecurityAuditEvent::SEVERITY_WARNING, [], [], $context, ['reason' => 'password_policy_failed']));
                    return AuthenticationResult::failure('Registration failed', 'password_policy_failed', 422, $policy->errors());
                }
            }
            $user = $creator($data);
            $auth = new AuthContext(true, $this->users->userId($user), $this->users->scopes($user), $this->users->permissions($user), $this->users->roles($user), null, ['source' => 'register']);
            $this->audit?->record(SecurityAuditEvent::make(SecurityAuditEvent::CATEGORY_AUTH, 'register', SecurityAuditEvent::OUTCOME_SUCCESS, SecurityAuditEvent::SEVERITY_INFO, ['user_id' => $auth->id()], [], $context));
            return AuthenticationResult::authenticated($auth);
        } catch (Throwable $e) {
            $this->audit?->record(SecurityAuditEvent::make(SecurityAuditEvent::CATEGORY_AUTH, 'register', SecurityAuditEvent::OUTCOME_FAILURE, SecurityAuditEvent::SEVERITY_WARNING, [], [], $context, ['reason' => 'exception', 'exception' => $e::class]));
            return AuthenticationResult::failure('Registration failed', 'registration_failed', 400);
        }
    }
}
