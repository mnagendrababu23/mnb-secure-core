<?php
namespace Mnb\SecurityCore\Session;

final class SessionPolicy
{
    public function __construct(private array $config = []) {}
    public static function fromConfig(array $config): self { return new self(is_array($config['sessions'] ?? null) ? $config['sessions'] : []); }
    public function enabled(): bool { return (bool)($this->config['enabled'] ?? true); }
    public function registryStore(): string { return (string)($this->config['registry']['store'] ?? 'file'); }
    public function registryPath(): string { return (string)($this->config['registry']['path'] ?? 'storage/tokens/sessions'); }
    public function idleTimeout(): int { return (int)($this->config['timeouts']['idle_timeout_seconds'] ?? 1800); }
    public function absoluteTimeout(): int { return (int)($this->config['timeouts']['absolute_timeout_seconds'] ?? 43200); }
    public function rememberMeTimeout(): int { return (int)($this->config['timeouts']['remember_me_timeout_seconds'] ?? 2592000); }
    public function rotateOnLogin(): bool { return (bool)($this->config['rotation']['rotate_on_login'] ?? true); }
    public function maxSessionsPerUser(bool $admin=false): int { return (int)($admin ? ($this->config['concurrency']['max_admin_sessions_per_user'] ?? 2) : ($this->config['concurrency']['max_sessions_per_user'] ?? 5)); }
    public function whenExceeded(): string { return (string)($this->config['concurrency']['when_exceeded'] ?? 'revoke_oldest'); }
    public function validate(SessionRecord $record, ?string $currentFingerprint = null): SessionPolicyDecision
    {
        if (!$this->enabled()) { return SessionPolicyDecision::deny('sessions_disabled'); }
        if ($record->status() !== SessionStatus::ACTIVE) { return SessionPolicyDecision::deny('session_not_active', ['status'=>$record->status()]); }
        $now=time();
        if ($record->idleExpiresAt() !== null && $now >= $record->idleExpiresAt()) { return SessionPolicyDecision::deny('idle_timeout'); }
        if ($record->expiresAt() !== null && $now >= $record->expiresAt()) { return SessionPolicyDecision::deny('absolute_timeout'); }
        if ($record->fingerprint() !== null && $currentFingerprint !== null && !SessionFingerprint::matches($record->fingerprint(), $currentFingerprint)) { return SessionPolicyDecision::deny('session_fingerprint_mismatch'); }
        return SessionPolicyDecision::allow('session_valid');
    }
    public function toArray(): array { return $this->config; }
}
