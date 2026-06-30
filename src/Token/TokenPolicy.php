<?php
namespace Mnb\SecurityCore\Token;

final class TokenPolicy
{
    public function __construct(private array $config = []) {}
    public static function fromConfig(array $config): self { return new self(is_array($config['tokens'] ?? null) ? $config['tokens'] : []); }
    public function enabled(): bool { return (bool)($this->config['enabled'] ?? true); }
    public function accessTtl(): int { return (int)($this->config['access_tokens']['ttl_seconds'] ?? 900); }
    public function refreshTtl(): int { return (int)($this->config['refresh_tokens']['ttl_seconds'] ?? 2592000); }
    public function apiTtl(): int { return (int)($this->config['api_tokens']['ttl_seconds'] ?? 7776000); }
    public function requireJti(): bool { return (bool)($this->config['access_tokens']['require_jti'] ?? true); }
    public function refreshRotationEnabled(): bool { return (bool)($this->config['refresh_tokens']['rotation_enabled'] ?? true); }
    public function reuseDetectionEnabled(): bool { return (bool)($this->config['refresh_tokens']['reuse_detection_enabled'] ?? true); }
    public function revokeFamilyOnReuse(): bool { return (bool)($this->config['refresh_tokens']['revoke_family_on_reuse'] ?? true); }
    public function maxFamilySize(): int { return (int)($this->config['refresh_tokens']['max_family_size'] ?? 50); }
    public function revocationStore(): string { return (string)($this->config['revocation']['store'] ?? 'file'); }
    public function revocationPath(): string { return (string)($this->config['revocation']['path'] ?? 'storage/tokens/revoked'); }
    public function cleanupExpired(): bool { return (bool)($this->config['revocation']['cleanup_expired_records'] ?? true); }
    public function validate(TokenRecord $record): TokenPolicyDecision
    {
        if (!$this->enabled()) { return TokenPolicyDecision::deny('tokens_disabled'); }
        if ($record->isExpired()) { return TokenPolicyDecision::deny('token_expired'); }
        if (!$record->isActive()) { return TokenPolicyDecision::deny('token_not_active', ['status'=>$record->status()]); }
        return TokenPolicyDecision::allow('token_policy_passed', ['type'=>$record->type()]);
    }
    public function toArray(): array { return $this->config; }
}
