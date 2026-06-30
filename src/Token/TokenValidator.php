<?php
namespace Mnb\SecurityCore\Token;

final class TokenValidator
{
    public function __construct(private TokenPolicy $policy, private TokenRevocationStoreInterface $revocations) {}
    public function validate(TokenRecord $record, ?string $currentFingerprint = null): TokenPolicyDecision
    {
        $policy = $this->policy->validate($record);
        if (!$policy->allowed()) { return $policy; }
        if ($this->revocations->isRevoked($record->id())) { return TokenPolicyDecision::deny('token_revoked'); }
        if ($record->fingerprint() !== null && $currentFingerprint !== null && !TokenFingerprint::matches($record->fingerprint(), $currentFingerprint)) { return TokenPolicyDecision::deny('token_fingerprint_mismatch'); }
        return TokenPolicyDecision::allow('token_valid', ['token_id'=>$record->id(),'type'=>$record->type()]);
    }
}
