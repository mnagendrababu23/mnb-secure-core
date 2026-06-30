<?php
namespace Mnb\SecurityCore\Token;

final class RefreshTokenReuseDetector
{
    public function __construct(private TokenRevocationStoreInterface $revocations, private TokenPolicy $policy) {}
    public function detect(TokenRecord $token): array
    {
        $reused = $token->type() === TokenType::REFRESH && $this->policy->reuseDetectionEnabled() && $this->revocations->isRevoked($token->id());
        return ['reused'=>$reused,'token_id'=>$token->id(),'family_id'=>$token->familyId(),'action'=>$reused && $this->policy->revokeFamilyOnReuse() ? 'revoke_family' : 'none'];
    }
}
