<?php
namespace Mnb\SecurityCore\Token;

final class RefreshTokenRotator
{
    public function __construct(private TokenPolicy $policy, private TokenRevocationService $revocations) {}
    public function rotate(TokenRecord $oldToken): array
    {
        if ($oldToken->type() !== TokenType::REFRESH) { return ['rotated'=>false,'reason'=>'not_refresh_token']; }
        if (!$this->policy->refreshRotationEnabled()) { return ['rotated'=>false,'reason'=>'rotation_disabled']; }
        $this->revocations->revoke($oldToken, TokenRevocationReason::LOGOUT);
        $family = $oldToken->familyId() ?: ('fam_' . bin2hex(random_bytes(12)));
        $new = TokenRecord::issue(TokenType::REFRESH, $oldToken->userHash(), $this->policy->refreshTtl(), $family, ['rotated_from'=>$oldToken->id()]);
        return ['rotated'=>true,'old_token_id'=>$oldToken->id(),'new_token'=>$new];
    }
}
