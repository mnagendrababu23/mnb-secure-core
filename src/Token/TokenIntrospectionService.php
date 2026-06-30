<?php
namespace Mnb\SecurityCore\Token;

final class TokenIntrospectionService
{
    public function __construct(private TokenValidator $validator) {}
    public function introspect(?TokenRecord $record): array
    {
        if ($record === null) { return ['active'=>false,'status'=>'unknown','safe_reason'=>'token_not_found']; }
        $decision = $this->validator->validate($record);
        return ['active'=>$decision->allowed(),'status'=>$decision->allowed()?TokenStatus::ACTIVE:'inactive','safe_reason'=>$decision->reason(),'token_type'=>$record->type(),'expires_at'=>$record->expiresAt() ? date('c', $record->expiresAt()) : null];
    }
}
