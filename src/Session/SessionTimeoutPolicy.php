<?php
namespace Mnb\SecurityCore\Session;

final class SessionTimeoutPolicy
{
    public function __construct(private SessionPolicy $policy) {}
    public function evaluate(SessionRecord $record): array
    {
        $now=time();
        if ($record->idleExpiresAt() !== null && $now >= $record->idleExpiresAt()) return ['active'=>false,'reason'=>'idle_timeout'];
        if ($record->expiresAt() !== null && $now >= $record->expiresAt()) return ['active'=>false,'reason'=>'absolute_timeout'];
        return ['active'=>true,'reason'=>'ok'];
    }
}
