<?php
namespace Mnb\SecurityCore\Session;

final class ForcedLogoutService
{
    public function __construct(private SessionRevocationService $revocations) {}
    public function forceUser(string $userId, string $reason = 'security_incident'): array { $count=$this->revocations->revokeUser($userId, 'forced_logout'); return ['forced_logout'=>true,'user_hash'=>SessionRecord::hashUser($userId),'revoked_sessions'=>$count,'reason'=>$reason]; }
}
