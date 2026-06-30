<?php
namespace Mnb\SecurityCore\Session;

final class ConcurrentSessionLimiter
{
    public function __construct(private SessionPolicy $policy, private SessionRegistryInterface $registry) {}
    public function enforce(string $userId, bool $admin = false): array
    {
        $sessions = array_values(array_filter($this->registry->forUserHash(SessionRecord::hashUser($userId)), fn(SessionRecord $r)=>$r->status()===SessionStatus::ACTIVE));
        $max = $this->policy->maxSessionsPerUser($admin); $revoked=[];
        if (count($sessions) > $max && $this->policy->whenExceeded() === 'revoke_oldest') {
            usort($sessions, fn(SessionRecord $a, SessionRecord $b)=>$a->createdAt() <=> $b->createdAt());
            while (count($sessions) > $max) { $old=array_shift($sessions); if ($old) { $this->registry->revoke($old->id(), 'concurrent_limit'); $revoked[]=$old->id(); } }
        }
        return ['passed'=>count($sessions) <= $max,'max_sessions'=>$max,'active_sessions'=>count($sessions),'revoked'=>$revoked];
    }
}
