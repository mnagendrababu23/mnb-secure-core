<?php
namespace Mnb\SecurityCore\Session;

final class DeviceSessionTracker
{
    public function __construct(private SessionRegistryInterface $registry) {}
    public function devices(string $userId): array { return array_map(fn(SessionRecord $r)=>['session_id'=>$r->id(),'status'=>$r->status(),'fingerprint'=>$r->fingerprint(),'last_seen_at'=>$r->lastSeenAt()], $this->registry->forUserHash(SessionRecord::hashUser($userId))); }
}
