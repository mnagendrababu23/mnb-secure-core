<?php
namespace Mnb\SecurityCore\Session;

final class SessionManager
{
    public function __construct(private SessionPolicy $policy, private SessionRegistryInterface $registry) {}
    public function create(string $userId, ?SessionContext $context = null): SessionRecord { $record=SessionRecord::create($userId,$this->policy->idleTimeout(),$this->policy->absoluteTimeout(),$context); $this->registry->save($record); return $record; }
    public function touch(string $sessionId): ?SessionRecord { $record=$this->registry->find($sessionId); if (!$record) return null; $record=$record->touched($this->policy->idleTimeout()); $this->registry->save($record); return $record; }
    public function list(?string $userId = null): array { $records=$userId===null?$this->registry->all():$this->registry->forUserHash(SessionRecord::hashUser($userId)); return array_map(fn(SessionRecord $r)=>$r->toArray(), $records); }
}
