<?php
namespace Mnb\SecurityCore\Session;

final class SessionRevocationService
{
    public function __construct(private SessionRegistryInterface $registry) {}
    public function revoke(string $sessionId, string $reason = 'revoked'): bool { return $this->registry->revoke($sessionId, $reason); }
    public function revokeUser(string $userId, string $reason = 'forced_logout'): int { $n=0; foreach ($this->registry->forUserHash(SessionRecord::hashUser($userId)) as $r) { if ($this->registry->revoke($r->id(), $reason)) $n++; } return $n; }
}
