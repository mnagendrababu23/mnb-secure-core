<?php
namespace Mnb\SecurityCore\Session;

final class AdminSessionControl
{
    public function __construct(private SessionRevocationService $revocations, private DeviceSessionTracker $devices) {}
    public function revokeSession(string $sessionId): bool { return $this->revocations->revoke($sessionId, 'admin_revoke'); }
    public function revokeUser(string $userId): int { return $this->revocations->revokeUser($userId, 'admin_revoke'); }
    public function devices(string $userId): array { return $this->devices->devices($userId); }
}
