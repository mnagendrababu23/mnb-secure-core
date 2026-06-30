<?php
namespace Mnb\SecurityCore\Session;

final class SessionRotationService
{
    public function __construct(private SessionManager $manager, private SessionRevocationService $revocations) {}
    public function rotate(SessionRecord $old, string $reason = 'rotation', ?SessionContext $context = null): array { $this->revocations->revoke($old->id(), 'revoked'); $new=$this->manager->create($old->userHash(), $context); return ['rotated'=>true,'old_session_id'=>$old->id(),'new_session'=>$new]; }
}
