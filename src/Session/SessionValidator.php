<?php
namespace Mnb\SecurityCore\Session;

final class SessionValidator
{
    public function __construct(private SessionPolicy $policy) {}
    public function validate(?SessionRecord $record, ?string $currentFingerprint = null): SessionPolicyDecision { return $record === null ? SessionPolicyDecision::deny('session_not_found') : $this->policy->validate($record, $currentFingerprint); }
}
