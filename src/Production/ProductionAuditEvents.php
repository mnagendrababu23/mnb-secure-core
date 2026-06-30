<?php
namespace Mnb\SecurityCore\Production;

final class ProductionAuditEvents
{
    public const READINESS_CHECKED = 'production.readiness.checked';
    public const RELEASE_PLAN_CREATED = 'production.release_plan.created';
    public const ENV_CHECKLIST_CREATED = 'production.env_checklist.created';
    public const FINAL_GATE_PASSED = 'production.final_gate.passed';
    public const FINAL_GATE_BLOCKED = 'production.final_gate.blocked';
}
