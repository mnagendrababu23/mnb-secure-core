<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Authz\TenantGuard;
use Mnb\SecurityCore\Authz\PermissionGuard;
use Mnb\SecurityCore\Authz\PolicyRegistry;
use Mnb\SecurityCore\Authz\Policies\StudentPolicy;

demo_title('04. Authorization Strategy');

$context = new TenantContext(
    userId: 7,
    schoolId: 10,
    branchId: 2,
    academicYearId: 2026,
    roles: ['teacher'],
    permissions: ['student.view', 'attendance.mark'],
    classIds: [3],
    sectionIds: [1]
);

$allowedStudent = ['id' => 501, 'school_id' => 10, 'branch_id' => 2, 'academic_year_id' => 2026, 'class_id' => 3, 'section_id' => 1];
$otherSchoolStudent = ['id' => 999, 'school_id' => 11, 'branch_id' => 2, 'academic_year_id' => 2026, 'class_id' => 3, 'section_id' => 1];
$otherClassStudent = ['id' => 502, 'school_id' => 10, 'branch_id' => 2, 'academic_year_id' => 2026, 'class_id' => 4, 'section_id' => 1];

$permission = new PermissionGuard();
$tenant = new TenantGuard();
$policies = new PolicyRegistry();
$policies->register('student', new StudentPolicy($tenant));

demo_step('Teacher has student.view permission', $permission->can($context, 'student.view'));
demo_step('Allowed student belongs to context', $tenant->recordBelongsToContext($allowedStudent, $context));
demo_step('Other school student belongs to context', $tenant->recordBelongsToContext($otherSchoolStudent, $context));
demo_step('Other class student class allowed', $tenant->classSectionAllowed($otherClassStudent, $context));
demo_step('Policy allows view allowed student', $policies->allows($context, 'student', 'view', $allowedStudent));
demo_step('Policy allows delete allowed student', $policies->allows($context, 'student', 'delete', $allowedStudent));

demo_result(
    $policies->allows($context, 'student', 'view', $allowedStudent)
    && !$policies->allows($context, 'student', 'view', $otherSchoolStudent)
    && !$policies->allows($context, 'student', 'delete', $allowedStudent),
    'Authorization blocks cross-school, cross-class, and missing-permission access.'
);
