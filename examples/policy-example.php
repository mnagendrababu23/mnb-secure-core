<?php
require __DIR__ . '/bootstrap.php';

use Mnb\SecurityCore\Authz\Policies\StudentPolicy;
use Mnb\SecurityCore\Authz\PolicyRegistry;
use Mnb\SecurityCore\Authz\TenantContext;

$context = new TenantContext(userId: 1, schoolId: 1, branchId: 1, academicYearId: 2026, permissions: ['student.view']);
$student = ['id' => 12, 'school_id' => 1, 'branch_id' => 1, 'academic_year_id' => 2026];

$policies = new PolicyRegistry();
$policies->register('student', new StudentPolicy());
var_dump($policies->allows($context, 'student', 'view', $student));
