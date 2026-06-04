<?php
require __DIR__ . '/bootstrap.php';

use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Authz\TenantGuard;

$context = new TenantContext(userId: 10, schoolId: 1, branchId: 2, academicYearId: 2026, permissions: ['student.view']);
$student = ['id' => 55, 'school_id' => 1, 'branch_id' => 2, 'academic_year_id' => 2026];

$allowed = (new TenantGuard())->recordBelongsToContext($student, $context);
var_dump($allowed); // true
