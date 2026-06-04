<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Pentest\PentestChecklist;
use Mnb\SecurityCore\Pentest\PentestFinding;
use Mnb\SecurityCore\Pentest\PentestReportBuilder;
use Mnb\SecurityCore\Pentest\PayloadLibrary;
use Mnb\SecurityCore\Pentest\RemediationTracker;
use Mnb\SecurityCore\Pentest\RiskRating;
use Mnb\SecurityCore\Pentest\VerificationMatrix;

demo_title('15. Penetration Testing, Security Verification, and Remediation');

$payloads = new PayloadLibrary();
demo_step('Payload categories', $payloads->categories());
demo_step('SQL injection payload sample count', count($payloads->get('sql_injection')));

$checklist = new PentestChecklist();
$cases = $checklist->all();
demo_step('Reusable pentest checklist cases', count($cases));
demo_step('First test case', $cases[0]->toArray());

$matrix = (new VerificationMatrix())->all();
demo_step('Concept 15 verification matrix includes secure database', $matrix['Secure Database Operations'] ?? []);

$finding = new PentestFinding(
    id: 'BOSS-API-001',
    title: 'Parent can access another student attendance by changing student_id',
    severity: RiskRating::CRITICAL,
    affectedTarget: '/api/v1/attendance?student_id=OTHER',
    affectedRole: 'Parent',
    stepsToReproduce: [
        'Login as Parent A',
        'Open own child attendance request',
        'Change student_id to another student',
        'Observe whether data is returned',
    ],
    payloads: ['student_id=9999'],
    businessImpact: 'Cross-account child privacy breach and school data exposure.',
    technicalImpact: 'Broken object-level authorization / IDOR.',
    recommendedFix: 'Apply TenantGuard plus parent-child ownership policy before returning attendance data.',
    evidence: ['Expected secure result: 403 and audit denied event']
);

$tracker = new RemediationTracker();
$tracker->addFinding($finding, 'Backend Security Owner', date('Y-m-d', strtotime('+7 days')));
$tracker->updateStatus('BOSS-API-001', 'In Progress', 'Ownership policy added; awaiting retest.');
demo_step('Remediation summary', $tracker->summary());

$report = (new PentestReportBuilder())->buildMarkdown(
    'BOSS for Schools Demo',
    ['Web admin panel', 'Parent/student API', 'Secure database layer'],
    [$finding],
    ['environment' => 'staging', 'tester' => 'internal-security']
);
$reportPath = demo_storage_path('pentest/demo-report.md');
file_put_contents($reportPath, $report);
demo_step('Pentest report generated', $reportPath);

demo_result(
    count($cases) >= 10
    && isset($matrix['Penetration Testing and Security Verification'])
    && $finding->riskScore() === 10
    && is_file($reportPath),
    'Penetration testing checklist, payloads, verification matrix, findings, remediation tracking, and report generation are working.'
);
