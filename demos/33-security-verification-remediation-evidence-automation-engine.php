<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Pentest\EvidenceCollector;
use Mnb\SecurityCore\Pentest\PentestFinding;
use Mnb\SecurityCore\Pentest\ReleaseGatePolicy;
use Mnb\SecurityCore\Pentest\RemediationPlan;
use Mnb\SecurityCore\Pentest\RemediationPolicy;
use Mnb\SecurityCore\Pentest\RetestResult;
use Mnb\SecurityCore\Pentest\RetestGate;
use Mnb\SecurityCore\Pentest\RiskRating;
use Mnb\SecurityCore\Pentest\SecurityCoverageAnalyzer;
use Mnb\SecurityCore\Pentest\SecurityReleaseGate;
use Mnb\SecurityCore\Pentest\SecurityVerificationRunner;
use Mnb\SecurityCore\Pentest\VerificationMatrix;
use Mnb\SecurityCore\Pentest\VerificationProfile;
use Mnb\SecurityCore\Pentest\VerificationResult;
use Mnb\SecurityCore\Pentest\VerificationTarget;

demo_title('33. Security Verification, Remediation, and Evidence Automation Engine');

$config = require __DIR__ . '/../config/security.php';
$profile = VerificationProfile::fromConfig($config, 'production_release');
$target = VerificationTarget::application('Demo Application', 'https://app.example.test');
demo_step('Verification profile loaded', $profile->toArray());
demo_step('Verification target created', $target->toArray());

$collector = new EvidenceCollector();
$collector->collect('http_response', 'blocked request sample', [
    'headers' => [
        'Authorization' => 'Bearer demo-super-secret-token',
        'Cookie' => 'sid=secret-cookie',
    ],
    'body' => 'password=secret token=abc123 /var/www/private/app.php',
]);
$bundle = $collector->bundle(['test_id' => 'PT-REL-001']);
demo_step('Evidence collected and redacted', $bundle->toArray());

$runner = new SecurityVerificationRunner(null, $collector);
$failed = $runner->verify('PT-REL-001', $target, VerificationResult::FAILED, $bundle->items, 'Open Critical finding blocks release.');
demo_step('Failed verification result recorded', $failed->toArray());

$finding = $runner->findingFromResult($failed);
demo_step('Finding created from failed verification', $finding?->toArray());

$remediationPolicy = RemediationPolicy::fromConfig($config);
$plan = RemediationPlan::fromFinding($finding, $remediationPolicy, ['PT-REL-001']);
demo_step('Remediation SLA plan generated', $plan->toArray());

$retestGate = new RetestGate($remediationPolicy);
$withoutRetest = $retestGate->canClose(new PentestFinding($finding->id, $finding->title, $finding->severity, $finding->affectedTarget, $finding->affectedRole, $finding->stepsToReproduce, $finding->payloads, $finding->businessImpact, $finding->technicalImpact, $finding->recommendedFix, 'Fixed'));
$withRetest = $retestGate->canClose(new PentestFinding($finding->id, $finding->title, $finding->severity, $finding->affectedTarget, $finding->affectedRole, $finding->stepsToReproduce, $finding->payloads, $finding->businessImpact, $finding->technicalImpact, $finding->recommendedFix, 'Fixed'), RetestResult::pass($finding->id, [$failed], $bundle->items, 'Control retested successfully.'));
demo_step('Retest gate blocks closure until evidence exists', ['without_retest' => $withoutRetest, 'with_retest' => $withRetest]);

$run = $runner->runProfile($profile, $target, VerificationResult::PASSED);
$coverage = (new SecurityCoverageAnalyzer(new VerificationMatrix()))->analyze($run->results(), $profile);
demo_step('Coverage report generated', $coverage->toArray());

$gate = new SecurityReleaseGate(ReleaseGatePolicy::fromConfig($config));
$blocked = $gate->evaluate([$finding], $run)->toArray();
$passed = $gate->evaluate([], $run)->toArray();
demo_step('Release gate blocks open Critical finding', $blocked);
demo_step('Release gate passes after remediation/retest inputs are clean', $passed);

demo_result(
    $bundle->count() === 1
    && $failed->failed()
    && $finding !== null
    && $plan->dueDate !== null
    && !$withoutRetest['passed']
    && $withRetest['passed']
    && $coverage->overallCoverage >= 90
    && !$blocked['passed']
    && $passed['passed'],
    'Security verification, redacted evidence, remediation SLA, retest gate, coverage analysis, and release gate automation are working.'
);
