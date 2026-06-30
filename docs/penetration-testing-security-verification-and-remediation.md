# Penetration Testing, Security Verification, and Remediation

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Document:** Detailed feature documentation and code usage  
**Feature area:** Penetration Testing, Security Verification, Evidence, Remediation, Retest, Coverage, and Release Gates

---

## 1. Purpose

The Penetration Testing, Security Verification, and Remediation feature helps teams prove that security controls are working, record evidence, track failed checks as findings, assign remediation, retest fixes, and block unsafe releases.

It is not designed to be an aggressive exploitation framework. It is a safe verification and governance layer for application security controls.

It helps answer:

```text
Which security controls exist?
Which controls have been verified?
What failed?
What evidence proves the result?
Who owns remediation?
Can this release safely go to production?
```

This feature is useful for:

```text
Internal security reviews
Pre-release security checks
CI/CD security gates
Manual penetration testing support
Security evidence collection
Remediation planning
Retest workflow
Production readiness approval
```

---

## 2. What this feature protects against

This feature helps detect and manage risks such as:

```text
Unverified security controls
Missing security evidence
Open Critical/High findings
Security fixes closed without retesting
Release with known vulnerabilities
Weak remediation ownership
Forgotten penetration testing checklist items
Missing coverage for new security engines
Unsafe payload testing without controlled records
```

It supports verification for controls such as:

```text
Authentication
Authorization
Tenant isolation
SQL injection protection
XSS protection
CSRF protection
File upload security
API security
Rate limiting
Database governance
Runtime command security
Outbound network / SSRF protection
Safe error responses
Memory/resource safety
Throughput/capacity management
Origin protection
Queue/background jobs
Token/session revocation
```

---

## 3. Main classes

Core classes include:

```text
Mnb\SecureCore\Pentest\PayloadLibrary
Mnb\SecureCore\Pentest\PentestChecklist
Mnb\SecureCore\Pentest\SecurityTestCase
Mnb\SecureCore\Pentest\PentestFinding
Mnb\SecureCore\Pentest\PentestReportBuilder
Mnb\SecureCore\Pentest\RemediationTracker
Mnb\SecureCore\Pentest\RiskRating
Mnb\SecureCore\Pentest\VerificationMatrix
```

Upgrade 29 adds the verification and evidence workflow classes:

```text
Mnb\SecureCore\Pentest\VerificationProfile
Mnb\SecureCore\Pentest\VerificationTarget
Mnb\SecureCore\Pentest\VerificationRun
Mnb\SecureCore\Pentest\VerificationResult
Mnb\SecureCore\Pentest\SecurityVerificationRunner
Mnb\SecureCore\Pentest\SecurityVerificationRegistry
Mnb\SecureCore\Pentest\EvidenceItem
Mnb\SecureCore\Pentest\EvidenceCollector
Mnb\SecureCore\Pentest\EvidenceStore
Mnb\SecureCore\Pentest\EvidenceRedactor
Mnb\SecureCore\Pentest\EvidenceBundle
Mnb\SecureCore\Pentest\RemediationPolicy
Mnb\SecureCore\Pentest\RemediationSlaCalculator
Mnb\SecureCore\Pentest\RemediationPlan
Mnb\SecureCore\Pentest\RetestRequest
Mnb\SecureCore\Pentest\RetestResult
Mnb\SecureCore\Pentest\RetestGate
Mnb\SecureCore\Pentest\SecurityReleaseGate
Mnb\SecureCore\Pentest\ReleaseGatePolicy
Mnb\SecureCore\Pentest\ReleaseGateReport
Mnb\SecureCore\Pentest\SecurityCoverageAnalyzer
Mnb\SecureCore\Pentest\ControlCoverageReport
Mnb\SecureCore\Pentest\PentestAuditEvents
```

---

## 4. Installation

Install the package from Packagist:

```bash
composer require mnb/mnb-secure-core
```

Load Composer autoload:

```php
<?php

require __DIR__ . '/vendor/autoload.php';
```

---

## 5. Configuration

The penetration testing and verification configuration is defined in `config/security.php`.

Example:

```php
'pentest' => [
    'enabled' => true,
    'safe_mode' => true,
    'evidence_storage' => __DIR__ . '/../storage/audit/pentest',
    'redact_evidence' => true,

    'required_profiles' => [
        'production_release',
        'api_security',
        'database_security',
    ],

    'release_gate' => [
        'enabled' => true,
        'block_on_open_critical' => true,
        'block_on_open_high' => true,
        'allow_accepted_risk' => false,
        'require_retest_for_critical' => true,
        'require_retest_for_high' => true,
        'minimum_coverage_percent' => 90,
    ],

    'sla' => [
        'Critical' => 'P3D',
        'High' => 'P7D',
        'Medium' => 'P30D',
        'Low' => 'P90D',
        'Info' => null,
    ],

    'profiles' => [
        'production_release' => [
            'required_tests' => [
                'PT-AUTH-001',
                'PT-AUTHZ-001',
                'PT-TENANT-001',
                'PT-INJ-001',
                'PT-XSS-001',
                'PT-CSRF-001',
                'PT-UPLOAD-001',
                'PT-API-001',
                'PT-DB-001',
                'PT-RUNTIME-001',
                'PT-SSRF-001',
                'PT-ERR-001',
            ],
        ],
    ],
],
```

### Important production notes

Use `safe_mode => true` by default. This package is intended to verify controls safely, not to run destructive exploitation automatically.

Do not store raw secrets in evidence. Keep `redact_evidence => true` enabled.

---

## 6. Basic SecurityKernel usage

```php
<?php

use Mnb\SecureCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);

$checklist = $kernel->pentestChecklist();
$payloads = $kernel->payloadLibrary();
$matrix = $kernel->verificationMatrix();
$runner = $kernel->securityVerificationRunner();
$coverage = $kernel->securityCoverageAnalyzer();
$releaseGate = $kernel->securityReleaseGate();
```

Depending on the exact integration style in your app, you can also instantiate classes directly.

---

## 7. Payload library

The payload library gives safe, categorized payload examples for verification.

Example:

```php
<?php

$payloads = $kernel->payloadLibrary();

$sqlPayloads = $payloads->forCategory('sql_injection');
$xssPayloads = $payloads->forCategory('xss');
$idorPayloads = $payloads->forCategory('idor');
$filePayloads = $payloads->forCategory('file_upload');
```

Common categories:

```text
sql_injection
xss
idor
csrf
file_upload
rate_limit
database
headers
error_disclosure
memory
throughput
runtime
ssrf
queue
token
session
origin
```

### Safe usage rule

Use payloads only in controlled local/staging verification targets that you own.

Do not use this feature to test third-party systems without permission.

---

## 8. Pentest checklist

The checklist contains reusable verification cases.

Example:

```php
<?php

$checklist = $kernel->pentestChecklist();
$cases = $checklist->all();

foreach ($cases as $case) {
    echo $case->id() . ' - ' . $case->title() . PHP_EOL;
}
```

Example checklist cases:

```text
PT-AUTH-001     Brute force login is blocked
PT-AUTH-002     Session fixation is blocked
PT-AUTHZ-001    Object-level authorization blocks IDOR
PT-TENANT-001   Cross-tenant data access is blocked
PT-INJ-001      SQL injection is neutralized
PT-XSS-001      XSS payloads are neutralized
PT-CSRF-001     State-changing actions require CSRF
PT-UPLOAD-001   Dangerous uploads are blocked
PT-API-001      API token and rate-limit protections work
PT-DB-001       Mass assignment and schema alteration are guarded
PT-RUNTIME-001  Unknown runtime commands are blocked
PT-SSRF-001     Private/internal outbound URLs are blocked
PT-ERR-001      Raw internal errors are hidden
PT-QUEUE-001    Long-running work is deferred to background job
PT-TOKEN-001    Revoked access token is rejected
PT-SESSION-001  Session ID rotates on login
```

---

## 9. Verification profiles

A verification profile defines which test cases are required for a particular release or security goal.

Example profile:

```php
<?php

use Mnb\SecureCore\Pentest\VerificationProfile;

$profile = new VerificationProfile(
    name: 'production_release',
    requiredTests: [
        'PT-AUTH-001',
        'PT-AUTHZ-001',
        'PT-TENANT-001',
        'PT-INJ-001',
        'PT-XSS-001',
        'PT-CSRF-001',
        'PT-UPLOAD-001',
        'PT-API-001',
        'PT-DB-001',
        'PT-RUNTIME-001',
        'PT-SSRF-001',
        'PT-ERR-001',
    ]
);
```

Useful profile names:

```text
production_release
api_security
database_security
file_security
runtime_network_security
queue_security
token_session_security
origin_security
```

---

## 10. Verification target

A verification target describes what is being tested.

Example:

```php
<?php

use Mnb\SecureCore\Pentest\VerificationTarget;

$target = new VerificationTarget(
    name: 'local-api',
    environment: 'testing',
    baseUrl: 'https://app.test',
    metadata: [
        'release' => 'v1.0.1',
        'owner' => 'security-team',
    ]
);
```

Keep metadata safe. Do not store raw credentials in target metadata.

---

## 11. Running verification checks

The verification runner records test outcomes and evidence.

Example:

```php
<?php

$result = $kernel->securityVerificationRunner()->recordResult(
    testId: 'PT-INJ-001',
    status: 'passed',
    severity: 'Critical',
    evidence: [
        'Prepared statements used',
        'SQL error not exposed to frontend',
        'Unsafe identifier rejected',
    ],
    notes: 'Tested login and search endpoints.'
);

if (!$result->passed()) {
    // Create finding or remediation plan.
}
```

Common result statuses:

```text
passed
failed
skipped
manual_required
not_applicable
```

---

## 12. Evidence collection

Evidence proves why a verification result passed or failed.

Evidence examples:

```text
HTTP status code
Response headers
Safe response body summary
Audit event ID
Query plan
Config check result
Log reference
Manual note
File hash
Command output summary
```

Example:

```php
<?php

$collector = $kernel->evidenceCollector();

$bundle = $collector->bundle([
    [
        'type' => 'http_response',
        'summary' => 'POST /login returned 429 after brute force threshold.',
        'data' => [
            'status' => 429,
            'headers' => [
                'Retry-After' => '60',
            ],
        ],
    ],
    [
        'type' => 'audit_event',
        'summary' => 'Rate-limit event recorded.',
        'data' => [
            'event' => 'rate_limit.blocked',
        ],
    ],
]);
```

---

## 13. Evidence redaction

Evidence must not leak secrets.

The evidence redactor should remove:

```text
Authorization headers
Cookies
Bearer tokens
Passwords
API keys
Database credentials
Private file paths
Raw PII unless explicitly allowed
```

Example:

```php
<?php

$redactor = $kernel->evidenceRedactor();

$safeEvidence = $redactor->redact([
    'Authorization' => 'Bearer secret-token-value',
    'Cookie' => 'session_id=secret',
    'body' => [
        'email' => 'student@example.com',
        'password' => 'secret-password',
    ],
]);
```

Safe output should replace sensitive values with a redaction marker.

---

## 14. Creating pentest findings

A failed verification result should become a finding.

Example:

```php
<?php

use Mnb\SecureCore\Pentest\PentestFinding;

$finding = new PentestFinding(
    id: 'FIND-2026-0001',
    title: 'Refresh token reuse was not detected',
    severity: 'High',
    affectedTarget: 'api-auth',
    affectedRole: 'authenticated_user',
    stepsToReproduce: [
        'Login and receive refresh token A.',
        'Refresh token A and receive refresh token B.',
        'Reuse refresh token A.',
        'Observe old token is still accepted.',
    ],
    payloads: [],
    evidence: [
        'Old refresh token returned 200 instead of revoking family.',
    ],
    businessImpact: 'Stolen refresh tokens may remain usable.',
    technicalImpact: 'Refresh token replay protection missing.',
    recommendedFix: 'Enable RefreshTokenReuseDetector and revoke token family on reuse.',
    status: 'open'
);
```

---

## 15. Risk rating

Risk ratings are typically:

```text
Critical
High
Medium
Low
Info
```

Example usage:

```php
<?php

$risk = $kernel->riskRating();
$score = $risk->score('High');
```

Recommended handling:

```text
Critical → immediate fix, no release
High     → fix before production unless explicitly accepted
Medium   → scheduled remediation
Low      → backlog or next sprint
Info     → documentation/awareness
```

---

## 16. Remediation policy and SLA

A remediation policy turns findings into due dates and ownership.

Example:

```php
<?php

$policy = $kernel->remediationPolicy();
$calculator = $kernel->remediationSlaCalculator();

$dueDate = $calculator->dueDate('High', new DateTimeImmutable('2026-07-01'));
```

Recommended SLA defaults:

```text
Critical → 3 days
High     → 7 days
Medium   → 30 days
Low      → 90 days
Info     → no SLA / backlog
```

---

## 17. Remediation plan

A remediation plan should include:

```text
finding_id
severity
owner
due_date
recommended_fix
affected_controls
required_retest_cases
required_evidence
status
history
```

Example:

```php
<?php

$plan = $kernel->remediationPlanBuilder()->fromFinding(
    finding: $finding,
    owner: 'backend-team',
    requiredRetests: ['PT-TOKEN-004']
);
```

---

## 18. Retest gate

Critical and High findings should not be closed without retesting.

Example:

```php
<?php

$gate = $kernel->retestGate();

$decision = $gate->canCloseFinding(
    finding: $finding,
    retestStatus: 'passed',
    evidence: ['PT-TOKEN-004 passed after token family revocation fix.']
);

if (!$decision->allowed()) {
    throw new RuntimeException($decision->reason());
}
```

Retest outcomes:

```text
retest_passed
retest_failed
manual_required
accepted_risk
false_positive
```

Critical/High closure should require either:

```text
Retest passed with evidence
Accepted risk with approval metadata
False positive with review evidence
```

---

## 19. Release gate

The release gate decides whether a release can go to production.

It should block release when:

```text
Open Critical finding exists
Open High finding exists
Critical/High finding is fixed but not retested
Required verification tests are missing
Coverage is below minimum threshold
Evidence is missing
Production checker failed
```

Example:

```php
<?php

$report = $kernel->securityReleaseGate()->evaluate(
    profile: 'production_release',
    results: $verificationResults,
    findings: $openFindings
);

if (!$report->passed()) {
    foreach ($report->blockers() as $blocker) {
        echo '[BLOCKED] ' . $blocker . PHP_EOL;
    }
}
```

---

## 20. Security coverage analysis

Coverage analysis shows which controls are verified.

Example:

```php
<?php

$coverage = $kernel->securityCoverageAnalyzer()->analyze(
    profile: 'production_release',
    results: $verificationResults
);

echo $coverage->overallPercent();
```

Example coverage report:

```json
{
  "overall_coverage": 92,
  "engines": {
    "Authentication Strategy": 100,
    "Authorization Strategy": 100,
    "Secure Database Governance": 90,
    "Runtime Execution Security": 80,
    "Outbound Network Security": 80,
    "File Upload Security": 100
  }
}
```

---

## 21. Verification matrix

The verification matrix maps security engines to test cases.

Example:

```php
<?php

$matrix = $kernel->verificationMatrix();
$coverage = $matrix->forControl('Secure Database Governance');
```

Example mapping:

```text
Secure Database Governance
  PT-INJ-001
  PT-DB-001
  PT-DB-002
  PT-DB-003
  PT-DB-004

Runtime Execution Security
  PT-RUNTIME-001
  PT-RUNTIME-002
  PT-RUNTIME-003

Outbound Network Security
  PT-SSRF-001
  PT-SSRF-002
  PT-SSRF-003
```

---

## 22. Report generation

Generate Markdown or JSON reports for internal review.

Example:

```php
<?php

$builder = $kernel->pentestReportBuilder();

$markdown = $builder->markdown(
    scope: 'MNB Secure Core v1.0.1 production release',
    findings: $findings,
    verificationResults: $results
);

file_put_contents(__DIR__ . '/storage/reports/pentest-report.md', $markdown);
```

Report should include:

```text
Scope
Executive summary
Finding counts
Finding details
Evidence summary
Remediation status
Retest status
Release gate decision
Residual risk
```

---

## 23. CLI usage

Existing checklist and report commands:

```bash
php bin/mnb-secure pentest:checklist
php bin/mnb-secure pentest:payloads
php bin/mnb-secure pentest:matrix
php bin/mnb-secure pentest:report-template
```

Verification and remediation commands:

```bash
php bin/mnb-secure pentest:run-checklist production_release
php bin/mnb-secure pentest:verify PT-INJ-001
php bin/mnb-secure pentest:evidence
php bin/mnb-secure pentest:coverage production_release
php bin/mnb-secure pentest:remediation-plan
php bin/mnb-secure pentest:retest
php bin/mnb-secure security:release-gate production_release
```

Useful vulnerability matrix commands:

```bash
php bin/mnb-secure vulnerabilities:report
php bin/mnb-secure vulnerabilities:check sql_injection
php bin/mnb-secure vulnerabilities:check ssrf
php bin/mnb-secure vulnerabilities:check command_injection
php bin/mnb-secure vulnerabilities:check error_disclosure
```

---

## 24. Demo

Run the demo:

```bash
php demos/33-security-verification-remediation-evidence-automation-engine.php
```

Run all demos:

```bash
php demos/run-all-demos.php
```

Demo flow:

```text
1. Verification profile loaded
2. Verification target created
3. Required test cases selected
4. Safe verification run created
5. Evidence collected and redacted
6. Finding created from failed verification
7. Remediation SLA calculated
8. Remediation plan generated
9. Retest required for Critical/High finding
10. Retest passed/failed result recorded
11. Coverage report generated
12. Release gate blocks open Critical/High findings
13. Release gate passes after remediation and retest
14. Vulnerability matrix linked to verification evidence
```

---

## 25. Recommended application workflow

Use this workflow for every production release:

```text
1. Run config validation.
2. Run vulnerability matrix report.
3. Run production readiness check.
4. Run required pentest checklist profile.
5. Attach evidence to all required tests.
6. Create findings for failed checks.
7. Assign remediation plans.
8. Retest Critical and High findings.
9. Run security release gate.
10. Release only if gate passes.
```

Example commands:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure vulnerabilities:report
php bin/mnb-secure production:readiness
php bin/mnb-secure pentest:run-checklist production_release
php bin/mnb-secure pentest:coverage production_release
php bin/mnb-secure security:release-gate production_release
php bin/mnb-secure final:gate
```

---

## 26. CI/CD integration

Example CI step:

```bash
php tests/run-tests.php
php demos/run-all-demos.php
php bin/mnb-secure config:validate
php bin/mnb-secure vulnerabilities:report
php bin/mnb-secure pentest:coverage production_release
php bin/mnb-secure security:release-gate production_release
```

A release should fail if:

```text
Tests fail
Demos fail
Config validation fails
Critical/High findings are open
Coverage is below minimum
Retest evidence is missing
Production readiness gate fails
```

---

## 27. Evidence safety rules

Always follow these evidence safety rules:

```text
Do not store plaintext passwords.
Do not store raw bearer tokens.
Do not store cookies.
Do not store full private file paths.
Do not store raw PII unless required and protected.
Do not expose evidence publicly.
Do redact before report generation.
Do keep evidence linked to request IDs/audit IDs.
```

Recommended evidence style:

```text
Good: "Authorization header was present and redacted."
Bad:  "Authorization: Bearer eyJhbGciOi..."
```

---

## 28. Audit events

Typical pentest audit events:

```text
pentest.verification.started
pentest.verification.completed
pentest.verification.failed
pentest.evidence.collected
pentest.evidence.redacted
pentest.finding.created
pentest.finding.assigned
pentest.finding.fixed
pentest.retest.requested
pentest.retest.passed
pentest.retest.failed
pentest.release_gate.passed
pentest.release_gate.blocked
pentest.coverage.calculated
```

Audit events should be safe and should not contain raw secrets.

---

## 29. Integration with other engines

### Authentication

Verify:

```text
Brute-force protection
Session rotation
Token revocation
Refresh token replay detection
```

### Authorization

Verify:

```text
Role checks
Permission checks
Tenant boundaries
Object-level access checks
```

### Database

Verify:

```text
Prepared statements
Query allow-lists
Tenant-scoped queries
Mass-assignment blocking
Schema alteration guards
```

### File security

Verify:

```text
Upload type checks
Malware scan flow
Quarantine
Protected downloads
Signed URLs
```

### Runtime and outbound network

Verify:

```text
Command allow-list
Safe process runner
SSRF blocking
Redirect-to-private-IP blocking
```

### Safe errors

Verify:

```text
No stack trace in production
No SQLSTATE disclosure
Request ID included
Technical logs hidden
```

### Queue/background jobs

Verify:

```text
Idempotency
Dead-letter queue
Retry backoff
Payload redaction
Worker safety
```

---

## 30. Production checklist

Before production release:

```text
[ ] Required verification profile configured.
[ ] All required test cases executed.
[ ] Evidence collected for passed/failed checks.
[ ] Evidence redaction enabled.
[ ] Critical findings fixed and retested.
[ ] High findings fixed and retested or formally accepted.
[ ] Remediation owners assigned.
[ ] SLA due dates calculated.
[ ] Security release gate passes.
[ ] Vulnerability matrix reviewed.
[ ] Production readiness checker passes.
[ ] Reports stored in protected internal location.
```

---

## 31. Testing examples

Example test cases to include in your project:

```text
Verification Profiles
- profile loads required tests
- missing required test is detected
- unknown test id is rejected

Verification Runner
- pass result recorded
- failed result creates finding
- manual_required result supported
- skipped result supported
- evidence attached to result

Evidence
- authorization header redacted
- cookie redacted
- token redacted
- password redacted
- evidence bundle generated

Remediation
- SLA due date calculated for Critical
- SLA due date calculated for High
- owner assigned
- remediation history recorded
- accepted risk requires approval metadata

Retest
- Critical finding cannot close without retest
- High finding cannot close without retest
- retest passed closes finding
- retest failed reopens finding

Release Gate
- open Critical blocks release
- open High blocks release
- fixed but not retested blocks release
- minimum coverage enforced
- release gate passes after remediation and retest
```

Run package tests:

```bash
php tests/run-tests.php
```

---

## 32. Common mistakes

### Mistake: Treating checklist presence as verification

Bad:

```text
Checklist exists, so security is done.
```

Good:

```text
Checklist test was executed, evidence was captured, and result was reviewed.
```

### Mistake: Closing Critical findings without retest

Bad:

```text
Developer says fixed, so close it.
```

Good:

```text
Fix is verified by retest evidence before closure.
```

### Mistake: Storing raw tokens in evidence

Bad:

```text
Authorization: Bearer real-token-value
```

Good:

```text
Authorization header present: [redacted]
```

### Mistake: Running unsafe payloads against systems you do not own

Use the payload library only in systems where you have authorization.

### Mistake: Skipping release gate

The release gate is the final safety check. Do not bypass it for production.

---

## 33. Best practices

```text
Use named verification profiles.
Keep evidence redaction enabled.
Attach audit IDs to evidence.
Assign every failed finding to an owner.
Require retest for Critical and High issues.
Use release gates in CI/CD.
Review coverage after every new security engine.
Store reports in internal protected storage.
Avoid raw secrets in notes, payloads, and reports.
```

---

## 34. Summary

The Penetration Testing, Security Verification, and Remediation feature turns security from a checklist into a controlled lifecycle:

```text
Test → Record evidence → Create finding → Assign remediation → Fix → Retest → Gate release
```

It helps make the security posture of `MNB Secure Core v1.0.1` provable, traceable, and release-ready.
