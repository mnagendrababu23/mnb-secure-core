# Backup, Recovery, and Incident Response

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Documentation topic:** 12. Backup, Recovery, and Incident Response

---

## 1. Purpose

The **Backup, Recovery, and Incident Response** layer helps applications prepare for, respond to, and recover from security and operational failures.

It is designed for situations such as:

- accidental data deletion
- ransomware or destructive activity
- database corruption
- failed deployments
- file storage loss
- compromised accounts
- stolen tokens
- unauthorized admin actions
- suspicious uploads
- queue/worker failures
- origin exposure incidents
- audit integrity failures
- service outage or capacity incident

This feature does not replace your hosting provider backup, database backup, firewall, SIEM, or disaster recovery plan. Instead, it gives your PHP application a secure framework for:

1. defining backup policies,
2. creating safe backup manifests,
3. verifying backup integrity,
4. planning restore operations,
5. recording incident response actions,
6. linking incidents to audit logs, tokens, sessions, queues, files, and security findings.

---

## 2. Why this feature is important

Security is not complete when prevention exists. A production application also needs recovery.

Without a backup and incident response strategy, these problems become serious:

- deleted records cannot be restored safely;
- compromised users remain active;
- malicious uploads remain in storage;
- failed jobs are retried forever;
- audit evidence is lost;
- developers restore the wrong database snapshot;
- secrets leak into backup archives;
- restore operations overwrite good data;
- incidents are handled manually without history;
- serious findings are closed without evidence.

MNB Secure Core treats backup and incident response as part of the same lifecycle:

```text
Detect → Contain → Preserve Evidence → Recover → Verify → Retest → Close
```

---

## 3. Main responsibilities

This feature covers the following responsibilities:

| Area | Purpose |
|---|---|
| Backup policy | Define what should be backed up and how long it is retained. |
| Backup manifest | Record what a backup contains without exposing secrets. |
| Backup integrity | Verify hashes and detect tampering or incomplete backup files. |
| Restore planning | Build a safe restore plan before applying changes. |
| Restore validation | Confirm restored data is usable and safe. |
| Incident records | Track security and operational incidents. |
| Incident actions | Record containment, mitigation, communication, and recovery steps. |
| Evidence preservation | Link logs, audit records, files, job IDs, token/session actions, and findings. |
| Post-incident review | Track root cause, remediation, and prevention actions. |

---

## 4. Typical use cases

### 4.1 Backup before schema changes

Before running a dangerous migration or schema alteration, create a backup manifest and require restore readiness.

Example:

```text
Schema alter request
    ↓
Backup policy check
    ↓
Backup manifest created
    ↓
Integrity hash recorded
    ↓
Schema plan allowed
```

### 4.2 Incident after compromised token

When a stolen refresh token is detected:

```text
Refresh token reuse detected
    ↓
Incident opened
    ↓
Token family revoked
    ↓
Related sessions forced out
    ↓
Audit evidence attached
    ↓
Retest required
```

### 4.3 Recovery after accidental delete

When a tenant admin accidentally deletes records:

```text
Soft delete record found
    ↓
Restore permission checked
    ↓
Restore plan created
    ↓
Restore performed
    ↓
Audit event generated
```

---

## 5. Recommended configuration

Add or review the `backup` and `incident_response` sections in `config/security.php` and `config/security.production.php`.

```php
return [
    'backup' => [
        'enabled' => true,
        'storage_path' => __DIR__ . '/../storage/backups',
        'manifest_path' => __DIR__ . '/../storage/backups/manifests',

        'encryption' => [
            'enabled' => true,
            'key_env' => 'BACKUP_ENCRYPTION_KEY',
        ],

        'retention' => [
            'daily_days' => 7,
            'weekly_weeks' => 4,
            'monthly_months' => 6,
        ],

        'integrity' => [
            'hash_algorithm' => 'sha256',
            'verify_after_create' => true,
            'verify_before_restore' => true,
        ],

        'restore' => [
            'require_dry_run' => true,
            'require_admin_approval' => true,
            'block_cross_environment_restore' => true,
            'require_integrity_check' => true,
        ],

        'redaction' => [
            'exclude_env_files' => true,
            'exclude_runtime_logs' => true,
            'exclude_tokens' => true,
            'exclude_cache' => true,
            'exclude_queue_runtime' => true,
        ],
    ],

    'incident_response' => [
        'enabled' => true,
        'storage_path' => __DIR__ . '/../storage/audit/incidents',
        'default_severity' => 'medium',

        'severity_sla' => [
            'critical' => 'P1D',
            'high' => 'P3D',
            'medium' => 'P14D',
            'low' => 'P30D',
        ],

        'containment' => [
            'allow_token_revocation' => true,
            'allow_session_forced_logout' => true,
            'allow_queue_pause' => true,
            'allow_file_quarantine' => true,
            'allow_origin_gate_block' => true,
        ],

        'evidence' => [
            'redact_secrets' => true,
            'hash_files' => true,
            'link_audit_events' => true,
            'link_pentest_findings' => true,
        ],

        'closure' => [
            'require_root_cause' => true,
            'require_remediation' => true,
            'require_retest_for_high' => true,
            'require_retest_for_critical' => true,
        ],
    ],
];
```

---

## 6. Basic installation context

Install the package with Composer:

```bash
composer require mnb/mnb-secure-core
```

Load Composer autoload:

```php
require __DIR__ . '/vendor/autoload.php';
```

Create the kernel:

```php
use Mnb\SecureCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

---

## 7. Backup policy usage

A backup policy should answer:

- Is backup enabled?
- Which paths or data sources are included?
- Which paths are excluded?
- Should backup be encrypted?
- How long should backup be retained?
- Is integrity verification required?
- Is restore dry-run required?

Example usage:

```php
$backupPolicy = $kernel->backupPolicy();

if (!$backupPolicy->isEnabled()) {
    throw new RuntimeException('Backups are disabled.');
}
```

For applications that do not expose a `backupPolicy()` convenience method yet, keep this pattern in your own application service and use the config values directly.

---

## 8. Creating a backup manifest

A backup manifest records safe metadata about a backup.

It should not expose secrets or raw sensitive values.

Recommended manifest fields:

```text
backup_id
created_at
environment
application_version
backup_type
included_resources
excluded_resources
hash_algorithm
archive_hash
encrypted
created_by
retention_until
notes
```

Example:

```php
$manifest = [
    'backup_id' => 'backup_' . bin2hex(random_bytes(8)),
    'created_at' => gmdate('c'),
    'environment' => $_ENV['APP_ENV'] ?? 'unknown',
    'backup_type' => 'pre_schema_change',
    'included_resources' => [
        'database:mnb_app',
        'storage:private_uploads',
    ],
    'excluded_resources' => [
        '.env',
        'storage/cache',
        'storage/tokens',
        'storage/queue',
    ],
    'hash_algorithm' => 'sha256',
    'encrypted' => true,
    'created_by' => 'admin:' . hash('sha256', (string) $adminUserId),
];
```

Write the manifest safely:

```php
$path = __DIR__ . '/storage/backups/manifests/' . $manifest['backup_id'] . '.json';

file_put_contents(
    $path,
    json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
);
```

Make sure the manifest directory is not publicly web-accessible.

---

## 9. Backup integrity verification

Every backup should have an integrity hash.

Example:

```php
$archivePath = __DIR__ . '/storage/backups/backup_2026_07_01.zip';
$hash = hash_file('sha256', $archivePath);
```

Store the hash in the manifest:

```php
$manifest['archive_hash'] = $hash;
```

Verify before restore:

```php
$currentHash = hash_file('sha256', $archivePath);

if (!hash_equals($manifest['archive_hash'], $currentHash)) {
    throw new RuntimeException('Backup integrity check failed.');
}
```

This prevents restoring corrupted or tampered backup archives.

---

## 10. What should not be included in public backup archives

Avoid including:

```text
.env
private keys
runtime tokens
active sessions
queue runtime payloads
cache files
unredacted audit exports
raw debug logs
vendor directory when not needed
git directory
node_modules
```

Recommended backup exclusions:

```text
.git/
vendor/
node_modules/
.env
storage/cache/
storage/tokens/
storage/queue/
storage/logs/debug/
storage/private/tmp/
```

For production disaster recovery, secrets should be backed up separately using a secure secrets manager, not inside normal app archives.

---

## 11. Restore planning

A restore plan should be created before restoring data.

A safe restore plan includes:

```text
restore_id
backup_id
target_environment
source_environment
restore_type
dry_run
integrity_verified
approval_required
approval_status
expected_changes
rollback_plan
risk_level
```

Example:

```php
$restorePlan = [
    'restore_id' => 'restore_' . bin2hex(random_bytes(8)),
    'backup_id' => $manifest['backup_id'],
    'target_environment' => $_ENV['APP_ENV'] ?? 'unknown',
    'source_environment' => $manifest['environment'],
    'restore_type' => 'database_restore',
    'dry_run' => true,
    'integrity_verified' => true,
    'approval_required' => true,
    'expected_changes' => [
        'restore database tables',
        'verify tenant counts',
        'verify admin login',
    ],
    'rollback_plan' => 'Create current-state backup before restore.',
];
```

---

## 12. Cross-environment restore protection

Do not restore production backups into local/dev without clear data protection controls.

Risky pattern:

```text
production backup → developer laptop
```

Safer pattern:

```text
production backup → staging restore vault → anonymized dataset → developer laptop
```

Recommended rule:

```php
if ($restorePlan['source_environment'] === 'production'
    && $restorePlan['target_environment'] !== 'production'
) {
    throw new RuntimeException('Cross-environment restore requires anonymization approval.');
}
```

---

## 13. Restore validation checklist

After restore, verify:

- database connection works;
- migrations are in expected state;
- tenant isolation still works;
- admin login works;
- token/session stores are cleaned as needed;
- queue workers are not replaying stale jobs;
- cache is cleared;
- audit trail is preserved;
- file storage references are valid;
- vulnerability report still passes;
- production readiness gate still passes.

Useful commands:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure vulnerabilities:report
php bin/mnb-secure production:readiness
php bin/mnb-secure final:gate
```

---

## 14. Incident response lifecycle

Recommended incident lifecycle:

```text
opened
triaged
contained
investigating
recovering
retest_required
resolved
closed
accepted_risk
```

Example incident record:

```php
$incident = [
    'incident_id' => 'inc_' . bin2hex(random_bytes(8)),
    'title' => 'Refresh token reuse detected',
    'severity' => 'high',
    'status' => 'opened',
    'opened_at' => gmdate('c'),
    'opened_by' => 'system',
    'affected_user_hash' => hash('sha256', (string) $userId),
    'evidence' => [],
    'containment_actions' => [],
];
```

Store incident records in a non-public audit location:

```php
$incidentPath = __DIR__ . '/storage/audit/incidents/' . $incident['incident_id'] . '.json';
file_put_contents($incidentPath, json_encode($incident, JSON_PRETTY_PRINT));
```

---

## 15. Incident severity model

Recommended severity levels:

| Severity | Example |
|---|---|
| Critical | Active compromise, data exfiltration, ransomware, production down. |
| High | Token theft, admin account compromise, major auth bypass. |
| Medium | Suspicious activity, blocked SSRF attempt, repeated failed uploads. |
| Low | Misconfiguration warning, stale proxy allow-list, minor policy gap. |
| Info | Informational event requiring no immediate action. |

---

## 16. Incident containment actions

Containment actions may include:

```text
revoke token
revoke token family
force logout sessions
pause queue workers
move job to dead letter
quarantine uploaded file
block IP/rate limit key
rotate secret
disable account
disable webhook endpoint
enable maintenance mode
block origin exposure path
```

Example: revoke all sessions after a password reset incident:

```php
$kernel->forcedLogoutService()->forceLogoutUser(
    userId: (string) $userId,
    reason: 'password_changed'
);
```

Example: revoke token family after refresh token reuse:

```php
$kernel->tokenRevocationService()->revokeFamily(
    familyId: $familyId,
    reason: 'refresh_reuse_detected'
);
```

Example: quarantine a suspicious upload:

```php
$kernel->secureFileManager()->quarantine(
    fileId: $fileId,
    reason: 'incident_response'
);
```

The exact methods depend on your application integration, but the principle is the same: incident response should call the security engine rather than manually editing database rows.

---

## 17. Evidence handling

Incident evidence must be useful but safe.

Evidence examples:

```text
audit event ID
request ID
job ID
file hash
token family ID
session ID hash
safe error fingerprint
vulnerability finding ID
origin exposure report ID
backup manifest ID
```

Do not store:

```text
raw passwords
raw tokens
full Authorization headers
session cookies
private keys
plain PII
unredacted database dumps
```

Example evidence item:

```php
$evidence = [
    'type' => 'audit_event',
    'reference' => 'audit_01HX...',
    'description' => 'Refresh token reuse detected',
    'collected_at' => gmdate('c'),
];
```

---

## 18. Linking incidents to audit logs

When an incident is opened, add an audit event:

```php
$kernel->auditTrail()->record('incident.opened', [
    'incident_id' => $incident['incident_id'],
    'severity' => $incident['severity'],
    'title' => $incident['title'],
]);
```

When containment happens:

```php
$kernel->auditTrail()->record('incident.containment_action', [
    'incident_id' => $incident['incident_id'],
    'action' => 'force_logout_user',
    'reason' => 'password_changed',
]);
```

---

## 19. Incident response with queue/background jobs

Some incident tasks should run in the background:

- export audit evidence;
- scan all recent uploads;
- notify admins;
- revoke many user sessions;
- generate recovery reports;
- verify backups.

Example queue dispatch:

```php
$kernel->jobDispatcher()->dispatch(
    name: 'incident_evidence_export',
    payload: [
        'incident_id' => $incident['incident_id'],
    ],
    queue: 'security',
    idempotencyKey: 'incident_evidence_export:' . $incident['incident_id']
);
```

Use idempotency keys to avoid duplicate incident jobs.

---

## 20. Incident response with token/session control

Common actions:

```php
// Revoke one token
$kernel->tokenRevocationService()->revoke(
    tokenId: $jti,
    reason: 'security_incident'
);

// Revoke all sessions for one user
$kernel->sessionRevocationService()->revokeUserSessions(
    userId: (string) $userId,
    reason: 'security_incident'
);

// Enforce concurrent session cleanup
$kernel->concurrentSessionLimiter()->enforce((string) $userId);
```

These calls are examples of the intended integration style. Exact method names may vary depending on your local application wrappers.

---

## 21. Incident response with files

If an uploaded file is suspicious:

```php
$kernel->auditTrail()->record('incident.file_suspected', [
    'incident_id' => $incidentId,
    'file_id' => $fileId,
    'reason' => 'malware_scan_failed',
]);
```

Then quarantine the file and prevent download:

```php
$kernel->secureFileManager()->quarantine($fileId, 'malware_scan_failed');
```

Recommended file incident evidence:

```text
file_id
sha256 hash
original safe filename
uploader user hash
tenant hash
scan result
quarantine path reference
```

---

## 22. Incident response with database governance

Database-related incidents include:

- unsafe schema change attempt;
- mass assignment blocked;
- tenant scope violation;
- suspicious export request;
- unauthorized hard delete request.

Recommended response:

```text
1. Open incident if severity is high enough.
2. Attach query plan or audit event reference.
3. Revoke affected sessions if needed.
4. Block repeated attempts through rate limiting.
5. Require remediation and retest.
```

---

## 23. Incident response with origin protection

Origin-related incidents include:

- direct IP Host access attempts;
- spoofed forwarded headers;
- unknown Host header;
- origin IP leak detected;
- risky response fingerprint.

Recommended commands:

```bash
php bin/mnb-secure origin:exposure-report
php bin/mnb-secure origin:leak-scan
php bin/mnb-secure origin:firewall-plan
php bin/mnb-secure origin:production-gate
```

---

## 24. Incident response with performance/queue failures

Operational incidents can become security risks.

Examples:

```text
queue overload
retry storm
dead-letter queue growth
worker memory leak
capacity exhaustion
large payload DoS
```

Recommended commands:

```bash
php bin/mnb-secure queue:pressure
php bin/mnb-secure queue:metrics
php bin/mnb-secure memory:worker-check
php bin/mnb-secure throughput:capacity-risk
php bin/mnb-secure performance:release-gate
```

---

## 25. Backup before incident remediation

Before destructive remediation, create a current-state backup.

Examples of destructive remediation:

- deleting suspicious records;
- applying emergency schema changes;
- removing many files;
- revoking large token families;
- purging queue jobs;
- rolling back deployments.

Recommended rule:

```text
If remediation may destroy or rewrite data, create a backup first.
```

---

## 26. CLI commands

Depending on your current build, useful commands include:

```bash
php bin/mnb-secure backup:policy
php bin/mnb-secure backup:plan
php bin/mnb-secure backup:verify
php bin/mnb-secure backup:restore-plan

php bin/mnb-secure incident:open
php bin/mnb-secure incident:list
php bin/mnb-secure incident:show <incident_id>
php bin/mnb-secure incident:contain <incident_id>
php bin/mnb-secure incident:close <incident_id>

php bin/mnb-secure vulnerabilities:report
php bin/mnb-secure production:readiness
php bin/mnb-secure final:gate
```

If your installed version exposes a smaller command set, keep the same workflows in your application services and use the available CLI commands for validation.

---

## 27. Example: open an incident after refresh token reuse

```php
$userHash = hash('sha256', (string) $userId);

$incident = [
    'incident_id' => 'inc_' . bin2hex(random_bytes(8)),
    'title' => 'Refresh token reuse detected',
    'severity' => 'high',
    'status' => 'opened',
    'affected_user_hash' => $userHash,
    'opened_at' => gmdate('c'),
];

$kernel->auditTrail()->record('incident.opened', [
    'incident_id' => $incident['incident_id'],
    'severity' => 'high',
    'category' => 'token_reuse',
]);

$kernel->tokenRevocationService()->revokeFamily(
    familyId: $familyId,
    reason: 'refresh_reuse_detected'
);

$kernel->sessionRevocationService()->revokeUserSessions(
    userId: (string) $userId,
    reason: 'refresh_reuse_detected'
);
```

---

## 28. Example: backup before schema alter

```php
$backupId = 'backup_' . bin2hex(random_bytes(8));

$manifest = [
    'backup_id' => $backupId,
    'backup_type' => 'pre_schema_alter',
    'created_at' => gmdate('c'),
    'created_by' => 'admin:' . hash('sha256', (string) $adminUserId),
    'reason' => 'before adding admission_number column',
];

$kernel->auditTrail()->record('backup.manifest_created', [
    'backup_id' => $backupId,
    'type' => 'pre_schema_alter',
]);

$schemaPlan = $kernel->schemaMigrationGuard()->planAddColumn(
    table: 'students',
    column: 'admission_number',
    type: 'VARCHAR(100)',
    dryRun: true
);
```

---

## 29. Example: recovery validation after restore

```php
$results = [];

$results['config'] = shell_exec('php bin/mnb-secure config:validate');
$results['vulnerability'] = shell_exec('php bin/mnb-secure vulnerabilities:report');
$results['production'] = shell_exec('php bin/mnb-secure production:readiness');

file_put_contents(
    __DIR__ . '/storage/audit/recovery-validation-' . date('Ymd-His') . '.json',
    json_encode($results, JSON_PRETTY_PRINT)
);
```

For production, prefer calling internal services directly instead of `shell_exec`. If shell execution is required, use the `SafeProcessRunner` from the Runtime Execution engine.

---

## 30. Safe process execution warning

Do not run unsafe recovery commands directly from user input.

Unsafe:

```php
shell_exec($_GET['restore_command']);
```

Safer:

```php
$kernel->safeProcessRunner()->run('backup_verify', [
    $backupId,
]);
```

Only allow approved recovery commands through the Runtime Execution engine.

---

## 31. Safe outbound notification warning

Incident notification webhooks should use the outbound network guard.

Unsafe:

```php
file_get_contents($webhookUrl);
```

Safer:

```php
$kernel->outboundHttpClient()->postJson($webhookUrl, [
    'incident_id' => $incidentId,
    'severity' => 'high',
]);
```

This prevents SSRF through alert/webhook configuration.

---

## 32. Release gate after incident

Do not release while serious incidents remain open.

Recommended gate conditions:

```text
open critical incident → block release
open high incident → block release unless accepted risk approved
failed retest → block release
missing evidence → block release
backup integrity failure → block release
production readiness failure → block release
```

Useful command:

```bash
php bin/mnb-secure final:gate
```

---

## 33. Testing examples

### Backup manifest test

```php
$manifest = [
    'backup_id' => 'backup_test',
    'created_at' => gmdate('c'),
    'encrypted' => true,
];

assert($manifest['encrypted'] === true);
assert(str_starts_with($manifest['backup_id'], 'backup_'));
```

### Integrity test

```php
$file = tempnam(sys_get_temp_dir(), 'backup_');
file_put_contents($file, 'backup-data');

$hash = hash_file('sha256', $file);

assert(hash_equals($hash, hash_file('sha256', $file)));
unlink($file);
```

### Incident evidence redaction test

```php
$evidence = [
    'Authorization' => 'Bearer secret-token',
    'request_id' => 'req_123',
];

$redacted = $kernel->errorLogSanitizer()->sanitize($evidence);

assert(!str_contains(json_encode($redacted), 'secret-token'));
```

---

## 34. Production checklist

Before production:

- [ ] Backups are enabled.
- [ ] Backups are encrypted.
- [ ] Backup key is stored outside the public repo.
- [ ] `.env` is excluded from normal app archives.
- [ ] Runtime token/session stores are excluded from release archives.
- [ ] Backup integrity verification is enabled.
- [ ] Restore dry-run is required.
- [ ] Restore approval is required.
- [ ] Cross-environment restore is blocked or anonymized.
- [ ] Incident storage is not publicly accessible.
- [ ] Incident evidence is redacted.
- [ ] Token/session forced logout is integrated.
- [ ] File quarantine is integrated.
- [ ] Queue dead-letter monitoring is enabled.
- [ ] Origin exposure reports are reviewed.
- [ ] Production readiness and final release gates pass.

---

## 35. Common mistakes

### Mistake 1: Backing up secrets inside normal app archives

Avoid storing `.env`, private keys, API tokens, and session/token stores in normal release or backup archives.

### Mistake 2: Restoring without verifying backup hash

Always verify integrity before restore.

### Mistake 3: Restoring production data to local development

Use anonymization and approval.

### Mistake 4: Closing incidents without evidence

Every serious incident should have evidence, remediation notes, and retest status.

### Mistake 5: Forgetting to revoke sessions after account compromise

Incident response should call token/session revocation services.

### Mistake 6: Letting queue jobs replay after restore

After restore, inspect queue and dead-letter state before restarting workers.

---

## 36. Recommended documentation links

Read these related files next:

```text
docs/logging-audit-and-monitoring.md
docs/environment-and-secret-management.md
docs/token-revocation-and-session-control.md
docs/request-response-queue-and-background-job-strategy.md
docs/safe-error-response-and-technical-log-isolation.md
docs/final-production-readiness-xss-release-consolidation.md
```

---

## 37. Summary

The **Backup, Recovery, and Incident Response** strategy ensures that MNB Secure Core applications are not only protected before an attack or failure, but also prepared to recover after one.

Use this feature to:

- create safe backup manifests;
- verify backup integrity;
- plan safe restores;
- avoid secret leakage in archives;
- open and track incidents;
- preserve redacted evidence;
- revoke compromised tokens and sessions;
- quarantine suspicious files;
- manage queue/worker incidents;
- block release while serious recovery or security issues remain open.

The strongest production security posture combines prevention, detection, response, recovery, retest, and release gates.
