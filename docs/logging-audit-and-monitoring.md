# Logging, Audit, and Monitoring

**Package:** `mnb/mnb-secure-core`  
**Version line:** `MNB Secure Core v1.0.1`  
**Documentation topic:** 11. Logging, Audit, and Monitoring

---

## 1. Purpose

The **Logging, Audit, and Monitoring** strategy in **MNB Secure Core** gives applications a safe way to record operational events, security events, audit trails, metrics, and alerts without leaking secrets or sensitive technical data.

Normal application logs are useful for debugging, but they can become dangerous when they contain:

- passwords,
- API keys,
- bearer tokens,
- cookies,
- session IDs,
- OTP values,
- private file paths,
- database credentials,
- tenant-private records,
- raw request bodies,
- stack traces in public places.

Audit logs are different from normal logs. Audit records are used to prove that important security-sensitive actions happened. They should be structured, timestamped, redacted, and integrity-checkable.

Monitoring is the next layer. It turns repeated security events into alerts, tracks counters, summarizes system health, and helps incident response.

MNB Secure Core separates these responsibilities:

```text
Application logs     → operational debugging and status
Security logs        → warnings, failures, suspicious activity
Audit trail          → tamper-evident security event history
Metrics              → counters and monitoring signals
Alerts               → threshold-based security notifications
Retention manager    → log/audit cleanup according to policy
```

---

## 2. Main classes

The logging and monitoring features mainly live under:

```text
src/Logging/
src/Monitoring/
```

Important logging classes:

```text
src/Logging/Logger.php
src/Logging/LogRecord.php
src/Logging/LogHandlerInterface.php
src/Logging/FileLogHandler.php
src/Logging/JsonLogHandler.php
src/Logging/FileLogger.php
src/Logging/LogDataProtector.php
src/Logging/SecurityAuditEvent.php
src/Logging/SecurityAuditTrail.php
src/Logging/TamperEvidentAuditLogger.php
src/Logging/AuditIntegrityVerifier.php
src/Logging/AuditExporter.php
src/Logging/AutoAuditLogger.php
src/Logging/LogRetentionPolicy.php
src/Logging/LogRetentionManager.php
src/Logging/NullSecurityAuditTrail.php
```

Important monitoring classes:

```text
src/Monitoring/MetricsRegistry.php
src/Monitoring/SecurityMetric.php
src/Monitoring/AlertRule.php
src/Monitoring/AlertManager.php
src/Monitoring/AlertChannelInterface.php
src/Monitoring/FileAlertChannel.php
src/Monitoring/WebhookAlertChannel.php
src/Monitoring/MonitoringSummary.php
src/Monitoring/TraceContext.php
```

Related integrations:

```text
src/Core/SecurityKernel.php
src/Errors/ErrorLogSanitizer.php
src/Env/SecretRedactor.php
src/Incident/IncidentResponseManager.php
src/Network/OutboundHttpClient.php
src/Origin/OriginLogRedactor.php
src/Production/FinalProductionReadinessChecker.php
```

---

## 3. Composer installation

Install the package:

```bash
composer require mnb/mnb-secure-core
```

Load Composer autoload:

```php
<?php

require __DIR__ . '/vendor/autoload.php';
```

---

## 4. Recommended configuration

In `config/security.php`, logging, audit, and monitoring are configured separately.

```php
'audit' => [
    'enabled' => true,
    'file' => __DIR__ . '/../storage/audit/security-audit.log',
    'mirror_to_log' => false,
    'log_file' => __DIR__ . '/../storage/logs/security-audit.log',

    'auto' => [
        'enabled' => false,
        'log_reads' => false,
        'log_preflight' => false,
        'excluded_paths' => [
            'health',
            'healthz',
            'metrics',
            'favicon.ico',
        ],
        'sensitive_input_keys' => [
            'password',
            'password_confirmation',
            'current_password',
            'new_password',
            'token',
            'api_token',
            'secret',
            'api_key',
            'authorization',
            'cookie',
            'session',
            'csrf',
            'otp',
            'private_key',
        ],
    ],
],

'logging' => [
    'enabled' => true,
    'default_channel' => 'app',

    'redaction' => [
        'enabled' => true,
        'use_secret_redactor' => true,
        'use_data_protection' => true,
    ],

    'channels' => [
        'app' => [
            'level' => 'info',
            'handler' => 'json_file',
            'path' => __DIR__ . '/../storage/logs/app.jsonl',
        ],
        'security' => [
            'level' => 'warning',
            'handler' => 'json_file',
            'path' => __DIR__ . '/../storage/logs/security.jsonl',
        ],
        'audit' => [
            'level' => 'info',
            'handler' => 'json_file',
            'path' => __DIR__ . '/../storage/logs/audit.jsonl',
        ],
    ],

    'retention' => [
        'app_days' => 14,
        'security_days' => 90,
        'audit_days' => 365,
        'debug_days' => 7,
    ],
],

'monitoring' => [
    'enabled' => true,

    'metrics' => [
        'enabled' => true,
        'driver' => 'file',
        'path' => __DIR__ . '/../storage/logs/metrics.json',
    ],

    'alerts' => [
        'enabled' => true,
        'channels' => ['file'],
        'file' => __DIR__ . '/../storage/logs/security-alerts.jsonl',
        'event_file' => __DIR__ . '/../storage/logs/monitoring-events.jsonl',
        'webhook_url' => '',

        'rules' => [
            'failed_login_spike' => [
                'event' => 'auth.login.failure',
                'threshold' => 10,
                'window_seconds' => 300,
                'severity' => 'high',
            ],
            'authorization_denial_spike' => [
                'event' => 'authorization.access.denied',
                'threshold' => 20,
                'window_seconds' => 600,
                'severity' => 'high',
            ],
            'malware_upload_detected' => [
                'event' => 'file.upload.rejected',
                'threshold' => 1,
                'window_seconds' => 300,
                'severity' => 'critical',
            ],
        ],
    ],
],
```

Production `.env` example:

```env
AUDIT_ENABLED=true
AUDIT_FILE=/var/app/storage/audit/security-audit.log
AUDIT_MIRROR_TO_LOG=false

LOGGING_ENABLED=true
LOGGING_DEFAULT_CHANNEL=app
LOG_LEVEL=info
SECURITY_LOG_LEVEL=warning
APP_LOG_FILE=/var/app/storage/logs/app.jsonl
SECURITY_LOG_FILE=/var/app/storage/logs/security.jsonl

LOG_RETENTION_APP_DAYS=14
LOG_RETENTION_SECURITY_DAYS=90
LOG_RETENTION_AUDIT_DAYS=365
LOG_RETENTION_DEBUG_DAYS=7

MONITORING_ENABLED=true
MONITORING_METRICS_ENABLED=true
MONITORING_ALERTS_ENABLED=true
MONITORING_ALERT_CHANNELS=file
MONITORING_ALERT_FILE=/var/app/storage/logs/security-alerts.jsonl
MONITORING_EVENT_FILE=/var/app/storage/logs/monitoring-events.jsonl
```

---

## 5. Security model

The logging strategy follows these rules:

```text
Never log raw secrets.
Never log plaintext tokens.
Never log passwords or OTPs.
Never log complete private records unless explicitly required and protected.
Prefer IDs, hashes, fingerprints, event IDs, and request IDs.
Use structured JSON logs for machine parsing.
Use audit events for security-sensitive actions.
Use metrics and alerts for repeated or critical events.
Keep technical detail in private logs, not frontend responses.
```

Recommended data format:

```text
Bad:  User john@example.com failed password Secret123
Good: auth.login.failure actor_hash=ab12cd34 reason=bad_credentials
```

---

## 6. Creating the kernel

```php
<?php

use Mnb\SecurityCore\Core\SecurityKernel;

require __DIR__ . '/vendor/autoload.php';

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

---

## 7. Application logging usage

Use normal logging for operational events:

```php
$logger = $kernel->logger('app');

$logger->info('User profile page opened.', [
    'user_id' => 'user_123',
    'request_id' => 'req_abc123',
]);
```

Use the security channel for security-relevant warnings:

```php
$securityLogger = $kernel->securityLogger();

$securityLogger->warning('Suspicious request blocked.', [
    'ip' => '203.0.113.10',
    'path' => '/admin',
    'reason' => 'unknown_host',
]);
```

The log data protector redacts sensitive values before records are written.

Example input:

```php
$logger->info('Debug auth context.', [
    'user_id' => 'user_123',
    'authorization' => 'Bearer eyJhbGciOi...',
    'password' => 'secret-password',
]);
```

Safe output should replace sensitive values:

```json
{
  "authorization": "[redacted]",
  "password": "[redacted]"
}
```

---

## 8. Audit trail usage

Use the audit trail for important security actions:

```php
$audit = $kernel->auditTrail();

$audit->loginSuccess(
    actor: [
        'user_id' => 'user_123',
        'role' => 'admin',
    ],
    context: [
        'ip' => '203.0.113.10',
        'path' => '/login',
    ]
);
```

Login failure example:

```php
$audit->loginFailure(
    actor: [
        'user_hint' => 'email_hash:' . hash('sha256', strtolower($email)),
    ],
    context: [
        'ip' => $request->ip(),
        'path' => $request->path(),
    ],
    meta: [
        'reason' => 'bad_credentials',
    ]
);
```

Token revocation example:

```php
$audit->tokenRevoked(
    actor: [
        'admin_id' => 'admin_123',
    ],
    target: [
        'token_jti_hash' => hash('sha256', $jti),
    ],
    context: [
        'reason' => 'admin_revoke',
    ]
);
```

Admin action example:

```php
$audit->adminAction(
    action: 'user.role.updated',
    actor: [
        'admin_id' => 'admin_123',
    ],
    target: [
        'user_id' => 'user_456',
    ],
    context: [
        'old_role' => 'teacher',
        'new_role' => 'school_admin',
    ]
);
```

Sensitive action example:

```php
$audit->sensitiveAction(
    action: 'student.report.exported',
    actor: [
        'user_id' => 'user_123',
    ],
    target: [
        'export_id' => 'export_789',
    ],
    context: [
        'tenant_id' => 'school_001',
        'rows' => 150,
    ]
);
```

---

## 9. Building request audit context

`SecurityAuditTrail::contextFromRequest()` creates a safe request context.

```php
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

$context = SecurityAuditTrail::contextFromRequest($request, [
    'request_id' => $requestId,
    'route' => 'students.store',
]);

$kernel->auditTrail()->sensitiveAction(
    'student.created',
    actor: ['user_id' => 'user_123'],
    target: ['student_id' => 'student_456'],
    context: $context
);
```

Typical context fields:

```text
ip
remote_ip
method
path
host
user_agent
request_id
```

Do not add raw request bodies to audit context.

---

## 10. Tamper-evident audit log

`TamperEvidentAuditLogger` writes each audit record with:

```text
event_id
time
category
action
outcome
severity
actor
target
context
meta
previous_hash
hash
```

Each record contains the previous record hash. This creates a hash chain.

If a line is removed or modified, verification fails.

Verify audit integrity:

```bash
php vendor/bin/mnb-secure audit:verify
```

Or, if running from package source:

```bash
php bin/mnb-secure audit:verify
```

Expected result:

```json
{
  "passed": true,
  "valid": true,
  "file": "storage/audit/security-audit.log",
  "entries": 120,
  "failed_line": null,
  "error": null
}
```

Important: tamper-evident logging detects modification. It does not replace backups, immutable storage, file permissions, SIEM ingestion, or external log shipping.

---

## 11. Audit export

Export all audit records:

```bash
php bin/mnb-secure audit:export
```

Export only authentication audit events:

```bash
php bin/mnb-secure audit:export auth 100
```

Code usage:

```php
$exporter = $kernel->auditExporter();

$report = $exporter->export(
    category: 'auth',
    limit: 100
);

foreach ($report['entries'] as $entry) {
    // send to SIEM, review in admin panel, or attach to incident evidence
}
```

JSON Lines export:

```php
$jsonl = $kernel->auditExporter()->toJsonLines('database', 500);
file_put_contents(__DIR__ . '/database-audit.jsonl', $jsonl);
```

---

## 12. Auto audit middleware

Auto-audit can record safe request outcomes for selected operations.

Enable carefully:

```php
'audit' => [
    'auto' => [
        'enabled' => true,
        'log_reads' => false,
        'log_preflight' => false,
        'excluded_paths' => ['health', 'metrics'],
    ],
],
```

Middleware usage:

```php
$autoAuditMiddleware = $kernel->autoAuditMiddleware();

$response = $autoAuditMiddleware->process($request, $handler);
```

Recommended middleware order:

```text
1. Request trust / trusted host middleware
2. Server identity protection middleware
3. Safe error handling middleware
4. Rate limit middleware
5. Authentication middleware
6. Authorization middleware
7. Auto audit middleware
8. Route handler
```

Do not enable broad read logging unless you really need it. It can generate large logs and may create privacy noise.

---

## 13. Log redaction and data protection

`LogDataProtector` protects log records before writing them.

It redacts common keys:

```text
password
passwd
secret
token
api_key
authorization
cookie
session
csrf
otp
private_key
app_key
data_key
signed_url_key
webhook_secret
```

It also redacts common secret patterns in strings:

```text
password=...
secret=...
token=...
api_key=...
Bearer ...
APP_KEY=...
DATA_KEY=...
```

Example:

```php
$logger->warning('Third-party API failed.', [
    'provider' => 'example',
    'api_key' => 'live_abc123',
    'error' => '401 invalid token Bearer secret-token',
]);
```

Safe record:

```json
{
  "provider": "example",
  "api_key": "[redacted]",
  "error": "401 invalid token Bearer [redacted]"
}
```

For highly sensitive data, do not rely only on redaction. Do not log it at all.

---

## 14. Metrics usage

`MetricsRegistry` stores counters.

```php
$metrics = $kernel->metricsRegistry();

$metrics->increment('auth.login.success', [
    'strategy' => 'session',
]);

$metrics->increment('auth.login.failure', [
    'reason' => 'bad_credentials',
]);

$count = $metrics->get('auth.login.failure', [
    'reason' => 'bad_credentials',
]);
```

Get all counters:

```php
$all = $metrics->all();
```

Metrics are useful for:

```text
failed login counts
authorization denial counts
upload rejection counts
rate limit hits
queue failures
token revocations
origin protection blocks
runtime command blocks
outbound SSRF blocks
```

Avoid high-cardinality labels such as raw user IDs, full URLs, raw IP addresses, tokens, or unique request IDs.

Better:

```php
$metrics->increment('request.blocked', [
    'reason' => 'rate_limited',
    'route_group' => 'api',
]);
```

Avoid:

```php
$metrics->increment('request.blocked', [
    'raw_url' => $request->fullUrl(),
    'token' => $token,
]);
```

---

## 15. Alert rules

Alerts are triggered when event counts cross configured thresholds.

Example config:

```php
'monitoring' => [
    'alerts' => [
        'enabled' => true,
        'channels' => ['file'],
        'rules' => [
            'failed_login_spike' => [
                'event' => 'auth.login.failure',
                'threshold' => 10,
                'window_seconds' => 300,
                'severity' => 'high',
            ],
        ],
    ],
],
```

Record an event:

```php
$alerts = $kernel->alertManager()->recordEvent('auth.login.failure', [
    'ip_hash' => hash('sha256', $request->ip()),
    'strategy' => 'password',
]);

foreach ($alerts as $alert) {
    // optionally link alert to incident response
}
```

A generated alert includes:

```text
alert_id
time
rule
event
severity
count
window_seconds
context
```

---

## 16. File alert channel

The file alert channel writes alerts as JSON Lines.

```php
'monitoring' => [
    'alerts' => [
        'channels' => ['file'],
        'file' => __DIR__ . '/../storage/logs/security-alerts.jsonl',
    ],
],
```

This is the safest default for local development, shared hosting, and first deployment.

---

## 17. Webhook alert channel

Webhook alerts are supported, but should be used carefully.

```php
'monitoring' => [
    'alerts' => [
        'channels' => ['file', 'webhook'],
        'webhook_url' => getenv('MONITORING_ALERT_WEBHOOK_URL') ?: '',
    ],
],
```

The webhook channel integrates with the outbound HTTP protection engine, so webhook delivery benefits from:

```text
HTTPS enforcement
SSRF blocking
private IP blocking
redirect guard
timeout
max response size
safe audit behavior
```

Do not send alerts to untrusted or user-controlled webhook URLs.

---

## 18. Monitoring summary

Generate a monitoring summary:

```bash
php bin/mnb-secure monitor:summary
```

Code usage:

```php
$summary = $kernel->monitoringSummary()->toArray();

print_r($summary);
```

The summary combines:

```text
audit export state
audit integrity verification
metrics registry state
alert manager state
```

This is useful for dashboards and production health checks.

---

## 19. Retention policy

Logs should not grow forever.

Configure retention:

```php
'logging' => [
    'retention' => [
        'app_days' => 14,
        'security_days' => 90,
        'audit_days' => 365,
        'debug_days' => 7,
    ],
],
```

Run cleanup:

```bash
php bin/mnb-secure logs:purge
```

Purge a specific channel if supported by your configuration:

```bash
php bin/mnb-secure logs:purge app
php bin/mnb-secure logs:purge security
php bin/mnb-secure logs:purge audit
```

Recommended retention:

| Log type | Suggested retention |
|---|---:|
| Application logs | 7–30 days |
| Debug logs | 1–7 days |
| Security logs | 90–180 days |
| Audit logs | 365+ days, depending on policy |
| Incident evidence | Follow incident retention policy |

---

## 20. Which events should be audited?

Audit these events:

```text
login success/failure
logout
password change
password reset request/complete
MFA/OTP challenge success/failure
token issued/revoked/rotated
session revoked/forced logout
role or permission change
admin action
data export
sensitive record create/update/delete
file upload accepted/rejected
file download allowed/denied
malware detection
schema alteration
database hard delete
backup created/restored
incident opened/closed
security release gate pass/fail
```

Do not audit every harmless read by default unless compliance requires it.

---

## 21. Event naming convention

Use lowercase dot-separated event names:

```text
auth.login.success
auth.login.failure
authorization.access.denied
file.upload.rejected
database.schema.alter_blocked
token.refresh_reuse_detected
session.forced_logout
queue.job.dead_lettered
origin.direct_ip_host_blocked
runtime.process.blocked
network.outbound.blocked
```

Audit category and action should be safe slugs.

Good:

```text
auth.login
token.revoked
admin.user.role_updated
```

Bad:

```text
User deleted: john@example.com with token abc123
```

---

## 22. Actor, target, context, and meta

Recommended audit structure:

```php
$audit->record(SecurityAuditEvent::make(
    category: 'database',
    action: 'student.update',
    outcome: SecurityAuditEvent::OUTCOME_SUCCESS,
    severity: SecurityAuditEvent::SEVERITY_INFO,
    actor: [
        'user_id' => 'user_123',
        'role' => 'school_admin',
    ],
    target: [
        'resource' => 'student',
        'id' => 'student_456',
    ],
    context: [
        'tenant_id' => 'school_001',
        'request_id' => 'req_abc123',
    ],
    meta: [
        'changed_fields' => ['name', 'status'],
    ]
));
```

Field guidance:

| Field | Purpose | Should contain |
|---|---|---|
| `actor` | Who performed action | user ID, role, safe fingerprint |
| `target` | What was affected | resource type, resource ID |
| `context` | Where/how it happened | request ID, IP hash, route, tenant |
| `meta` | Extra safe details | reason codes, changed field names |

Avoid storing raw PII or secrets in any of these fields.

---

## 23. Linking logs to safe error responses

The safe error engine returns a request ID to the frontend.

Example frontend response:

```json
{
  "status": false,
  "message": "Something went wrong. Please try again later.",
  "error": {
    "code": "INTERNAL_ERROR",
    "request_id": "req_abc123"
  }
}
```

Internal log:

```php
$kernel->securityLogger()->error('Unhandled exception.', [
    'request_id' => 'req_abc123',
    'error_code' => 'INTERNAL_ERROR',
    'exception_class' => $exception::class,
]);
```

This lets support ask for `request_id` without exposing stack traces or SQL errors to the user.

---

## 24. Integrating with incident response

Alerts and audit evidence can feed incident response.

Example:

```php
$alerts = $kernel->alertManager()->recordEvent('token.refresh_reuse_detected', [
    'family_id_hash' => hash('sha256', $familyId),
]);

if ($alerts !== []) {
    $kernel->incidentResponse()->openIncident(
        type: 'token_compromise',
        severity: 'high',
        context: [
            'alerts' => $alerts,
            'family_id_hash' => hash('sha256', $familyId),
        ]
    );
}
```

Use incident integration for:

```text
refresh token reuse
malware upload
repeated authorization denial
origin bypass attempts
runtime command blocking
outbound SSRF attempts
audit integrity failure
backup verification failure
```

---

## 25. Integrating with queue/background jobs

Background jobs should log and audit safely.

```php
$kernel->auditTrail()->sensitiveAction(
    'queue.job.started',
    actor: ['worker_id' => 'worker_01'],
    target: ['job_id' => $jobId],
    context: ['queue' => 'files']
);

try {
    $handler->handle($job);

    $kernel->auditTrail()->sensitiveAction(
        'queue.job.succeeded',
        actor: ['worker_id' => 'worker_01'],
        target: ['job_id' => $jobId]
    );
} catch (Throwable $e) {
    $kernel->securityLogger()->error('Queue job failed.', [
        'job_id' => $jobId,
        'error_code' => 'JOB_FAILED',
        'exception_class' => $e::class,
    ]);
}
```

Do not log raw job payloads. Queue payloads may include sensitive identifiers or operational details.

---

## 26. Integrating with database governance

Database operations should record safe audit events.

Recommended events:

```text
database.search
database.find
database.create
database.update
database.delete
database.hard_delete
database.schema.add_column
database.schema.add_index
database.schema.alter_blocked
```

Example:

```php
$audit->record(SecurityAuditEvent::database(
    action: 'schema.add_column',
    outcome: SecurityAuditEvent::OUTCOME_SUCCESS,
    actor: ['admin_id' => 'admin_123'],
    target: [
        'table' => 'students',
        'column' => 'admission_number',
    ],
    context: [
        'dry_run' => false,
        'backup_verified' => true,
    ]
));
```

Avoid logging SQL with raw bindings. Log query shape, table name, operation, and binding count instead.

---

## 27. Integrating with file security

Recommended file events:

```text
file.upload.accepted
file.upload.rejected
file.upload.quarantined
file.download.allowed
file.download.denied
file.malware.detected
file.document.sanitized
file.retention.deleted
```

Example:

```php
$audit->uploadRejected(
    actor: ['user_id' => 'user_123'],
    target: ['file_name' => 'invoice.exe'],
    context: [
        'reason' => 'extension_not_allowed',
        'profile' => 'documents',
    ]
);
```

Do not log full private file paths if origin/path redaction is enabled. Prefer storage IDs.

---

## 28. Integrating with token and session control

Recommended token/session events:

```text
token.issued
token.validated
token.revoked
token.refresh_rotated
token.refresh_reuse_detected
token.family_revoked
session.created
session.rotated
session.revoked
session.forced_logout
session.concurrent_limit_exceeded
```

Example:

```php
$audit->tokenRejected(
    target: ['jti_hash' => hash('sha256', $jti)],
    context: ['reason' => 'revoked']
);
```

Never log raw access tokens, refresh tokens, remember-me tokens, or session IDs. Hash them first or use safe IDs.

---

## 29. Integrating with origin protection

Origin protection should log attempts to bypass public infrastructure.

Recommended events:

```text
origin.direct_ip_host_blocked
origin.untrusted_host_blocked
origin.forwarded_header_spoofing_blocked
origin.identity_headers_stripped
origin.leak_detected
origin.production_gate_blocked
```

Example:

```php
$kernel->alertManager()->recordEvent('origin.direct_ip_host_blocked', [
    'host' => '203.0.113.10',
    'ip_hash' => hash('sha256', $request->ip()),
]);
```

---

## 30. CLI reference

Verify audit hash chain:

```bash
php bin/mnb-secure audit:verify
```

Export audit records:

```bash
php bin/mnb-secure audit:export
php bin/mnb-secure audit:export auth 100
php bin/mnb-secure audit:export database 500
```

Purge logs by retention policy:

```bash
php bin/mnb-secure logs:purge
php bin/mnb-secure logs:purge app
php bin/mnb-secure logs:purge security
php bin/mnb-secure logs:purge audit
```

Show monitoring summary:

```bash
php bin/mnb-secure monitor:summary
```

Show alert rules and event count:

```bash
php bin/mnb-secure monitor:alerts
```

Run production checks:

```bash
php bin/mnb-secure check:production
php bin/mnb-secure production:readiness
php bin/mnb-secure final:gate
```

---

## 31. Testing examples

### Test that secrets are redacted

```php
$logger = $kernel->logger('app');

$logger->info('Secret test.', [
    'password' => 'secret123',
    'authorization' => 'Bearer abc.def.ghi',
]);

$contents = file_get_contents(__DIR__ . '/../storage/logs/app.jsonl');

assert(str_contains($contents, '[redacted]'));
assert(!str_contains($contents, 'secret123'));
assert(!str_contains($contents, 'abc.def.ghi'));
```

### Test audit integrity

```php
$audit = $kernel->auditTrail();

$audit->loginSuccess(['user_id' => 'user_123']);
$audit->tokenRevoked(target: ['jti_hash' => hash('sha256', 'token_123')]);

$result = $kernel->auditIntegrityVerifier()->verify();

assert($result['passed'] === true);
assert($result['valid'] === true);
```

### Test alert threshold

```php
$alerts = [];

for ($i = 0; $i < 10; $i++) {
    $alerts = $kernel->alertManager()->recordEvent('auth.login.failure', [
        'ip_hash' => 'ip_hash_123',
    ]);
}

assert($alerts !== []);
```

### Test retention purge

```php
$result = $kernel->logRetentionManager()->purge();

assert(isset($result['passed']));
```

---

## 32. Production checklist

Before production:

```text
[ ] Logging is enabled.
[ ] Audit is enabled.
[ ] Audit file path is outside public web root.
[ ] Log files are outside public web root.
[ ] Log redaction is enabled.
[ ] Secret redactor is enabled.
[ ] Safe error responses include request IDs.
[ ] Debug logging is disabled or heavily limited in production.
[ ] Audit integrity verification is scheduled.
[ ] Log retention policy is configured.
[ ] Security alert rules are configured.
[ ] Alert destination is tested.
[ ] Webhook alerts use only trusted HTTPS URLs.
[ ] Monitoring summary is checked by deployment/ops flow.
[ ] Audit logs are backed up or shipped if compliance requires it.
[ ] File permissions restrict logs to application/admin users only.
[ ] Raw request bodies are not logged.
[ ] Raw tokens/passwords/OTP values are not logged.
```

---

## 33. Recommended file permissions

Storage paths should not be public.

Recommended structure:

```text
storage/
  logs/
  audit/
  cache/
  private/
  backups/
```

Recommended permissions vary by hosting model, but the goal is:

```text
Application can write logs and audit records.
Web users cannot download logs directly.
Other system users cannot read secrets from logs.
Backups include audit files when required.
```

On Linux, a common starting point is:

```bash
chmod -R 750 storage
chmod -R 750 storage/logs storage/audit
```

Use your server user/group policy carefully.

---

## 34. Common mistakes

### Mistake 1: Logging raw tokens

Bad:

```php
$logger->debug('Token received.', ['token' => $token]);
```

Better:

```php
$logger->debug('Token received.', [
    'token_hash' => hash('sha256', $token),
]);
```

### Mistake 2: Logging raw request bodies

Bad:

```php
$logger->info('Request body.', $_POST);
```

Better:

```php
$logger->info('Request received.', [
    'route' => 'students.store',
    'field_count' => count($_POST),
]);
```

### Mistake 3: Storing audit logs in public directory

Bad:

```text
public/audit/security-audit.log
```

Good:

```text
storage/audit/security-audit.log
```

### Mistake 4: Using audit logs as debugging dumps

Audit logs should describe important actions, not dump raw objects.

Bad:

```php
$audit->sensitiveAction('student.created', meta: ['student' => $fullStudentRecord]);
```

Better:

```php
$audit->sensitiveAction('student.created', target: ['student_id' => $studentId]);
```

### Mistake 5: Alerting on high-cardinality unique values

Bad:

```php
$alertManager->recordEvent('login.failure.' . $email);
```

Good:

```php
$alertManager->recordEvent('auth.login.failure', [
    'email_hash' => hash('sha256', strtolower($email)),
]);
```

---

## 35. Recommended event catalog

Use a stable event catalog across the app.

Authentication:

```text
auth.login.success
auth.login.failure
auth.logout
auth.password.changed
auth.password.reset_requested
auth.password.reset_completed
```

Authorization:

```text
authorization.access.allowed
authorization.access.denied
authorization.field.denied
authorization.tenant_boundary.denied
```

API and rate limiting:

```text
api.token.accepted
api.token.rejected
rate_limit.allowed
rate_limit.blocked
```

Files:

```text
file.upload.accepted
file.upload.rejected
file.upload.quarantined
file.download.allowed
file.download.denied
file.malware.detected
```

Database:

```text
database.query.allowed
database.query.blocked
database.schema.plan_created
database.schema.alter_allowed
database.schema.alter_blocked
```

Runtime and network:

```text
runtime.process.allowed
runtime.process.blocked
network.outbound.allowed
network.outbound.blocked
```

Errors:

```text
error.safe_response.created
error.escalation.triggered
error.repeated_500.detected
```

Queue:

```text
queue.job.dispatched
queue.job.succeeded
queue.job.failed
queue.job.dead_lettered
```

Token and session:

```text
token.revoked
token.refresh_reuse_detected
session.revoked
session.forced_logout
```

Production and release:

```text
production.readiness.failed
release.gate.blocked
release.gate.passed
```

---

## 36. Example monitoring dashboard data

A simple admin dashboard can call:

```php
$summary = $kernel->monitoringSummary()->toArray();
$metrics = $kernel->metricsRegistry()->toArray();
$alerts = $kernel->alertManager()->summary();
$audit = $kernel->auditExporter()->export(limit: 50);
```

Recommended dashboard sections:

```text
Audit integrity status
Recent critical audit events
Recent alerts
Failed login count
Authorization denial count
Upload rejection count
Queue dead-letter count
Origin protection blocks
Token/session revocations
Last production readiness result
```

Do not show full logs to normal admins. Use role-based access and field masking.

---

## 37. Release readiness

Before releasing or deploying, run:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure audit:verify
php bin/mnb-secure monitor:summary
php bin/mnb-secure check:production
php bin/mnb-secure production:readiness
php bin/mnb-secure final:gate
```

For local testing:

```bash
php tests/run-tests.php
php demos/run-all-demos.php
```

A healthy logging/audit/monitoring setup should have:

```text
valid audit hash chain
redaction enabled
private log paths
alert rules configured
retention configured
monitoring summary available
no public log exposure
no raw secret leakage
```

---

## 38. Summary

The Logging, Audit, and Monitoring strategy provides the observability layer of **MNB Secure Core**.

It helps you:

```text
record operational logs safely,
protect logs from secret leakage,
record tamper-evident audit trails,
verify audit integrity,
export audit evidence,
track metrics,
raise threshold-based alerts,
clean old logs by policy,
link alerts to incident response,
prove security-sensitive activity happened.
```

Use normal logs for debugging, audit logs for security evidence, metrics for counters, and alerts for repeated or critical events.

The most important rule is simple:

```text
Log enough to investigate, but never log enough to compromise the system.
```
