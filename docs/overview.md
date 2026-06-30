# MNB Secure Core Overview

**Package:** `mnb/mnb-secure-core`  
**Current release line:** `v1.0.1`  
**Type:** Reusable no-framework PHP security library  
**PHP:** 8.1+  
**Install:** `composer require mnb/mnb-secure-core`

MNB Secure Core is a reusable PHP security foundation for custom applications that need production-grade security controls without depending on a full framework. It is suitable for APIs, admin panels, school/ERP systems, CRM tools, billing systems, reporting dashboards, internal tools, file-processing apps, and shared-hosting PHP projects.

The library provides modular security engines that can be used independently or through the central `SecurityKernel`.

---

## 1. What MNB Secure Core Does

MNB Secure Core helps developers protect the full application lifecycle:

```text
Incoming request
    ↓
Request trust, size, host, HTTPS, and method validation
    ↓
Authentication and token/session validation
    ↓
Authorization, tenant isolation, and permission checks
    ↓
Safe database/file/cache/runtime/network operations
    ↓
Safe response generation and safe error handling
    ↓
Audit logging, monitoring, verification, and production readiness checks
```

The goal is not to replace application business logic. The goal is to provide safe building blocks so business logic does not directly handle risky operations such as raw SQL, direct file storage, direct command execution, unguarded outbound HTTP calls, unsafe token/session handling, unescaped output, or unbounded background processing.

---

## 2. Why Use This Library

MNB Secure Core gives PHP applications a ready-made security foundation instead of forcing every project to rebuild security controls from scratch. It is useful when you need strong security in a custom PHP app but do not want to depend on a full framework.

Main advantages:

| Advantage | What it gives you |
| --- | --- |
| Reusable security foundation | One package for request security, auth, authorization, data protection, files, database safety, runtime protection, queues, tokens, sessions, logging, and production readiness. |
| Works with plain PHP | Suitable for no-framework projects, shared hosting, legacy apps, and custom PHP systems. |
| Policy-driven controls | Lets teams define allowed hosts, request profiles, database fields, queue jobs, commands, outbound URLs, token rules, session limits, and release gates. |
| Reduced implementation mistakes | Helps avoid common mistakes such as raw SQL, unescaped output, unsafe uploads, leaked logs, unrevoked tokens, duplicate jobs, and unbounded memory usage. |
| Better multi-tenant safety | Connects tenant context across authorization, database queries, cache keys, file access, sessions, logs, and audit events. |
| Safer operations | Adds diagnostics for production readiness, secrets, origin exposure, rate limits, queue pressure, memory usage, throughput, backups, and incident response. |
| Verification included | Provides pentest checklists, evidence bundles, remediation tracking, vulnerability matrix mapping, and release gates. |
| Composer-ready | Installs from Packagist using `composer require mnb/mnb-secure-core`. |

> For deeper documentation for each security engine, refer to the `docs/` directory. For runnable examples and integration samples, refer to the `examples/` and `demos/` directories.

---

## 3. Core Design Principles

### 2.1 No-framework by default

The package is designed for plain PHP projects. It can also be integrated into existing frameworks, but it does not require Laravel, Symfony, Slim, CodeIgniter, or any other framework.

### 2.2 SecurityKernel as the main entry point

Most engines are exposed through `Mnb\SecurityCore\Core\SecurityKernel`.

```php
<?php

require __DIR__ . '/../vendor/autoload.php';

use Mnb\SecurityCore\Env\EnvLoader;
use Mnb\SecurityCore\Core\SecurityKernel;

EnvLoader::load(__DIR__ . '/../.env');

$config = require __DIR__ . '/../config/security.php';
$kernel = new SecurityKernel($config);
```

### 2.3 Deny by default where risk is high

High-risk areas such as runtime commands, schema changes, raw database operations, queue jobs, outbound network calls, and token/session validity are designed to be controlled by policy and allow-lists.

### 2.4 Safe public output, detailed private diagnostics

Frontend users should receive clean and safe responses. Developers and operators should receive technical diagnostics only in protected logs with request IDs and redacted sensitive values.

### 2.5 Production readiness is a first-class feature

The package includes CLI checks, production gates, vulnerability matrix reports, release build planning, and configuration validation so apps can be reviewed before deployment.

---

## 4. Installation

Install from Packagist:

```bash
composer require mnb/mnb-secure-core
```

Copy the default security config into your app:

```bash
cp vendor/mnb/mnb-secure-core/config/security.php config/security.php
cp vendor/mnb/mnb-secure-core/.env.production.example .env
```

Create private storage folders outside the public web root:

```bash
mkdir -p storage/private \
         storage/quarantine \
         storage/cache \
         storage/logs \
         storage/audit \
         storage/backups \
         storage/queue \
         storage/tokens
```

Run basic checks:

```bash
php vendor/mnb/mnb-secure-core/bin/mnb-secure config:validate
php vendor/mnb/mnb-secure-core/bin/mnb-secure doctor
php vendor/mnb/mnb-secure-core/bin/mnb-secure production:readiness
```

---

## 5. Current v1.0.1 Security Engine Coverage

The current `v1.0.1` release line includes the following engines.

| Engine | Purpose |
| --- | --- |
| Trust Zones and Data Boundaries | Separates users, tenants, roles, resources, data classes, and execution boundaries. |
| Secure Request Receiving | Validates request method, size, host, HTTPS, trusted proxies, JSON input, and suspicious request patterns. |
| Authentication Strategy | Supports safe authentication flow patterns for users, APIs, sessions, webhooks, and internal calls. |
| Authorization Strategy | Enforces roles, permissions, scopes, ownership, tenant access, and field-level controls. |
| Data Protection | Provides encryption, masking, hashing, redaction, and export safety helpers. |
| Web Application Security | Adds output escaping, HTML sanitization, CSP/security headers, secure cookies, signed URLs, and safe redirects. |
| API Security and Rate Limiting | Protects API endpoints with token scope checks, throttling, rate policies, and abuse controls. |
| File Upload, Download, and Document Security | Validates uploads, isolates private files, supports malware scanning hooks, and protects downloads. |
| Cache Strategy | Provides tenant-aware cache keys, TTL policies, sensitive-cache rules, invalidation, and stampede protection. |
| Environment and Secret Management | Loads `.env`, validates secrets, redacts sensitive values, and reports secret readiness. |
| Logging, Audit, and Monitoring | Provides structured logs, tamper-evident audit events, security metrics, alerting, and retention controls. |
| Backup, Recovery, and Incident Response | Supports encrypted/signed backups, restore dry-runs, incident playbooks, and evidence collection. |
| Vulnerability Blocking Matrix | Maps OWASP/CWE-style risks to implemented controls, gaps, recommendations, and verification status. |
| Runtime Execution and Outbound Network Security | Protects process execution, command allow-lists, outbound HTTP, SSRF, DNS, and redirects. |
| Secure Database Governance | Controls connection, CRUD, search, query limits, tenant scoping, schema plans, transactions, and masking. |
| Security Verification and Remediation | Adds pentest checklists, evidence bundles, remediation SLAs, retest gates, release gates, and coverage reports. |
| Safe Error Response and Technical Log Isolation | Produces safe public errors while isolating technical logs with redaction, fingerprints, and escalation rules. |
| Memory Governance and Resource Safety | Adds memory profiles, stream guards, bounded buffers, payload depth checks, temp file budgets, and worker leak checks. |
| Throughput Governance and Performance Capacity | Adds latency budgets, concurrency limiting, adaptive throttling, queue pressure, SLOs, and capacity release gates. |
| Origin Identity Protection | Protects against direct IP Host access, origin leaks, proxy spoofing, fingerprint headers, and CDN bypass risks. |
| Async Queue and Background Jobs | Provides secure job dispatch, 202 responses, idempotency, retries, dead-letter queue, and worker supervision. |
| Token Revocation and Session Control | Provides token revocation, refresh rotation, session registry, forced logout, device sessions, and remember-me safety. |
| Final Production Readiness and XSS Enforcement | Adds safe template rendering, unsafe output scanning, production checklist, release manifest, and final gates. |

---

## 6. High-Level Architecture

```text
Application
    ↓
SecurityKernel
    ├── Request / Trust / Host / Proxy Protection
    ├── Auth / Token / Session Control
    ├── Authorization / Tenant / Resource Access
    ├── Web / XSS / Headers / Cookies / Redirects
    ├── Database / Query / Schema Governance
    ├── Files / Documents / Downloads
    ├── Runtime / Process Execution Safety
    ├── Network / Outbound HTTP / SSRF Guard
    ├── Cache / Secrets / Data Protection
    ├── Queue / Background Jobs / Worker Safety
    ├── Memory / Throughput / Capacity Controls
    ├── Logging / Audit / Monitoring / Incident Response
    ├── Verification / Remediation / Release Gates
    └── Production Readiness / Vulnerability Matrix
```

Each engine focuses on a specific security boundary, but the strongest protection comes from using them together.

---

## 7. Basic Usage Pattern

### 6.1 Bootstrap the kernel

```php
use Mnb\SecurityCore\Env\EnvLoader;
use Mnb\SecurityCore\Core\SecurityKernel;

EnvLoader::load(__DIR__ . '/../.env');

$config = require __DIR__ . '/../config/security.php';
$kernel = new SecurityKernel($config);
```

### 6.2 Validate production configuration

```php
$report = $kernel->finalProductionReadinessChecker()->check();

if (!$report->isReady()) {
    foreach ($report->findings() as $finding) {
        echo $finding['message'] . PHP_EOL;
    }
}
```

### 6.3 Escape output safely

```php
$renderer = $kernel->safeTemplateRenderer();

echo $renderer->render('Hello, {{ name }}', [
    'name' => '<script>alert(1)</script>',
]);
```

### 6.4 Run a safe outbound request

```php
$response = $kernel->outboundHttpClient()->get('https://api.example.com/status');
```

### 6.5 Dispatch background work safely

```php
$result = $kernel->jobDispatcher()->dispatch(
    name: 'file_scan',
    payload: ['file_id' => $fileId],
    queue: 'files',
    idempotencyKey: 'file_scan:' . $fileId
);
```

### 6.6 Revoke a token

```php
$kernel->tokenRevocationService()->revoke(
    tokenId: $jti,
    reason: 'logout'
);
```

---

## 8. Recommended Middleware Order

For web/API applications, apply middleware in this order where applicable:

```text
1. ErrorHandlingMiddleware
2. ServerIdentityProtectionMiddleware
3. TrustedHostMiddleware
4. RequestTrustMiddleware
5. SecureRequestMiddleware
6. ThroughputMiddleware
7. RateLimitMiddleware
8. AuthenticationMiddleware
9. Session/Token validation middleware
10. CsrfMiddleware for browser state-changing routes
11. Authorization middleware
12. Application controller/handler
```

This order ensures unsafe requests are rejected early, errors are safely handled, and authenticated/authorized logic runs only after basic request trust is established.

---

## 9. CLI Overview

The package includes a CLI tool:

```bash
php vendor/mnb/mnb-secure-core/bin/mnb-secure <command>
```

Important command groups:

```text
config:*          Configuration validation
security:*        Security checks and release gates
vulnerabilities:* Vulnerability matrix reports
request:*         Request trust and receiving checks
auth:*            Authentication diagnostics
rate:*            Rate limiting diagnostics
files:*           File security checks
db:*              Database governance checks
runtime:*         Runtime command safety checks
outbound:*        Outbound network/SSRF checks
pentest:*         Verification/remediation checks
errors:*          Safe error response checks
memory:*          Memory/resource checks
throughput:*      Performance/capacity checks
origin:*          Origin exposure checks
queue:*           Queue/background job checks
token:*           Token revocation checks
session:*         Session control checks
xss:*             Output encoding/XSS checks
production:*      Production readiness checks
release:*         Release planning and manifest checks
final:*           Final release gate
```

Common production checks:

```bash
php vendor/mnb/mnb-secure-core/bin/mnb-secure config:validate
php vendor/mnb/mnb-secure-core/bin/mnb-secure doctor
php vendor/mnb/mnb-secure-core/bin/mnb-secure vulnerabilities:report
php vendor/mnb/mnb-secure-core/bin/mnb-secure production:readiness
php vendor/mnb/mnb-secure-core/bin/mnb-secure final:gate
```

---

## 10. Production Responsibilities

Some security controls require application or server configuration. The library provides checks, helpers, and gates, but the production app must still configure real values.

Required production items:

```text
APP_ENV=production
APP_DEBUG=false
APP_KEY with strong random value
DATA_ENCRYPTION_KEY with strong random value
DATA_SEARCH_HASH_KEY with strong random value
SIGNED_URL_KEY with strong random value
REQUEST_WEBHOOK_SECRET with strong random value when webhooks are used
HTTPS enabled
Trusted hosts configured
Trusted proxies/CDN configured if behind proxy
Origin firewall rules configured when hiding server IP
Writable private storage outside public web root
Database user privileges restricted
Queue workers supervised
Logs/audit/backup retention configured
```

Recommended checks before deployment:

```bash
php vendor/mnb/mnb-secure-core/bin/mnb-secure production:env-checklist
php vendor/mnb/mnb-secure-core/bin/mnb-secure origin:production-gate
php vendor/mnb/mnb-secure-core/bin/mnb-secure performance:release-gate
php vendor/mnb/mnb-secure-core/bin/mnb-secure queue:release-gate
php vendor/mnb/mnb-secure-core/bin/mnb-secure security:release-gate production_release
php vendor/mnb/mnb-secure-core/bin/mnb-secure final:gate
```

---

## 11. Validation Status

Latest local validation from the current `v1.0.1` upgrade line:

| Check | Result |
| --- | ---: |
| PHP lint | Passed |
| Tests | 398 passed, 0 failed |
| Demo suite | Passed |
| Config validation | Passed |
| Vulnerability score | 99.05 |
| Vulnerability grade | A+ |

Production `doctor` results can still warn until real `.env`, HTTPS, CDN/proxy, secrets, database, and filesystem settings are configured in the deployed application.

---

## 12. Release Line Summary

The current `v1.0.1` release line includes the following major upgrade packages:

| Upgrade | Title |
| ---: | --- |
| 27 | Runtime Execution and Outbound Network Security Engine |
| 28 | Secure Database Governance and Query Lifecycle Engine |
| 29 | Security Verification, Remediation, and Evidence Automation Engine |
| 30 | Safe Error Response and Technical Log Isolation Engine |
| 31 | Memory Governance and Resource Safety Engine |
| 32 | Throughput Governance and Performance Capacity Engine |
| 33 | Origin Identity Protection and Exposure Hardening Engine |
| 34 | Async Request, Response Queue, and Background Job Orchestration Engine |
| 35 | Token Revocation and Session Control Engine |
| 36 | Final Production Readiness, XSS Enforcement, and Release Consolidation Patch |

All of these are still under `v1.0.1` according to the current release decision.

---

## 13. What This Overview Is Not

This overview does not replace feature-specific documentation. Each engine should have its own dedicated document under `docs/`.

Recommended documentation sequence:

```text
docs/overview.md
docs/installation.md
docs/configuration.md
docs/request-security.md
docs/authentication.md
docs/authorization.md
docs/web-security.md
docs/database-governance.md
docs/runtime-network-security.md
docs/error-handling.md
docs/memory-resource-safety.md
docs/throughput-capacity.md
docs/origin-protection.md
docs/queue-background-jobs.md
docs/token-session-control.md
docs/production-readiness.md
docs/cli-reference.md
```

---

## 14. Key Takeaway

MNB Secure Core is a defense-in-depth security library for PHP applications. It gives developers a centralized, reusable, and testable set of security controls covering request handling, authentication, authorization, data, files, database operations, runtime commands, outbound network calls, queues, tokens, sessions, logs, errors, memory, throughput, origin protection, verification, and production readiness.

Use it as the security foundation of your application, then connect your app-specific business logic to the relevant engines through `SecurityKernel`.
