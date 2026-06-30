# Data Protection Strategy

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Document type:** Detailed feature documentation and code usage  
**Feature area:** Data classification, field protection, encryption at rest, searchable hashes, masking, response filtering, log redaction, safe export, encrypted storage, backup protection, tenant-aware data handling

---

## 1. Overview

The **Data Protection Strategy** controls how sensitive data is classified, stored, searched, returned, logged, exported, and backed up.

Authentication and authorization decide who can access the system. Data protection decides what happens to the data itself:

```text
Should this field be encrypted before storage?
Should this value be searchable without exposing plaintext?
Should this field be masked in API responses?
Should this field be removed from logs?
Should this field be excluded from CSV exports?
Should this file be encrypted at rest?
```

`mnb-secure-core` provides a policy-driven data protection layer. You define resources and fields, then the library applies consistent protection rules before storage, before response, before logging, and before export.

Typical protected resources:

```text
users
students
parents
employees
payments
orders
medical_records
documents
audit_exports
backups
api_tokens
```

Typical protected fields:

```text
email
phone
parent_phone
aadhaar_number
pan_number
payment_reference
address
password_hash
api_token
refresh_token
private_note
```

The strategy follows these defaults:

```text
Classify data before handling it.
Encrypt sensitive fields before storage.
Use keyed search hashes instead of plaintext lookup values.
Mask sensitive fields before returning API responses.
Redact sensitive fields before logging.
Exclude highly sensitive fields from exports.
Protect CSV exports from formula injection.
Keep encryption keys outside source code.
Audit sensitive protection workflows.
```

---

## 2. Why Data Protection Matters

Many applications protect routes but still leak sensitive data through storage, logs, exports, or debugging tools.

Common risks:

```text
Plaintext PII in database
Plaintext API tokens in database
Passwords or token values in logs
Sensitive fields returned in API JSON
CSV formula injection during export
Backup files containing raw secrets
Search indexes containing sensitive plaintext
Developers accidentally exposing password_hash fields
Production logs containing phone/email/payment values
Data retained longer than expected
Missing encryption key rotation plan
```

The Data Protection Strategy reduces these risks using:

```text
Data classification
Resource-level policies
Field-level rules
AES-256-GCM encryption
Key-ring based encryption keys
Authenticated additional data / AAD support
Keyed HMAC search hashing
Response masking
Log redaction
Export filtering
CSV formula-injection protection
Encrypted private storage integration
Audit events for sensitive workflows
```

Recommended safe data lifecycle:

```text
Incoming request
    ↓
Secure request receiving
    ↓
Validation and authorization
    ↓
Data protection policy lookup
    ↓
Protect for storage
    ↓
Secure database / encrypted file storage
    ↓
Protect for response / log / export
    ↓
Safe output or audit trail
```

---

## 3. Main Classes

Data protection is mainly built around these classes:

```text
Mnb\SecurityCore\Data\DataClassifier
Mnb\SecurityCore\Data\DataMasker
Mnb\SecurityCore\Data\DataProtectionPolicy
Mnb\SecurityCore\Data\DataProtectionRegistry
Mnb\SecurityCore\Data\DataProtectionDecision
Mnb\SecurityCore\Data\ProtectedField
Mnb\SecurityCore\Data\ProtectedPayload
Mnb\SecurityCore\Data\FieldFilter
Mnb\SecurityCore\Data\FieldProtector
Mnb\SecurityCore\Data\Encryption
Mnb\SecurityCore\Data\KeyRing
Mnb\SecurityCore\Data\KeyProviderInterface
Mnb\SecurityCore\Data\SearchHash
Mnb\SecurityCore\Data\ExportPolicy
Mnb\SecurityCore\Data\SafeCsvExporter
```

Related encrypted file storage classes:

```text
Mnb\SecurityCore\Files\EncryptedStorage
Mnb\SecurityCore\Files\LocalPrivateStorage
```

Related database protection classes:

```text
Mnb\SecurityCore\Database\SecureDatabase
Mnb\SecurityCore\Database\DatabaseResultFilter
Mnb\SecurityCore\Database\DatabaseFieldProtection
Mnb\SecurityCore\Database\TableSecurityPolicy
```

Related logging and error redaction classes:

```text
Mnb\SecurityCore\Logging\LogDataProtector
Mnb\SecurityCore\Errors\ErrorLogSanitizer
```

Related production readiness classes:

```text
Mnb\SecurityCore\Production\FinalProductionReadinessChecker
Mnb\SecurityCore\Production\EnvChecklistBuilder
```

---

## 4. Installation

Install from Packagist:

```bash
composer require mnb/mnb-secure-core
```

Load Composer autoload:

```php
require __DIR__ . '/vendor/autoload.php';
```

Typical config path after Composer installation:

```text
vendor/mnb/mnb-secure-core/config/security.php
```

In a real app, copy the config file into your own application config folder and override values with environment variables.

---

## 5. Data Classification Model

The library supports these primary data classes:

```text
public
internal
confidential
sensitive
highly_sensitive
```

Recommended meaning:

| Class | Meaning | Example | Typical protection |
|---|---|---|---|
| `public` | Safe to show publicly | Public notice title | No encryption required |
| `internal` | App/internal data | Record ID, status, class name | Return only to allowed users |
| `confidential` | Private user/business data | Email, address | Mask in response/log/export as needed |
| `sensitive` | Strongly protected PII/financial data | Phone, parent phone, payment reference | Encrypt/search-hash/mask/redact |
| `highly_sensitive` | Secrets or extremely private data | Password hash, token, API key | Never return/export/log |

Example with `DataClassifier`:

```php
use Mnb\SecurityCore\Data\DataClassifier;

$classifier = new DataClassifier([
    'name' => DataClassifier::INTERNAL,
    'email' => DataClassifier::CONFIDENTIAL,
    'parent_phone' => DataClassifier::SENSITIVE,
    'password_hash' => DataClassifier::HIGHLY_SENSITIVE,
]);

echo $classifier->classify('email');       // confidential
echo $classifier->classify('unknown');     // internal by default
```

Check whether a field is sensitive:

```php
if ($classifier->isSensitive('parent_phone')) {
    // Apply stronger protection before response/log/export.
}
```

---

## 6. Configuration

The current configuration block is named `data_protection`.

Example production-ready structure:

```php
return [
    'app' => [
        'env' => $_ENV['APP_ENV'] ?? 'production',
        'key' => $_ENV['APP_KEY'] ?? '',
    ],

    'data_protection' => [
        'enabled' => true,
        'default_class' => 'internal',
        'deny_unclassified_fields' => false,
        'audit' => true,

        'encryption' => [
            'enabled' => true,
            'current_key_id' => $_ENV['DATA_KEY_ID'] ?? 'app-v1',
            'keys' => [
                $_ENV['DATA_KEY_ID'] ?? 'app-v1' => $_ENV['DATA_KEY'] ?? '',
            ],
            'aad' => true,
        ],

        'search_hash' => [
            'enabled' => true,
            'key' => $_ENV['DATA_SEARCH_HASH_KEY'] ?? '',
            'prefix' => $_ENV['DATA_SEARCH_HASH_PREFIX'] ?? 'mnb:search',
        ],

        'resources' => [
            'students' => [
                'default_class' => 'sensitive',
                'tenant_scoped' => true,
                'fields' => [
                    'id' => [
                        'class' => 'internal',
                    ],
                    'name' => [
                        'class' => 'internal',
                    ],
                    'email' => [
                        'class' => 'confidential',
                        'encrypt' => true,
                        'search_hash' => true,
                        'mask' => 'email',
                        'export' => 'masked',
                        'log' => false,
                    ],
                    'parent_phone' => [
                        'class' => 'sensitive',
                        'encrypt' => true,
                        'search_hash' => true,
                        'mask' => 'last4',
                        'export' => 'masked',
                        'log' => false,
                    ],
                    'password_hash' => [
                        'class' => 'highly_sensitive',
                        'read' => false,
                        'write' => false,
                        'export' => false,
                        'log' => false,
                    ],
                ],
            ],
        ],

        'exports' => [
            'csv_injection_protection' => true,
            'audit' => true,
            'max_rows' => 50000,
        ],

        'storage' => [
            'encrypt_files' => true,
        ],

        'backups' => [
            'encrypt' => true,
            'sign' => true,
            'retention_days' => 30,
        ],

        'logs' => [
            'redact_before_write' => true,
        ],
    ],
];
```

---

## 7. Environment Variables

Recommended `.env` values:

```env
APP_ENV=production
APP_KEY=replace_with_32_plus_character_random_secret

DATA_PROTECTION_ENABLED=true
DATA_PROTECTION_DEFAULT_CLASS=internal
DATA_PROTECTION_AUDIT=true

DATA_ENCRYPTION_ENABLED=true
DATA_KEY_ID=app-v1
DATA_KEY=replace_with_32_plus_character_random_data_key
DATA_ENCRYPTION_AAD=true

DATA_SEARCH_HASH_ENABLED=true
DATA_SEARCH_HASH_KEY=replace_with_32_plus_character_random_hash_key
DATA_SEARCH_HASH_PREFIX=mnb:search

DATA_EXPORT_MAX_ROWS=50000
DATA_ENCRYPT_FILES=true
DATA_BACKUP_ENCRYPT=true
DATA_BACKUP_SIGN=true
DATA_BACKUP_RETENTION_DAYS=30
```

Important:

```text
Do not commit real keys to Git.
Use 32+ character random secrets.
Use different keys for app key, encryption key, and search hash key.
Rotate keys through a planned process.
Back up keys securely, because encrypted data cannot be recovered without them.
```

---

## 8. Field Policy Options

Each protected field can define:

```text
class        Data classification.
encrypt      Whether to encrypt before storage.
search_hash  Whether to create a keyed search hash companion field.
mask         How to mask before response/export/log.
read         Whether field may be returned.
write        Whether field may be accepted for storage.
export       Whether/how field may be exported.
log          Whether field may be written to logs.
```

Example:

```php
'email' => [
    'class' => 'confidential',
    'encrypt' => true,
    'search_hash' => true,
    'mask' => 'email',
    'read' => true,
    'write' => true,
    'export' => 'masked',
    'log' => false,
],
```

Field behavior:

| Option | Effect |
|---|---|
| `encrypt: true` | Stores encrypted value using `KeyRing`. |
| `search_hash: true` | Adds `{field}_hash` for secure exact lookup. |
| `mask: email` | Masks email in responses/exports. |
| `mask: last4` | Shows only last four digits. |
| `mask: hidden` | Returns `[hidden]`. |
| `read: false` | Removes field from API responses. |
| `write: false` | Removes field before storage. |
| `export: false` | Excludes field from exports. |
| `export: masked` | Includes masked value in exports. |
| `log: false` | Redacts field before logging. |

---

## 9. Build a Data Protection Registry from Config

The easiest way is through `DataProtectionRegistry::fromConfig()`.

```php
use Mnb\SecurityCore\Data\DataProtectionRegistry;

$config = require __DIR__ . '/config/security.php';

$registry = DataProtectionRegistry::fromConfig($config);
```

With audit trail:

```php
use Mnb\SecurityCore\Data\DataProtectionRegistry;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;

$audit = new SecurityAuditTrail(
    new TamperEvidentAuditLogger(__DIR__ . '/storage/audit/security.log')
);

$registry = DataProtectionRegistry::fromConfig($config, $audit);
```

---

## 10. Protect Data Before Storage

Before storing user or business data, call `protectForStorage()`.

```php
$student = [
    'id' => 44,
    'name' => 'Ravi Kumar',
    'email' => 'ravi@example.com',
    'parent_phone' => '9876543210',
    'password_hash' => '$2y$...',
];

$stored = $registry->protectForStorage('students', $student);
```

Possible result:

```php
[
    'id' => 44,
    'name' => 'Ravi Kumar',
    'email' => 'mnbenc:...',
    'email_hash' => '8ce6...',
    'parent_phone' => 'mnbenc:...',
    'parent_phone_hash' => '77b4...',
    // password_hash removed because write=false
]
```

Why this is useful:

```text
The database does not receive plaintext sensitive values.
Exact search remains possible through keyed hash fields.
Protected fields are removed before storage.
Highly sensitive fields can be blocked from write/update paths.
```

---

## 11. Decrypt Data for Internal Use

Use `unprotectFromStorage()` only in trusted internal service logic.

```php
$plain = $registry->unprotectFromStorage('students', $stored);
```

Important:

```text
Do not return this directly to frontend.
Do not log this directly.
Do not export this directly.
Use protectForResponse(), protectForLog(), or protectForExport() for outbound paths.
```

---

## 12. Protect Data Before API Response

Before returning JSON to a browser, app, or API client:

```php
$response = $registry->protectForResponse('students', $stored);

return json_encode([
    'status' => true,
    'data' => $response,
]);
```

Example response:

```json
{
  "id": 44,
  "name": "Ravi Kumar",
  "email": "r***@example.com",
  "parent_phone": "******3210"
}
```

Notice:

```text
Encrypted fields were decrypted internally.
Search hash fields were removed.
Highly sensitive fields were removed.
Sensitive fields were masked.
```

---

## 13. Protect Data Before Logging

Never log raw user records.

Bad:

```php
$logger->info('student saved', $student);
```

Good:

```php
$logSafe = $registry->protectForLog('students', $stored);

$logger->info('student saved', [
    'student' => $logSafe,
]);
```

Example log-safe result:

```php
[
    'id' => 44,
    'name' => 'Ravi Kumar',
    'email' => '[redacted]',
    'parent_phone' => '[redacted]',
]
```

This reduces:

```text
PII exposure in logs
Token/secret leakage
Payment reference leakage
Sensitive incident artifact leakage
```

---

## 14. Protect Data Before Export

Use `protectForExport()` before generating reports, CSVs, or downloadable files.

```php
$exportSafe = $registry->protectForExport('students', $stored);
```

For CSV, use `SafeCsvExporter`:

```php
use Mnb\SecurityCore\Data\ExportPolicy;
use Mnb\SecurityCore\Data\SafeCsvExporter;

$exporter = new SafeCsvExporter(
    $registry,
    new ExportPolicy([
        'csv_injection_protection' => true,
        'max_rows' => 50000,
        'audit' => true,
    ])
);

$csv = $exporter->export('students', [$stored]);

file_put_contents(__DIR__ . '/storage/private/students.csv', $csv);
```

CSV protection includes:

```text
Sensitive field masking
Highly sensitive field exclusion
Search hash field removal
CSV formula-injection protection
Maximum row limit
```

CSV formula injection example:

```text
=HYPERLINK("http://evil.test")
```

Safe output is prefixed:

```text
'=HYPERLINK("http://evil.test")
```

---

## 15. Search Encrypted Fields Safely

Encrypted values cannot be searched directly. The recommended pattern is to store a keyed HMAC search hash.

Configuration:

```php
'email' => [
    'class' => 'confidential',
    'encrypt' => true,
    'search_hash' => true,
    'mask' => 'email',
],
```

When saving:

```php
$stored = $registry->protectForStorage('students', [
    'email' => 'ravi@example.com',
]);

// $stored['email']      = encrypted value
// $stored['email_hash'] = keyed HMAC search hash
```

When searching:

```php
$emailHash = $registry->searchHash('students', 'email', 'ravi@example.com');

// Use this in a secure DB query:
// WHERE email_hash = :email_hash
```

With `SecureDatabase`, keep query building policy-driven:

```php
$hash = $registry->searchHash('students', 'email', $requestEmail);

$rows = $secureDb->search(
    $context,
    $studentTablePolicy,
    filters: [
        'email_hash' => ['eq' => $hash],
    ]
);
```

Important:

```text
Search hashes should use a separate secret key.
Do not use unsalted plain hashes like md5/sha1/sha256(value).
Do not expose search hash fields in responses, logs, or exports.
```

---

## 16. KeyRing Encryption

`KeyRing` provides AES-256-GCM encryption with key identifiers.

```php
use Mnb\SecurityCore\Data\KeyRing;

$keyRing = new KeyRing('app-v1', [
    'app-v1' => 'replace_with_32_plus_character_secret_key',
]);

$cipher = $keyRing->encrypt('private value', 'students:email');
$plain = $keyRing->decrypt($cipher, 'students:email');
```

Encrypted values use the prefix:

```text
mnbenc:
```

Check whether a value is already encrypted:

```php
if ($keyRing->isEncrypted($cipher)) {
    // already encrypted
}
```

Why AAD matters:

```text
AAD binds encrypted data to a resource/field context.
If a ciphertext from students:email is moved to payments:reference, decryption can fail.
This reduces copy/paste or field-swapping abuse.
```

---

## 17. Key Rotation Strategy

A safe key rotation plan should use key IDs.

Initial config:

```php
'encryption' => [
    'current_key_id' => 'app-v1',
    'keys' => [
        'app-v1' => $_ENV['DATA_KEY_V1'],
    ],
],
```

During rotation:

```php
'encryption' => [
    'current_key_id' => 'app-v2',
    'keys' => [
        'app-v1' => $_ENV['DATA_KEY_V1'], // old data can still decrypt
        'app-v2' => $_ENV['DATA_KEY_V2'], // new writes use this
    ],
],
```

Recommended rotation workflow:

```text
1. Add new key to key ring.
2. Set current_key_id to the new key.
3. Keep old key available for decrypting existing data.
4. Re-encrypt old records in a controlled background job.
5. Verify data access and backups.
6. Remove old key only after all old ciphertext has been migrated and backups are handled.
```

Do not:

```text
Overwrite the old key.
Delete the old key before re-encryption is complete.
Use the same key for all purposes.
Log key values.
Commit keys to Git.
```

---

## 18. Simple Field Filtering

For simple cases, `FieldFilter` can mask or allow selected fields.

```php
use Mnb\SecurityCore\Data\DataClassifier;
use Mnb\SecurityCore\Data\DataMasker;
use Mnb\SecurityCore\Data\FieldFilter;

$classifier = new DataClassifier([
    'student_name' => DataClassifier::CONFIDENTIAL,
    'parent_phone' => DataClassifier::SENSITIVE,
    'fee_payment_ref' => DataClassifier::HIGHLY_SENSITIVE,
]);

$filter = new FieldFilter($classifier, new DataMasker());

$record = [
    'student_name' => 'Rahul Kumar',
    'parent_phone' => '9876543210',
    'fee_payment_ref' => 'rzp_secret_reference_123',
    'public_notice' => 'Holiday tomorrow',
];

$masked = $filter->maskSensitive($record);
$publicApi = $filter->allowOnly($record, ['student_name', 'public_notice']);
```

Example output:

```php
[
    'student_name' => 'Rahul Kumar',
    'parent_phone' => '[masked]',
    'fee_payment_ref' => '[hidden]',
    'public_notice' => 'Holiday tomorrow',
]
```

Use this for lightweight field filtering. For full production workflows, prefer `DataProtectionRegistry`.

---

## 19. Encrypted Private File Storage

Data protection is not only database fields. Sensitive file contents should also be encrypted when stored privately.

Example:

```php
use Mnb\SecurityCore\Data\KeyRing;
use Mnb\SecurityCore\Files\EncryptedStorage;
use Mnb\SecurityCore\Files\LocalPrivateStorage;

$keyRing = new KeyRing('storage-v1', [
    'storage-v1' => 'replace_with_32_plus_character_storage_key',
]);

$storage = new EncryptedStorage(
    new LocalPrivateStorage(__DIR__ . '/storage/private'),
    $keyRing
);

$storage->put('exports/students.txt', 'private export body');

$plain = $storage->read('exports/students.txt');
```

The raw stored file should not contain plaintext:

```php
$raw = file_get_contents(__DIR__ . '/storage/private/exports/students.txt');

if (str_contains($raw, 'private export body')) {
    throw new RuntimeException('File was stored in plaintext.');
}
```

Use encrypted private storage for:

```text
Sensitive exports
Private reports
Uploaded documents after scanning
Backup artifacts
Temporary incident evidence
Audit bundles
```

---

## 20. Secure Database Integration

Data protection should be applied before data enters the secure database layer.

Example create flow:

```php
$input = [
    'name' => $_POST['name'] ?? '',
    'email' => $_POST['email'] ?? '',
    'parent_phone' => $_POST['parent_phone'] ?? '',
    'password_hash' => 'should_not_be_written_here',
];

$protected = $registry->protectForStorage('students', $input);

$studentId = $secureDb->create(
    $authContext,
    $studentTablePolicy,
    $protected
);
```

Example response flow:

```php
$row = $secureDb->findById($authContext, $studentTablePolicy, $studentId);

$safe = $registry->protectForResponse('students', $row);

return json_encode([
    'status' => true,
    'data' => $safe,
]);
```

Important order:

```text
Validate input first.
Authorize action.
Apply data protection.
Use secure database policies.
Return data through response protection.
Log only log-safe data.
```

---

## 21. Tenant-Aware Data Protection

A resource can be marked tenant scoped:

```php
'users' => [
    'default_class' => 'sensitive',
    'tenant_scoped' => true,
    'fields' => [
        'tenant_id' => ['class' => 'internal'],
        'email' => ['class' => 'confidential', 'encrypt' => true, 'search_hash' => true],
    ],
],
```

This means:

```text
Data protection policy knows the resource belongs to a tenant.
Authorization/database layers should enforce tenant access.
Logs/exports should avoid leaking cross-tenant data.
```

Recommended tenant-safe flow:

```text
Auth context identifies user.
Tenant guard resolves tenant.
Authorization checks tenant/resource permission.
Database query includes tenant scope.
Data protection masks/encrypts per field.
Response contains only allowed data.
```

---

## 22. Logging and Audit Behavior

When enabled, `DataProtectionRegistry` records audit events for sensitive protection actions such as:

```text
protected.storage
protected.export
```

Audit events should include safe metadata only:

```text
resource name
field count
operation outcome
request ID if available
actor hash if available
tenant hash if available
```

Audit events should not include:

```text
plain email
plain phone
plain token
plain payment reference
private encryption keys
raw ciphertext unless required
```

Example with audit:

```php
$registry = DataProtectionRegistry::fromConfig($config, $auditTrail);

$stored = $registry->protectForStorage('students', $student);
```

---

## 23. Masking Patterns

Supported field mask examples:

```text
email
phone
last4
hidden
masked
```

Email masking:

```php
$masker = new \Mnb\SecurityCore\Data\DataMasker();

echo $masker->email('ravi@example.com');
// r***@example.com
```

Phone/last4 masking:

```php
echo $masker->phone('9876543210');
// ******3210
```

Classification masking:

```php
echo $masker->value('secret', DataClassifier::SENSITIVE);
// [masked]

echo $masker->value('secret', DataClassifier::HIGHLY_SENSITIVE);
// [hidden]
```

---

## 24. API Example: Create Student Safely

```php
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Data\DataProtectionRegistry;

require __DIR__ . '/vendor/autoload.php';

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);

$registry = DataProtectionRegistry::fromConfig($config, $kernel->auditTrail());

$input = [
    'name' => trim($_POST['name'] ?? ''),
    'email' => trim($_POST['email'] ?? ''),
    'parent_phone' => trim($_POST['parent_phone'] ?? ''),
    'password_hash' => $_POST['password_hash'] ?? null,
];

$protected = $registry->protectForStorage('students', $input);

// Store $protected using SecureDatabase or your repository.

$safeResponse = $registry->protectForResponse('students', $protected);

header('Content-Type: application/json');
echo json_encode([
    'status' => true,
    'message' => 'Student created.',
    'data' => $safeResponse,
]);
```

Expected safety:

```text
password_hash is removed.
email is encrypted before storage.
email_hash is generated for search.
parent_phone is encrypted before storage.
parent_phone_hash is generated for search.
response only receives masked values.
```

---

## 25. API Example: Search by Encrypted Email

```php
$email = trim($_GET['email'] ?? '');

$emailHash = $registry->searchHash('students', 'email', $email);

$rows = $secureDb->search(
    $context,
    $studentPolicy,
    filters: [
        'email_hash' => ['eq' => $emailHash],
    ],
    limit: 10
);

$safeRows = array_map(
    fn (array $row) => $registry->protectForResponse('students', $row),
    $rows
);

return json_encode([
    'status' => true,
    'data' => $safeRows,
]);
```

Do not search encrypted fields with `LIKE` against ciphertext.

Use:

```text
Exact lookup → keyed search hash
Partial lookup → separate safe indexed field, if allowed by policy
Reporting → pre-approved export/report pipeline
```

---

## 26. Export Example

```php
use Mnb\SecurityCore\Data\ExportPolicy;
use Mnb\SecurityCore\Data\SafeCsvExporter;

$exporter = new SafeCsvExporter(
    $registry,
    new ExportPolicy([
        'csv_injection_protection' => true,
        'max_rows' => 10000,
        'audit' => true,
    ])
);

$csv = $exporter->export('students', $rows, [
    'id',
    'name',
    'email',
    'parent_phone',
]);

header('Content-Type: text/csv');
header('Content-Disposition: attachment; filename="students.csv"');
echo $csv;
```

For large exports, combine with:

```text
Memory Governance and Resource Safety Engine
Throughput Governance and Performance Capacity Engine
Async Queue and Background Job Engine
EncryptedStorage
```

Recommended large export flow:

```text
Request export
    ↓
Authorization check
    ↓
Queue background export job
    ↓
Chunk database rows
    ↓
Protect each row for export
    ↓
Write encrypted private export file
    ↓
Return protected download link
```

---

## 27. CLI Commands Related to Data Protection

Depending on your current installed upgrade set, useful commands include:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure production:env-checklist
php bin/mnb-secure production:readiness
php bin/mnb-secure final:gate
```

Useful adjacent checks:

```bash
php bin/mnb-secure db:policy
php bin/mnb-secure db:health
php bin/mnb-secure xss:policy
php bin/mnb-secure xss:scan
php bin/mnb-secure memory:policy
php bin/mnb-secure queue:policy
```

Run data protection demo:

```bash
php demos/05-data-protection.php
php demos/23-data-protection-strategy-engine.php
```

Run all demos:

```bash
php demos/run-all-demos.php
```

Run tests:

```bash
php tests/run-tests.php
```

---

## 28. Demo Reference

The package includes these related demos:

```text
demos/05-data-protection.php
demos/23-data-protection-strategy-engine.php
```

Demo 05 shows basic classification, masking, and encryption:

```text
DataClassifier
FieldFilter
DataMasker
Encryption
```

Demo 23 shows the full strategy engine:

```text
DataProtectionRegistry
KeyRing
SearchHash
SafeCsvExporter
EncryptedStorage
Audit trail integration
```

---

## 29. Testing Examples

### Test: sensitive field is encrypted before storage

```php
$stored = $registry->protectForStorage('students', [
    'email' => 'ravi@example.com',
]);

assert(str_starts_with($stored['email'], 'mnbenc:'));
assert(isset($stored['email_hash']));
```

### Test: response masks sensitive fields

```php
$response = $registry->protectForResponse('students', $stored);

assert($response['email'] !== 'ravi@example.com');
assert(!isset($response['email_hash']));
```

### Test: highly sensitive field is not returned

```php
$stored = $registry->protectForStorage('students', [
    'password_hash' => 'hash',
]);

$response = $registry->protectForResponse('students', $stored);

assert(!isset($response['password_hash']));
```

### Test: logs are redacted

```php
$logSafe = $registry->protectForLog('students', [
    'email' => 'ravi@example.com',
    'parent_phone' => '9876543210',
]);

assert($logSafe['email'] === '[redacted]');
assert(!str_contains(json_encode($logSafe), '9876543210'));
```

### Test: CSV formula injection is neutralized

```php
$csv = $exporter->export('students', [[
    'name' => '=HYPERLINK("http://evil.test")',
    'email' => 'ravi@example.com',
]]);

assert(str_contains($csv, "'=HYPERLINK"));
```

### Test: search hash is stable and keyed

```php
$hash1 = $registry->searchHash('students', 'email', 'RAVI@example.com');
$hash2 = $registry->searchHash('students', 'email', 'ravi@example.com');

assert($hash1 === $hash2);
```

---

## 30. Production Checklist

Before production, verify:

```text
[ ] APP_KEY is set and strong.
[ ] DATA_KEY is set and strong.
[ ] DATA_SEARCH_HASH_KEY is set and strong.
[ ] Data keys are not committed to Git.
[ ] Sensitive resources are configured in data_protection.resources.
[ ] Sensitive fields have encrypt/search_hash/mask/log/export rules.
[ ] password_hash, tokens, secrets, and API keys are never returned/exported/logged.
[ ] Search hash fields are never returned/exported/logged.
[ ] Logs are redacted before write.
[ ] Backups are encrypted and signed.
[ ] Private files are stored outside public web root.
[ ] Sensitive exports use SafeCsvExporter.
[ ] Large exports are queued and streamed.
[ ] Tenant-scoped resources are also enforced by database/authorization policies.
[ ] Key rotation process is documented.
[ ] Key backup/recovery process is documented.
[ ] Production readiness command passes.
```

Recommended commands:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure production:env-checklist
php bin/mnb-secure production:readiness
php bin/mnb-secure final:gate
```

---

## 31. Common Mistakes

## Mistake 1: Returning raw database rows

Bad:

```php
return json_encode($row);
```

Good:

```php
return json_encode($registry->protectForResponse('students', $row));
```

---

## Mistake 2: Logging raw request payloads

Bad:

```php
$logger->info('request payload', $_POST);
```

Good:

```php
$logger->info('student payload', $registry->protectForLog('students', $_POST));
```

---

## Mistake 3: Searching encrypted values directly

Bad:

```sql
WHERE email = :email
```

when `email` is encrypted.

Good:

```sql
WHERE email_hash = :email_hash
```

---

## Mistake 4: Exporting raw sensitive records

Bad:

```php
fputcsv($handle, $row);
```

Good:

```php
$csv = $exporter->export('students', $rows);
```

---

## Mistake 5: Using the same key everywhere

Bad:

```text
APP_KEY = DATA_KEY = DATA_SEARCH_HASH_KEY = JWT_SECRET
```

Good:

```text
APP_KEY is separate.
DATA_KEY is separate.
DATA_SEARCH_HASH_KEY is separate.
JWT_SECRET is separate.
Webhook secrets are separate.
```

---

## Mistake 6: Losing old encryption keys

If old ciphertext uses `app-v1`, the old key must stay available until data is re-encrypted and old backups are handled.

Bad:

```text
Delete app-v1 key immediately after creating app-v2.
```

Good:

```text
Keep app-v1 for decrypting old data.
Write new data with app-v2.
Run controlled migration.
Remove app-v1 only after verification.
```

---

## 32. Recommended Integration With Other Engines

Data protection should work with these engines:

| Engine | Integration |
|---|---|
| Trust Zones and Data Boundaries | Define which zone can handle which data class. |
| Secure Request Receiving | Validate and limit data before protection. |
| Authentication | Identify actor. |
| Authorization | Decide whether actor can read/write/export data. |
| Secure Database Governance | Store protected fields through safe queries. |
| File Security | Encrypt private files and protect downloads. |
| Logging/Audit | Log only redacted/safe records. |
| Backup/Recovery | Encrypt and sign backups. |
| Safe Errors | Avoid exposing protected values in errors. |
| Queue Engine | Run large exports/protection jobs in background. |
| Memory/Throughput | Stream large protected exports safely. |
| Production Readiness | Verify secrets, policies, and release safety. |

---

## 33. Minimal Working Example

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use Mnb\SecurityCore\Data\DataProtectionRegistry;

$config = [
    'app' => [
        'key' => str_repeat('A', 40),
    ],
    'data_protection' => [
        'enabled' => true,
        'audit' => false,
        'encryption' => [
            'enabled' => true,
            'current_key_id' => 'demo-v1',
            'keys' => [
                'demo-v1' => str_repeat('K', 40),
            ],
            'aad' => true,
        ],
        'search_hash' => [
            'enabled' => true,
            'key' => str_repeat('H', 40),
            'prefix' => 'demo:search',
        ],
        'resources' => [
            'students' => [
                'default_class' => 'sensitive',
                'fields' => [
                    'name' => ['class' => 'internal'],
                    'email' => [
                        'class' => 'confidential',
                        'encrypt' => true,
                        'search_hash' => true,
                        'mask' => 'email',
                        'export' => 'masked',
                        'log' => false,
                    ],
                    'parent_phone' => [
                        'class' => 'sensitive',
                        'encrypt' => true,
                        'search_hash' => true,
                        'mask' => 'last4',
                        'export' => 'masked',
                        'log' => false,
                    ],
                    'password_hash' => [
                        'class' => 'highly_sensitive',
                        'read' => false,
                        'write' => false,
                        'export' => false,
                        'log' => false,
                    ],
                ],
            ],
        ],
    ],
];

$registry = DataProtectionRegistry::fromConfig($config);

$input = [
    'name' => 'Ravi Kumar',
    'email' => 'ravi@example.com',
    'parent_phone' => '9876543210',
    'password_hash' => 'hash',
];

$stored = $registry->protectForStorage('students', $input);
$response = $registry->protectForResponse('students', $stored);
$logSafe = $registry->protectForLog('students', $stored);

print_r($stored);
print_r($response);
print_r($logSafe);
```

---

## 34. Summary

The **Data Protection Strategy** ensures that sensitive data is handled safely throughout its lifecycle.

It protects:

```text
Data before database storage
Data before API response
Data before logs
Data before CSV/export
Data before private file storage
Data before backups and incident artifacts
```

Use it whenever your application handles:

```text
PII
student or parent records
payment data
private documents
tokens or secrets
internal reports
exports
backups
audit artifacts
```

The safest rule is simple:

```text
Never store, return, log, or export raw sensitive data directly.
Always pass data through the correct protection path first.
```
