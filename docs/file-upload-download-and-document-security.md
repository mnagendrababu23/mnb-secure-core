# File Upload, Download, and Document Security

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Document type:** Detailed feature documentation and code usage  
**Feature area:** Secure uploads, private storage, malware scanning, document inspection, quarantine, protected downloads, signed download URLs, archive safety, retention cleanup, audit logging, data protection integration, memory/resource integration, and production readiness

---

## 1. Overview

The **File Upload, Download, and Document Security** layer protects one of the most dangerous application boundaries: user-controlled files.

Files are risky because an uploaded file can be:

```text
malware
executable code disguised as a document
a polyglot file
an archive bomb
a double-extension trick
an oversized payload
a document with active content
a private document being downloaded by the wrong user
a sensitive file leaked through public storage
```

`mnb-secure-core` provides a complete file security workflow:

```text
Incoming upload
    ↓
Request size and upload profile check
    ↓
Filename normalization
    ↓
Extension allow/block list
    ↓
MIME detection and MIME/extension pairing
    ↓
Executable-content checks
    ↓
Archive/document inspection
    ↓
Malware scan
    ↓
Private/encrypted storage
    ↓
File metadata record
    ↓
Download policy enforcement
    ↓
Signed URL / authorization / tenant check
    ↓
Safe download response
    ↓
Audit log
```

This feature is designed for PHP applications that need to accept files from browsers, mobile apps, API clients, admin panels, school portals, SaaS tenants, or internal tools.

---

## 2. What This Feature Protects Against

File and document security helps reduce risk from:

```text
Malware upload
Web shell upload
Double-extension bypass
Dangerous MIME spoofing
Executable content disguised as document
Archive bombs / zip bombs
Nested archive abuse
Oversized file upload
Public storage leakage
Unauthorized downloads
Tenant data leakage
Sensitive document exposure
Inline rendering XSS
Content sniffing
Unsafe file names
Path traversal
Download cache leakage
Unscanned file access
Uncontrolled signed URLs
Temporary file buildup
Rejected/quarantine file buildup
```

File security should be used together with:

```text
Secure Request Receiving Strategy
Authentication Strategy
Authorization Strategy
Data Protection Strategy
Web Application Security Controls
API Security and Rate Limiting
Runtime Execution and Outbound Network Security
Memory Governance and Resource Safety
Safe Error Responses and Hidden Technical Logs
```

---

## 3. Main Classes

The file security layer is mainly built around these classes:

```text
Mnb\SecurityCore\Files\FileUploadPolicy
Mnb\SecurityCore\Files\UploadSecurityProfile
Mnb\SecurityCore\Files\SecureFileManager
Mnb\SecurityCore\Files\LocalPrivateStorage
Mnb\SecurityCore\Files\EncryptedStorage
Mnb\SecurityCore\Files\FileChecksum
Mnb\SecurityCore\Files\FileSecurityRecord
Mnb\SecurityCore\Files\FileSecurityPolicy
Mnb\SecurityCore\Files\FileSecurityRegistry
Mnb\SecurityCore\Files\FileSecurityDecision
Mnb\SecurityCore\Files\ProtectedDownloadManager
Mnb\SecurityCore\Files\SafeDownloadResponse
Mnb\SecurityCore\Files\ArchiveInspector
Mnb\SecurityCore\Files\DocumentInspectionResult
Mnb\SecurityCore\Files\DocumentInspectorInterface
Mnb\SecurityCore\Files\DocumentSanitizerInterface
Mnb\SecurityCore\Files\NullDocumentSanitizer
Mnb\SecurityCore\Files\FileRetentionManager

Mnb\SecurityCore\Contracts\MalwareScannerInterface
Mnb\SecurityCore\Files\NullMalwareScanner
Mnb\SecurityCore\Files\HeuristicMalwareScanner
Mnb\SecurityCore\Files\ClamAvMalwareScanner
Mnb\SecurityCore\Files\CompositeMalwareScanner
```

The main access points are available through `SecurityKernel`:

```php
use Mnb\SecurityCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);

$uploadPolicy = $kernel->uploadPolicy('documents');
$fileManager = $kernel->secureFileManager(profile: 'documents');
$registry = $kernel->fileSecurityRegistry();
$downloads = $kernel->protectedDownloadManager();
$retention = $kernel->fileRetentionManager();
```

---

## 4. Installation

Install the package with Composer:

```bash
composer require mnb/mnb-secure-core
```

Bootstrap the Composer autoloader:

```php
require __DIR__ . '/vendor/autoload.php';
```

Load your security config:

```php
$config = require __DIR__ . '/config/security.php';
$kernel = new \Mnb\SecurityCore\Core\SecurityKernel($config);
```

---

## 5. Configuration

File security is controlled by these main config areas:

```text
limits.upload_max_bytes
uploads
file_security
data_protection.storage
runtime.commands.clamav_scan
memory.profiles.upload_scan
```

A typical configuration looks like this:

```php
return [
    'limits' => [
        'request_max_bytes' => 12 * 1024 * 1024,
        'upload_max_bytes' => 10 * 1024 * 1024,
    ],

    'paths' => [
        'private_storage' => __DIR__ . '/../storage/private',
        'quarantine' => __DIR__ . '/../storage/quarantine',
    ],

    'uploads' => [
        'profile' => $_ENV['UPLOAD_PROFILE'] ?? 'custom',
        'strict_production' => true,
        'allow_archives_in_production' => false,

        'allowed_extensions' => [
            'jpg', 'jpeg', 'png', 'gif',
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv',
        ],

        'allowed_mime_prefixes' => [
            'image/',
            'application/pdf',
            'text/',
            'application/vnd.',
            'application/msword',
        ],

        'blocked_extensions' => [
            'php', 'phtml', 'phar', 'cgi', 'pl', 'sh',
            'exe', 'com', 'bat', 'cmd', 'js', 'html', 'htm', 'svg',
        ],

        'deny_double_extensions' => true,
        'randomize_names' => true,
        'max_original_name_length' => 180,
        'reject_executable_content' => true,

        'max_archive_entries' => 500,
        'max_archive_uncompressed_bytes' => 104857600,

        'scanner' => [
            'driver' => $_ENV['UPLOAD_SCANNER_DRIVER'] ?? 'heuristic', // none, heuristic, clamav, composite
            'clamav_binary' => $_ENV['CLAMAV_BINARY'] ?? 'clamscan',
            'timeout_seconds' => 30,
            'fail_closed' => true,
            'heuristic_read_bytes' => 2097152,
        ],

        'profiles' => [
            'images' => ['max_bytes' => 5 * 1024 * 1024],
            'documents' => ['max_bytes' => 15 * 1024 * 1024],
            'videos' => ['max_bytes' => 100 * 1024 * 1024],
            'archives' => ['max_bytes' => 25 * 1024 * 1024],
            'strict' => ['max_bytes' => 5 * 1024 * 1024],
        ],
    ],

    'file_security' => [
        'enabled' => true,
        'deny_by_default' => true,
        'default_download_disposition' => 'attachment',
        'deny_download_until_scan_passed' => true,
        'audit_downloads' => true,
        'audit_deletes' => true,

        'metadata' => [
            'require_owner' => false,
            'require_tenant' => false,
            'require_checksum' => true,
            'require_scan_status' => true,
        ],

        'download' => [
            'cache_policy' => 'download',
            'nosniff' => true,
            'safe_filename' => true,
            'allow_inline' => false,
            'inline_profiles' => ['images'],
            'signed_urls' => [
                'enabled' => true,
                'ttl' => 900,
                'one_time' => false,
            ],
        ],

        'inspection' => [
            'enabled' => true,
            'inspect_pdf' => true,
            'inspect_office' => true,
            'inspect_archives' => true,
            'max_nested_archive_depth' => 1,
        ],

        'sanitization' => [
            'enabled' => false,
            'driver' => 'null',
            'reencode_images' => false,
            'strip_image_metadata' => true,
            'strip_pdf_active_content' => false,
        ],

        'retention' => [
            'quarantine_ttl_hours' => 24,
            'rejected_ttl_days' => 7,
            'temporary_exports_ttl_hours' => 24,
        ],
    ],
];
```

---

## 6. Upload Profiles

Upload profiles let you use different security rules for different file categories.

Built-in profile names include:

```text
default
images
documents
videos
archives
strict
```

Use an upload profile from the kernel:

```php
$policy = $kernel->uploadPolicy('images');

print_r($policy->describe());
```

Example output shape:

```php
[
    'max_bytes' => 5242880,
    'allowed_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'webp'],
    'blocked_extensions' => ['php', 'phtml', 'phar', 'exe', 'sh'],
    'deny_double_extensions' => true,
    'reject_executable_content' => true,
]
```

Use strict mode for high-risk upload points:

```php
$strictPolicy = $kernel->uploadPolicy('strict');
```

Recommended profile usage:

| Use case | Recommended profile |
|---|---|
| Profile photo | `images` |
| Student document | `documents` |
| Admin import CSV | `documents` or custom CSV-only profile |
| Video lesson upload | `videos` |
| Backup import | custom strict internal-only profile |
| Public anonymous upload | `strict` |

---

## 7. Secure Upload Flow

A normal secure upload flow should follow this model:

```text
1. Use request receiving middleware to limit request size.
2. Store PHP upload temporarily outside public web root.
3. Pass temporary path and original name to SecureFileManager.
4. Validate extension, MIME, content, archive/document safety, and malware scan.
5. Store final file under private/encrypted storage.
6. Save returned metadata in your database.
7. Use ProtectedDownloadManager for all downloads.
```

Example controller-style upload handler:

```php
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Exceptions\SecurityException;

$config = require __DIR__ . '/../config/security.php';
$kernel = new SecurityKernel($config);

$file = $_FILES['document'] ?? null;

if (!$file || ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
    http_response_code(422);
    echo json_encode(['status' => false, 'message' => 'Upload failed.']);
    exit;
}

try {
    $manager = $kernel->secureFileManager(profile: 'documents');

    $record = $manager->storeFromPath(
        sourcePath: $file['tmp_name'],
        originalName: $file['name'],
        module: 'student-documents',
        actor: [
            'user_id' => $currentUserId,
            'role' => 'teacher',
        ],
        context: [
            'data_class' => 'confidential',
            'owner_user_id' => $studentUserId,
            'school_id' => $schoolId,
            'branch_id' => $branchId,
            'academic_year_id' => $academicYearId,
        ]
    );

    // Save $record in your database.
    // The library returns safe metadata; the host app owns persistence.

    echo json_encode([
        'status' => true,
        'message' => 'File uploaded securely.',
        'file' => [
            'file_id' => $record['file_id'] ?? null,
            'original_name' => $record['original_name'] ?? null,
            'mime' => $record['mime'] ?? null,
            'size' => $record['size'] ?? null,
            'checksum_sha256' => $record['checksum_sha256'] ?? null,
            'scan_status' => $record['scan_status'] ?? null,
        ],
    ]);
} catch (SecurityException $e) {
    http_response_code(400);
    echo json_encode([
        'status' => false,
        'message' => 'File upload rejected.',
        'code' => 'UPLOAD_REJECTED',
    ]);
}
```

Do not move uploaded files directly into `public/`.

Unsafe:

```php
move_uploaded_file($_FILES['file']['tmp_name'], __DIR__ . '/public/uploads/' . $_FILES['file']['name']);
```

Safer:

```php
$record = $kernel->secureFileManager(profile: 'documents')->storeFromPath(
    $_FILES['file']['tmp_name'],
    $_FILES['file']['name'],
    'documents',
    ['user_id' => $currentUserId],
    ['data_class' => 'internal']
);
```

---

## 8. Filename Safety

The library normalizes original names through `FileSecurityRecord::safeOriginalName()` and upload validation.

It is designed to avoid dangerous names such as:

```text
../../.env
shell.php
invoice.pdf.php
<script>alert(1)</script>.jpg
very-long-name-....pdf
```

The original filename should be treated as display metadata only. It should never be used as the final physical storage name.

Recommended practice:

```text
Original filename: used for safe display only
Storage path: randomized/internal path
Download filename: sanitized Content-Disposition filename
```

---

## 9. Extension and MIME Validation

File extension checks alone are not enough.

A secure upload should check:

```text
File size
Original name length
Double extension
Allowed extension
Blocked extension
Detected MIME type
MIME/extension pairing
Executable content signatures
Archive safety
Document inspection
Malware scan
```

Example policy checks:

```php
$policy = $kernel->uploadPolicy('documents');

if (!$policy->allowsExtension('pdf')) {
    throw new RuntimeException('PDF uploads are disabled.');
}

if (!$policy->allowsMime('application/pdf')) {
    throw new RuntimeException('PDF MIME type is disabled.');
}
```

Avoid allowing risky extensions:

```text
php
phtml
phar
cgi
pl
sh
exe
bat
cmd
js
html
svg
```

SVG is commonly blocked by default because it can contain active JavaScript and cross-site scripting payloads.

---

## 10. Malware Scanning

The package supports multiple scanner strategies through `MalwareScannerInterface`.

Available scanners:

```text
NullMalwareScanner
HeuristicMalwareScanner
ClamAvMalwareScanner
CompositeMalwareScanner
```

### 10.1 Null scanner

Use only for local development or controlled tests:

```php
use Mnb\SecurityCore\Files\NullMalwareScanner;

$manager = $kernel->secureFileManager(
    scanner: new NullMalwareScanner(),
    profile: 'documents'
);
```

Do not use this scanner in production.

### 10.2 Heuristic scanner

The heuristic scanner can detect obvious dangerous content patterns and suspicious executable signatures.

```php
$manager = $kernel->secureFileManager(profile: 'documents');
```

If `UPLOAD_SCANNER_DRIVER=heuristic`, the kernel can use heuristic scanning as the default scanner.

### 10.3 ClamAV scanner

ClamAV is recommended for stronger production scanning when available.

Example `.env`:

```env
UPLOAD_SCANNER_DRIVER=clamav
CLAMAV_BINARY=clamscan
UPLOAD_SCAN_TIMEOUT=30
UPLOAD_SCAN_FAIL_CLOSED=true
```

The ClamAV scanner is integrated with the Runtime Execution Security engine so process execution is guarded by command allow-listing, timeouts, output limits, and safe environment handling.

Example manual wiring:

```php
use Mnb\SecurityCore\Files\ClamAvMalwareScanner;

$scanner = new ClamAvMalwareScanner(
    binary: 'clamscan',
    timeoutSeconds: 30
);

$manager = $kernel->secureFileManager(
    scanner: $scanner,
    profile: 'documents'
);
```

### 10.4 Composite scanner

Use `CompositeMalwareScanner` when you want multiple scanners to agree that a file is safe.

```php
use Mnb\SecurityCore\Files\CompositeMalwareScanner;
use Mnb\SecurityCore\Files\HeuristicMalwareScanner;
use Mnb\SecurityCore\Files\ClamAvMalwareScanner;

$scanner = new CompositeMalwareScanner([
    new HeuristicMalwareScanner(),
    new ClamAvMalwareScanner('clamscan', 30),
]);

$manager = $kernel->secureFileManager(
    scanner: $scanner,
    profile: 'documents'
);
```

---

## 11. Document and Archive Inspection

`ArchiveInspector` checks archive-style files for dangerous conditions.

It helps defend against:

```text
Archive bombs
Too many archive entries
Large decompressed size
Nested archive abuse
Blocked extensions inside archive
```

Kernel access:

```php
$inspector = $kernel->documentInspector();

$result = $inspector->inspect(
    path: $path,
    mime: 'application/zip',
    extension: 'zip'
);

if ($result->failed()) {
    print_r($result->findings());
}
```

The result type is `DocumentInspectionResult`:

```php
if ($result->passed()) {
    echo $result->message();
}

foreach ($result->findings() as $finding) {
    echo $finding . PHP_EOL;
}
```

Recommended archive limits:

```php
'uploads' => [
    'max_archive_entries' => 500,
    'max_archive_uncompressed_bytes' => 104857600,
],

'file_security' => [
    'inspection' => [
        'enabled' => true,
        'inspect_archives' => true,
        'max_nested_archive_depth' => 1,
    ],
],
```

In production, avoid accepting archives from untrusted users unless there is a strong business reason.

---

## 12. Document Sanitization

The package includes `DocumentSanitizerInterface` so applications can integrate custom sanitizers.

Default implementation:

```text
NullDocumentSanitizer
```

This means the library can run without external document tools, while giving you an extension point.

Example custom sanitizer:

```php
use Mnb\SecurityCore\Files\DocumentSanitizerInterface;
use Mnb\SecurityCore\Files\DocumentInspectionResult;

final class PdfSanitizer implements DocumentSanitizerInterface
{
    public function sanitize(string $path, string $mime, string $extension): DocumentInspectionResult
    {
        if ($extension !== 'pdf') {
            return DocumentInspectionResult::pass('No PDF sanitization required.');
        }

        // Call a safe PDF sanitization tool here.
        // Prefer SafeProcessRunner for external commands.

        return DocumentInspectionResult::pass('PDF sanitized.');
    }
}
```

Use it with `SecureFileManager`:

```php
$manager = $kernel->secureFileManager(
    profile: 'documents',
    sanitizer: new PdfSanitizer()
);
```

Production sanitization examples:

```text
Re-encode images
Strip image metadata
Flatten PDFs
Remove active PDF content
Remove macros from office files
Convert documents to safe preview formats
```

---

## 13. Private and Encrypted Storage

Files should be stored outside the public web root.

Recommended structure:

```text
storage/private/
storage/quarantine/
storage/rejected/
storage/tmp/
```

Use `LocalPrivateStorage` for private local storage:

```php
use Mnb\SecurityCore\Files\LocalPrivateStorage;

$storage = new LocalPrivateStorage(__DIR__ . '/../storage/private');
$storage->put('documents/file.txt', 'content');
$content = $storage->read('documents/file.txt');
```

Use `EncryptedStorage` when file encryption is enabled:

```php
$storage = $kernel->encryptedPrivateStorage();
$storage->put('documents/secure.bin', $binaryContents);
```

Enable encrypted private storage:

```php
'data_protection' => [
    'storage' => [
        'encrypt_files' => true,
    ],
],
```

Required production secret:

```env
DATA_ENCRYPTION_KEY=use_a_real_32_byte_random_secret
```

---

## 14. File Metadata Records

`SecureFileManager::storeFromPath()` returns a metadata array. Store this metadata in your database.

Typical metadata:

```php
[
    'file_id' => 'file_...',
    'storage_path' => 'student-documents/2026/06/random-name.pdf',
    'original_name' => 'marksheet.pdf',
    'mime' => 'application/pdf',
    'extension' => 'pdf',
    'profile' => 'documents',
    'data_class' => 'confidential',
    'scan_status' => 'passed',
    'checksum_sha256' => '...',
    'size' => 123456,
    'owner_user_id' => 1001,
    'school_id' => 10,
    'branch_id' => 5,
    'academic_year_id' => 2026,
]
```

Wrap persisted data with `FileSecurityRecord` when making download decisions:

```php
use Mnb\SecurityCore\Files\FileSecurityRecord;

$record = FileSecurityRecord::fromArray($fileRowFromDatabase);

echo $record->originalName();
echo $record->checksum();
```

Do not trust file metadata from the client. Metadata must come from your trusted database record, not from request parameters.

---

## 15. Protected Downloads

Downloads should never serve files directly from public URLs.

Unsafe:

```text
https://example.com/uploads/private/student-report.pdf
```

Safer:

```text
GET /files/{file_id}/download
    ↓
Authenticate
    ↓
Authorize
    ↓
Load trusted file record from database
    ↓
ProtectedDownloadManager
    ↓
SafeDownloadResponse
```

Example download route:

```php
use Mnb\SecurityCore\Http\Request;

$request = Request::fromGlobals();

// Load file record from your database using a safe query.
$fileRecord = $fileRepository->findById($fileId);

if (!$fileRecord) {
    http_response_code(404);
    echo 'File not found';
    exit;
}

$response = $kernel->protectedDownloadManager()->download(
    request: $request,
    fileRecord: $fileRecord,
    policyName: 'student_document.download',
    disposition: 'attachment'
);

$response->send();
```

The download manager checks:

```text
policy exists
requested action allowed
required role/permission/scope
required tenant context
allowed data class
scan status passed
safe disposition
safe cache policy
safe filename
signed URL rules if used
```

---

## 16. File Download Policies

Configure named download policies under `file_security.policies`.

Example:

```php
'file_security' => [
    'policies' => [
        'student_document.download' => [
            'actions' => ['download'],
            'roles' => ['school_admin', 'teacher', 'super_admin'],
            'permissions' => ['documents.download'],
            'scopes' => ['documents:download'],
            'tenant_required' => true,
            'data_classes' => ['internal', 'confidential', 'sensitive'],
            'require_scan_passed' => true,
            'disposition' => 'attachment',
            'allow_inline' => false,
            'cache_policy' => 'download',
            'audit' => true,
            'signed_urls' => [
                'enabled' => true,
                'ttl' => 900,
            ],
        ],
    ],
],
```

Decision example:

```php
$registry = $kernel->fileSecurityRegistry();

$decision = $registry->decide(
    policyName: 'student_document.download',
    request: $request,
    fileRecord: $fileRecord,
    action: 'download'
);

if ($decision->denied()) {
    http_response_code($decision->statusCode());
    echo $decision->safeMessage();
    exit;
}
```

---

## 17. Tenant-Aware File Security

For multi-tenant systems, file records should include tenant fields:

```text
school_id
branch_id
academic_year_id
owner_user_id
```

`FileSecurityRecord::tenantResource()` provides a normalized resource shape:

```php
$record = FileSecurityRecord::fromArray($fileRow);

$resource = $record->tenantResource();
```

Use tenant-required policies for student/private files:

```php
'file_security' => [
    'policies' => [
        'student_document.download' => [
            'tenant_required' => true,
            'data_classes' => ['confidential', 'sensitive'],
        ],
    ],
],
```

This prevents one school, branch, tenant, or user from downloading another tenant's private document when the app provides the correct request/user/tenant context.

---

## 18. Signed Download URLs

Signed URLs are useful when you need temporary access links.

Example:

```php
$url = $kernel->protectedDownloadManager()->signedUrl(
    fileRecord: $fileRecord,
    path: '/download.php',
    policyName: 'student_document.download',
    params: [
        'file_id' => $fileRecord['file_id'],
    ],
    ttlSeconds: 900
);

echo $url;
```

Verify a signed URL:

```php
$isValid = $kernel->protectedDownloadManager()->verifySignedUrl(
    url: $_SERVER['REQUEST_URI'],
    policyName: 'student_document.download'
);

if (!$isValid) {
    http_response_code(403);
    echo 'Invalid or expired link.';
    exit;
}
```

Signed URL production rules:

```text
Use short TTLs.
Do not include secrets in URL params.
Do not use signed URLs as a replacement for authorization for sensitive files unless explicitly intended.
Prefer signed URLs for temporary links, not permanent access.
Use HTTPS only.
```

Required production secret:

```env
SIGNED_URL_KEY=use_a_real_32_byte_random_secret
```

---

## 19. Safe Download Responses

`SafeDownloadResponse` builds response headers safely.

It protects against:

```text
Content-Type confusion
Content-Disposition injection
Unsafe inline rendering
Browser content sniffing
Filename injection
Cache leakage
```

Example:

```php
use Mnb\SecurityCore\Files\SafeDownloadResponse;
use Mnb\SecurityCore\Files\FileSecurityRecord;

$record = FileSecurityRecord::fromArray($fileRecord);
$contents = $kernel->secureFileManager()->readForDownload($fileRecord);

$response = SafeDownloadResponse::make(
    contents: $contents,
    record: $record,
    disposition: 'attachment'
);

$response->send();
```

Recommended response headers:

```text
Content-Type: safe detected MIME
Content-Disposition: attachment; filename="safe-name.pdf"
X-Content-Type-Options: nosniff
Cache-Control: private, no-store or controlled download policy
```

Avoid inline display for sensitive content unless you have a strong reason.

---

## 20. Inline Rendering Rules

Inline rendering increases risk because browsers may execute or interpret content.

Examples of risky inline files:

```text
svg
html
xml
pdf with active content
user-generated text/html
```

Recommended defaults:

```php
'file_security' => [
    'download' => [
        'allow_inline' => false,
        'inline_profiles' => ['images'],
    ],
],
```

If inline images are allowed, still use:

```text
strict MIME rules
nosniff
safe filenames
CSP headers
authorization checks
private cache policy
```

---

## 21. Quarantine Workflow

Rejected or suspicious files should be moved into quarantine or rejected storage depending on your app design.

Quarantine is useful when:

```text
scan failed
malware suspected
archive inspection failed
manual review is required
incident evidence must be preserved
```

Do not serve quarantined files to users.

Recommended quarantine metadata:

```php
[
    'file_id' => 'file_...',
    'original_name' => 'invoice.pdf.php',
    'reason' => 'blocked_extension',
    'scan_status' => 'rejected',
    'quarantine_path' => '...',
    'uploaded_by' => $userId,
    'request_id' => $requestId,
    'created_at' => date('c'),
]
```

Retention cleanup:

```php
$report = $kernel->fileRetentionManager()->purgeQuarantine(
    __DIR__ . '/../storage/quarantine'
);

print_r($report);
```

---

## 22. File Retention and Cleanup

`FileRetentionManager` helps remove old temporary/quarantine/rejected files.

Example:

```php
$retention = $kernel->fileRetentionManager();

$quarantine = $retention->purgeQuarantine(__DIR__ . '/../storage/quarantine');
$rejected = $retention->purgeRejected(__DIR__ . '/../storage/rejected');
$exports = $retention->purgeTemporaryExports(__DIR__ . '/../storage/tmp/exports');

print_r([
    'quarantine' => $quarantine,
    'rejected' => $rejected,
    'exports' => $exports,
]);
```

Recommended scheduled cleanup:

```bash
php bin/mnb-secure file:retention-cleanup
```

If your CLI does not have a dedicated file retention command yet, run cleanup through your app scheduler using `FileRetentionManager`.

---

## 23. File Checksums

`FileChecksum` creates SHA-256 checksums for integrity and deduplication.

```php
use Mnb\SecurityCore\Files\FileChecksum;

$checksum = FileChecksum::sha256($absolutePath);
```

Use checksums for:

```text
integrity checking
duplicate detection
evidence records
audit trails
file tampering detection
safe metadata comparison
```

Never use checksums as authorization tokens.

---

## 24. API Upload Example

A JSON API upload response should not expose internal storage paths.

```php
try {
    $record = $kernel->secureFileManager(profile: 'documents')->storeFromPath(
        $_FILES['file']['tmp_name'],
        $_FILES['file']['name'],
        'api-documents',
        ['user_id' => $currentUserId],
        ['data_class' => 'internal']
    );

    echo json_encode([
        'status' => true,
        'file' => [
            'id' => $record['file_id'],
            'name' => $record['original_name'],
            'mime' => $record['mime'],
            'size' => $record['size'],
            'scan_status' => $record['scan_status'],
        ],
    ]);
} catch (Throwable $e) {
    // Let SafeErrorHandler handle this in real apps.
    http_response_code(400);
    echo json_encode([
        'status' => false,
        'message' => 'File upload rejected.',
    ]);
}
```

Do not return:

```text
absolute filesystem path
private storage root
quarantine path
scan command output with paths
raw exception message
```

---

## 25. Background Job Upload Scanning

For large files, scan asynchronously.

Recommended pattern:

```text
1. Accept upload into private temporary location.
2. Create database record with scan_status = pending.
3. Dispatch file_scan queue job.
4. Return 202 Accepted.
5. Worker scans file.
6. Worker updates scan_status = passed/rejected.
7. Download policy denies access until scan_status = passed.
```

Example dispatch:

```php
$job = $kernel->jobDispatcher()->dispatch(
    name: 'file_scan',
    payload: [
        'file_id' => $fileId,
    ],
    queue: 'files',
    idempotencyKey: 'file_scan:' . $fileId
);

$response = $kernel->asyncResponseFactory()->accepted($job);
$response->send();
```

Download protection should require scan completion:

```php
'file_security' => [
    'deny_download_until_scan_passed' => true,
    'policies' => [
        'student_document.download' => [
            'require_scan_passed' => true,
        ],
    ],
],
```

---

## 26. Memory and Streaming Integration

Large files should not be fully loaded into memory unless they are small and controlled.

Use the Memory Governance engine for large reads:

```php
$reader = $kernel->safeStreamReader();

foreach ($reader->chunks($absolutePath, 'upload_scan') as $chunk) {
    // inspect chunk safely
}
```

Recommended memory profile:

```php
'memory' => [
    'profiles' => [
        'upload_scan' => [
            'enabled' => true,
            'max_bytes' => '128M',
            'require_streaming' => true,
            'max_read_bytes' => 10485760,
        ],
    ],
],
```

Avoid:

```php
$contents = file_get_contents($veryLargeUpload);
```

for untrusted or large files.

---

## 27. Runtime Security Integration

When using external scanners or sanitizers, use the Runtime Execution Security engine.

Example safe process use:

```php
$result = $kernel->safeProcessRunner()->run('clamav_scan', [
    $absoluteFilePath,
]);

if (!$result->isSuccessful()) {
    throw new RuntimeException('Scan failed.');
}
```

Configure allowed scanner command:

```php
'runtime' => [
    'commands' => [
        'clamav_scan' => [
            'binary' => 'clamscan',
            'allowed_args' => ['--no-summary', '--infected'],
            'timeout_seconds' => 30,
            'max_output_bytes' => 65536,
        ],
    ],
],
```

Never build scanner commands with raw user input.

Unsafe:

```php
shell_exec('clamscan ' . $_GET['path']);
```

Safe:

```php
$kernel->safeProcessRunner()->run('clamav_scan', [$trustedAbsolutePath]);
```

---

## 28. Logging and Audit Events

File operations should be auditable.

Recommended audit events:

```text
file.upload.accepted
file.upload.rejected
file.upload.quarantined
file.scan.started
file.scan.passed
file.scan.failed
file.download.allowed
file.download.denied
file.signed_url.created
file.signed_url.rejected
file.retention.purged
```

The package's file security registry audits decisions when policy `audit` is enabled.

Example:

```php
$decision = $kernel->fileSecurityRegistry()->decide(
    'student_document.download',
    $request,
    $fileRecord,
    'download'
);

if ($decision->denied()) {
    // The registry can audit this denial depending on policy.
}
```

Logs should not contain:

```text
raw file contents
malware samples
absolute private paths
secrets in signed URLs
personal document contents
```

Use safe error and log redaction layers to avoid technical leakage.

---

## 29. Common Upload Policies

### 29.1 Public image upload

```php
'uploads' => [
    'profile' => 'images',
],

'file_security' => [
    'policies' => [
        'profile_photo.download' => [
            'actions' => ['download'],
            'data_classes' => ['public', 'internal'],
            'require_scan_passed' => true,
            'allow_inline' => true,
            'inline_profiles' => ['images'],
            'cache_policy' => 'public_asset',
            'audit' => false,
        ],
    ],
],
```

### 29.2 Student confidential document

```php
'file_security' => [
    'policies' => [
        'student_document.download' => [
            'actions' => ['download'],
            'roles' => ['teacher', 'school_admin', 'super_admin'],
            'permissions' => ['documents.download'],
            'tenant_required' => true,
            'data_classes' => ['confidential', 'sensitive'],
            'require_scan_passed' => true,
            'disposition' => 'attachment',
            'allow_inline' => false,
            'audit' => true,
        ],
    ],
],
```

### 29.3 Admin CSV import

```php
'uploads' => [
    'profiles' => [
        'admin_csv_import' => [
            'max_bytes' => 10 * 1024 * 1024,
            'allowed_extensions' => ['csv'],
            'allowed_mime_prefixes' => ['text/csv', 'text/plain'],
            'blocked_extensions' => ['php', 'exe', 'sh', 'js', 'html'],
            'deny_double_extensions' => true,
            'reject_executable_content' => true,
        ],
    ],
],
```

### 29.4 Archive upload for trusted admin only

```php
'uploads' => [
    'allow_archives_in_production' => false,
    'profiles' => [
        'trusted_admin_archive' => [
            'max_bytes' => 25 * 1024 * 1024,
            'allowed_extensions' => ['zip'],
            'max_archive_entries' => 200,
            'max_archive_uncompressed_bytes' => 50 * 1024 * 1024,
        ],
    ],
],
```

Use additional authorization before allowing archive upload.

---

## 30. Middleware Order for Upload Routes

Recommended upload route pipeline:

```text
RequestIdMiddleware
ErrorHandlingMiddleware
ServerIdentityProtectionMiddleware
TrustedHostMiddleware
RequestTrustMiddleware
RequestSizeMiddleware
JsonBodyParserMiddleware or multipart parser
SuspiciousRequestMiddleware
CsrfMiddleware for browser uploads
RateLimitMiddleware
AuthenticationMiddleware
AuthorizationMiddleware
ThroughputMiddleware
Controller upload handler
```

For API uploads, use bearer/API token authentication instead of browser CSRF where appropriate.

---

## 31. Upload Route Example

```php
$pipeline = $kernel->middlewarePipeline([
    $kernel->errorHandlingMiddleware(),
    $kernel->requestSizeMiddleware(),
    $kernel->rateLimitMiddleware('api'),
    $kernel->authenticationMiddleware(),
    $kernel->authorizationMiddleware('documents.upload'),
]);

$response = $pipeline->handle($request, function ($request) use ($kernel) {
    $file = $_FILES['file'] ?? null;

    if (!$file || $file['error'] !== UPLOAD_ERR_OK) {
        return $kernel->apiResponder()->validationError([
            'file' => 'A valid file is required.',
        ]);
    }

    $record = $kernel->secureFileManager(profile: 'documents')->storeFromPath(
        $file['tmp_name'],
        $file['name'],
        'documents',
        ['user_id' => $request->userId()],
        ['data_class' => 'internal']
    );

    return $kernel->apiResponder()->success([
        'file_id' => $record['file_id'],
        'name' => $record['original_name'],
        'scan_status' => $record['scan_status'],
    ], 201);
});
```

Adjust method names to match your app/router wrappers.

---

## 32. Download Route Example

```php
$pipeline = $kernel->middlewarePipeline([
    $kernel->errorHandlingMiddleware(),
    $kernel->rateLimitMiddleware('api'),
    $kernel->authenticationMiddleware(),
]);

$response = $pipeline->handle($request, function ($request) use ($kernel, $fileRepository) {
    $fileId = $request->routeParam('file_id');
    $fileRecord = $fileRepository->findById($fileId);

    if (!$fileRecord) {
        return $kernel->apiResponder()->notFound('File not found.');
    }

    return $kernel->protectedDownloadManager()->download(
        request: $request,
        fileRecord: $fileRecord,
        policyName: 'student_document.download'
    );
});
```

Important: load the file record by ID from your trusted database. Do not let the user send `storage_path` directly.

---

## 33. Testing Examples

### 33.1 Extension blocking

```php
$policy = $kernel->uploadPolicy('documents');

assert($policy->allowsExtension('pdf') === true);
assert($policy->allowsExtension('php') === false);
```

### 33.2 MIME blocking

```php
$policy = $kernel->uploadPolicy('images');

assert($policy->allowsMime('image/png') === true);
assert($policy->allowsMime('application/x-php') === false);
```

### 33.3 Archive inspection

```php
$result = $kernel->documentInspector()->inspect(
    path: __DIR__ . '/fixtures/sample.zip',
    mime: 'application/zip',
    extension: 'zip'
);

assert($result instanceof \Mnb\SecurityCore\Files\DocumentInspectionResult);
```

### 33.4 File security policy decision

```php
$request = \Mnb\SecurityCore\Http\Request::fromGlobals();

$record = [
    'storage_path' => 'documents/a.pdf',
    'original_name' => 'a.pdf',
    'mime' => 'application/pdf',
    'extension' => 'pdf',
    'profile' => 'documents',
    'data_class' => 'confidential',
    'scan_status' => 'passed',
    'checksum_sha256' => str_repeat('a', 64),
    'size' => 123,
];

$decision = $kernel->fileSecurityRegistry()->decide(
    'student_document.download',
    $request,
    $record,
    'download'
);

assert($decision->allowed() || $decision->denied());
```

### 33.5 Signed URL verification

```php
$url = $kernel->protectedDownloadManager()->signedUrl(
    $record,
    '/files/download.php',
    'student_document.download',
    ['file_id' => 'file_123'],
    900
);

assert($kernel->protectedDownloadManager()->verifySignedUrl($url, 'student_document.download') === true);
```

---

## 34. CLI and Demo References

Relevant validation commands:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure vulnerabilities:report
php bin/mnb-secure memory:profile upload_scan
php bin/mnb-secure queue:handlers
```

Relevant demo:

```bash
php demos/08-file-upload-download-document-security.php
```

Depending on your exact v1.0.1 demo numbering, this concept may also be represented by the file security/document security demo included in the package.

Run all demos:

```bash
php demos/run-all-demos.php
```

Run tests:

```bash
php tests/run-tests.php
```

---

## 35. Production Checklist

Before enabling uploads in production, verify:

```text
Upload max size is lower than request max size.
Uploaded files are stored outside public web root.
File names are randomized.
Original names are sanitized.
Dangerous extensions are blocked.
Double extensions are denied.
SVG/HTML/JS uploads are blocked unless safely sanitized.
MIME type and extension are checked together.
Executable content is rejected.
Archive inspection is enabled if archives are allowed.
Archive limits are strict.
Malware scanning is enabled.
Scanner fails closed in production.
ClamAV command is allow-listed if ClamAV is used.
Quarantine path is not public.
Encrypted file storage is enabled for sensitive files.
Downloads go through ProtectedDownloadManager.
Direct public file URLs are disabled for private files.
Signed URL key is a real 32+ byte secret.
Signed URL TTL is short.
Download policies require scan_status = passed.
Tenant-required file policies are enabled for multi-tenant files.
Sensitive documents force attachment disposition.
X-Content-Type-Options: nosniff is applied.
Download cache policy is private/no-store for sensitive files.
File audit logging is enabled.
Quarantine/rejected/temp retention cleanup is scheduled.
Large file processing uses streaming or background jobs.
```

---

## 36. Common Mistakes

### Mistake 1: Storing uploads under `public/uploads`

Bad:

```text
public/uploads/student-document.pdf
```

Good:

```text
storage/private/student-documents/random-id.pdf
```

and serve only through `ProtectedDownloadManager`.

### Mistake 2: Trusting the original filename

Bad:

```php
$path = 'uploads/' . $_FILES['file']['name'];
```

Good:

```php
$record = $kernel->secureFileManager()->storeFromPath(
    $_FILES['file']['tmp_name'],
    $_FILES['file']['name']
);
```

### Mistake 3: Allowing download before scan passes

Bad:

```text
scan_status = pending, but user can download
```

Good:

```php
'require_scan_passed' => true
```

### Mistake 4: Using only extension validation

Bad:

```php
if (str_ends_with($name, '.jpg')) allow();
```

Good:

```text
extension + detected MIME + content signature + scanner + policy
```

### Mistake 5: Inline rendering sensitive documents

Bad:

```text
Content-Disposition: inline
```

for confidential PDFs.

Good:

```text
Content-Disposition: attachment
X-Content-Type-Options: nosniff
Cache-Control: private, no-store
```

### Mistake 6: Not cleaning quarantine/temp files

Bad:

```text
storage/quarantine grows forever
```

Good:

```php
$kernel->fileRetentionManager()->purgeQuarantine($path);
```

---

## 37. Recommended Database Columns for File Records

The library does not force a database schema, but this structure is useful:

```sql
CREATE TABLE files (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    file_id VARCHAR(80) NOT NULL UNIQUE,
    storage_path VARCHAR(500) NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    mime VARCHAR(150) NOT NULL,
    extension VARCHAR(30) NOT NULL,
    profile VARCHAR(80) NOT NULL,
    data_class VARCHAR(50) NOT NULL,
    scan_status VARCHAR(30) NOT NULL,
    checksum_sha256 CHAR(64) NULL,
    size BIGINT UNSIGNED NOT NULL,
    owner_user_id BIGINT UNSIGNED NULL,
    school_id BIGINT UNSIGNED NULL,
    branch_id BIGINT UNSIGNED NULL,
    academic_year_id BIGINT UNSIGNED NULL,
    created_by BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NULL,
    deleted_at DATETIME NULL,
    INDEX idx_files_file_id (file_id),
    INDEX idx_files_owner (owner_user_id),
    INDEX idx_files_tenant (school_id, branch_id, academic_year_id),
    INDEX idx_files_scan_status (scan_status)
);
```

Never store raw file contents in normal relational tables unless you have a strong reason. Store metadata in DB and content in private/encrypted storage.

---

## 38. Security Design Summary

The secure file design should follow these rules:

```text
Deny by default.
Accept only known-safe profiles.
Block dangerous extensions explicitly.
Validate MIME and extension together.
Never trust original filename.
Randomize storage names.
Store outside public web root.
Scan before download.
Inspect archives and documents.
Use private/encrypted storage for sensitive files.
Authorize every download.
Apply tenant boundaries.
Use attachment disposition for sensitive files.
Use signed URLs only with short TTLs.
Audit upload and download decisions.
Clean temporary/quarantine files.
Use queue/streaming for expensive file work.
```

---

## 39. Related Documentation

Read these documents together with this file:

```text
docs/secure-request-receiving-strategy.md
docs/authentication-strategy.md
docs/authorization-strategy.md
docs/data-protection-strategy.md
docs/web-application-security-controls.md
docs/api-security-and-rate-limiting.md
docs/memory-governance-and-resource-safety.md
docs/runtime-execution-and-outbound-network-security.md
docs/async-request-response-queue-background-job-orchestration.md
```

---

## 40. Quick Start Summary

```php
use Mnb\SecurityCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);

// 1. Upload securely.
$record = $kernel->secureFileManager(profile: 'documents')->storeFromPath(
    $_FILES['file']['tmp_name'],
    $_FILES['file']['name'],
    'documents',
    ['user_id' => $currentUserId],
    ['data_class' => 'confidential']
);

// Save $record to database.

// 2. Later, download securely.
$fileRecord = $fileRepository->findById($fileId);

$response = $kernel->protectedDownloadManager()->download(
    request: \Mnb\SecurityCore\Http\Request::fromGlobals(),
    fileRecord: $fileRecord,
    policyName: 'student_document.download'
);

$response->send();
```

That is the core rule: **never serve uploaded files directly; always pass them through security policy, authorization, scan-status checks, safe headers, and audit.**
