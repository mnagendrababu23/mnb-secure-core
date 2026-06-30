<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Files\ArchiveInspector;
use Mnb\SecurityCore\Http\Request;

demo_title('25. File Upload, Download, and Document Security Engine');

$config = require __DIR__ . '/../config/security.php';
$config['app']['key'] = str_repeat('F', 40);
$config['web_security']['signed_urls']['key'] = str_repeat('S', 40);
$config['paths']['private_storage'] = demo_storage_path('file-security/private');
$config['paths']['quarantine'] = demo_storage_path('file-security/quarantine');
$config['paths']['audit'] = demo_storage_path('file-security/audit');
$config['audit']['file'] = demo_storage_path('file-security/audit/security-audit.log');
$config['file_security']['policies']['student_document.download']['roles'] = ['school_admin'];
$config['file_security']['policies']['student_document.download']['permissions'] = ['documents.download'];
$config['file_security']['policies']['student_document.download']['tenant_required'] = true;
$config['file_security']['policies']['student_document.download']['data_classes'] = ['sensitive'];

$kernel = new SecurityKernel($config);

$source = demo_storage_path('file-security/source/student-note.txt');
file_put_contents($source, 'private student document');

$record = $kernel->secureFileManager(profile: 'documents')->storeFromPath(
    $source,
    'student-note.txt',
    'student-documents',
    ['user_id' => 501],
    ['school_id' => 10, 'branch_id' => 5, 'academic_year_id' => 2026, 'data_class' => 'sensitive']
);

$request = (new Request('GET', '/download/' . $record['file_id'], [], [], [], ['REMOTE_ADDR' => '127.0.0.1']))
    ->withAttribute('auth', new AuthContext(true, 501, ['documents:download'], ['documents.download'], ['school_admin']))
    ->withAttribute('tenant_context', new TenantContext(userId: 501, schoolId: 10, branchId: 5, academicYearId: 2026, permissions: ['documents.download']));

$response = $kernel->protectedDownloadManager()->download($request, $record, 'student_document.download');
$signedUrl = $kernel->protectedDownloadManager()->signedUrl($record, '/download/' . $record['file_id'], 'student_document.download');
$archiveResult = (new ArchiveInspector())->inspect($source, 'application/x-tar', 'tar');

demo_step('Stored file id', $record['file_id']);
demo_step('Checksum recorded', isset($record['checksum_sha256']) ? 'YES' : 'NO');
demo_step('Scan status', $record['scan_status']);
demo_step('Download status', $response->status());
demo_step('Download headers', $response->headers());
demo_step('Signed URL verifies', $kernel->protectedDownloadManager()->verifySignedUrl($signedUrl, 'student_document.download') ? 'YES' : 'NO');
demo_step('Unsupported archive deep inspection fails closed', $archiveResult->failed() ? 'YES' : 'NO');

demo_result(
    isset($record['file_id'], $record['checksum_sha256'])
    && $record['scan_status'] === 'passed'
    && $response->status() === 200
    && $response->body() === 'private student document'
    && str_contains($response->headers()['Content-Disposition'] ?? '', 'attachment')
    && (($response->headers()['X-Content-Type-Options'] ?? '') === 'nosniff')
    && $kernel->protectedDownloadManager()->verifySignedUrl($signedUrl, 'student_document.download')
    && $archiveResult->failed(),
    'File security engine stores metadata, gates downloads by policy/tenant/scan status, emits safe headers, signs URLs, and exposes document inspection hooks.'
);
