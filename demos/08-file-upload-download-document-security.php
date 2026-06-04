<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Files\FileUploadPolicy;
use Mnb\SecurityCore\Files\LocalPrivateStorage;
use Mnb\SecurityCore\Files\SecureFileManager;
use Mnb\SecurityCore\Exceptions\SecurityException;

demo_title('08. File Upload, Download, and Document Security');

$source = demo_storage_path('uploads/student-note.txt');
file_put_contents($source, 'Safe student document text.');
$storage = new LocalPrivateStorage(demo_storage_path('private-documents'));
$policy = new FileUploadPolicy(['txt'], ['text/plain'], 1024 * 1024, true, true);
$manager = new SecureFileManager($storage, $policy, demo_storage_path('quarantine'));

$stored = $manager->storeFromPath($source, 'student-note.txt', 'students');
$download = $manager->readForDownload($stored);

$blocked = false;
try {
    $manager->storeFromPath($source, 'shell.php.txt', 'students');
} catch (SecurityException $e) {
    $blocked = true;
    demo_step('Blocked malicious file reason', $e->getMessage());
}

demo_step('Stored file metadata', $stored);
demo_step('Downloaded content', $download);
demo_step('Double-extension upload blocked', $blocked);
demo_result($storage->exists($stored['storage_path']) && $download === 'Safe student document text.' && $blocked, 'Private file storage, quarantine flow, safe download, and double-extension blocking are working.');
