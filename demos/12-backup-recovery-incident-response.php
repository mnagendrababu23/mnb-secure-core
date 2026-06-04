<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Recovery\BackupManager;
use Mnb\SecurityCore\Recovery\IncidentResponse;

demo_title('12. Backup, Recovery, and Incident Response');

$sourceDir = demo_storage_path('backup-source');
file_put_contents($sourceDir . '/students.json', json_encode([['id' => 1, 'name' => 'Demo Student']]));
file_put_contents($sourceDir . '/fees.json', json_encode([['receipt_id' => 10, 'amount' => 2500]]));

$manager = new BackupManager(demo_storage_path('backups'));
$archive = $manager->createArchive($sourceDir, 'school-demo-backup');
$verified = $manager->verifyArchive($archive);
$checklist = (new IncidentResponse())->checklist('suspected_fee_data_tampering');

demo_step('Created backup archive', $archive);
demo_step('Backup archive verifies', $verified);
demo_step('Incident checklist first steps', array_slice($checklist, 0, 4));
demo_result(is_file($archive) && $verified && count($checklist) >= 6, 'Backup creation/verification and incident response checklist are working.');
