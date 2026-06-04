<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Data\DataClassifier;
use Mnb\SecurityCore\Data\DataMasker;
use Mnb\SecurityCore\Data\FieldFilter;
use Mnb\SecurityCore\Data\Encryption;

demo_title('05. Data Protection Strategy');

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
$encryption = new Encryption('demo-key-demo-key-demo-key-demo-key');
$cipher = $encryption->encrypt('Highly private document metadata');
$plain = $encryption->decrypt($cipher);

demo_step('Masked record', $masked);
demo_step('Public API allowed fields', $publicApi);
demo_step('Encrypted payload length', strlen($cipher));
demo_step('Decryption works', $plain === 'Highly private document metadata');

demo_result($masked['parent_phone'] === '[masked]' && $masked['fee_payment_ref'] === '[hidden]' && $plain === 'Highly private document metadata', 'Sensitive fields are masked and private data can be encrypted/decrypted.');
