<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Trust\BoundaryGuard;
use Mnb\SecurityCore\Trust\DataBoundary;
use Mnb\SecurityCore\Trust\TrustZone;
use Mnb\SecurityCore\Data\DataClassifier;

demo_title('01. Trust Zones and Data Boundaries');

$guard = new BoundaryGuard();
$guard->add(new DataBoundary(TrustZone::PUBLIC, [DataClassifier::PUBLIC], ['read']));
$guard->add(new DataBoundary(TrustZone::AUTHENTICATED, [DataClassifier::PUBLIC, DataClassifier::INTERNAL, DataClassifier::CONFIDENTIAL], ['read']));
$guard->add(new DataBoundary(TrustZone::SCHOOL_ADMIN, [DataClassifier::PUBLIC, DataClassifier::INTERNAL, DataClassifier::CONFIDENTIAL, DataClassifier::SENSITIVE], ['read', 'create', 'update']));
$guard->add(new DataBoundary(TrustZone::INTERNAL_SYSTEM, [DataClassifier::PUBLIC, DataClassifier::INTERNAL, DataClassifier::CONFIDENTIAL, DataClassifier::SENSITIVE, DataClassifier::HIGHLY_SENSITIVE], ['read', 'create', 'update', 'backup']));

demo_step('Public zone can read public data', $guard->allows(TrustZone::PUBLIC, DataClassifier::PUBLIC, 'read'));
demo_step('Public zone can read sensitive student data', $guard->allows(TrustZone::PUBLIC, DataClassifier::SENSITIVE, 'read'));
demo_step('School admin can update sensitive fee/student data', $guard->allows(TrustZone::SCHOOL_ADMIN, DataClassifier::SENSITIVE, 'update'));
demo_step('School admin can run backup', $guard->allows(TrustZone::SCHOOL_ADMIN, DataClassifier::HIGHLY_SENSITIVE, 'backup'));
demo_step('Internal system can run backup', $guard->allows(TrustZone::INTERNAL_SYSTEM, DataClassifier::HIGHLY_SENSITIVE, 'backup'));

demo_result(
    !$guard->allows(TrustZone::PUBLIC, DataClassifier::SENSITIVE, 'read') && $guard->allows(TrustZone::INTERNAL_SYSTEM, DataClassifier::HIGHLY_SENSITIVE, 'backup'),
    'Boundary guard blocks public sensitive access and allows internal backup only.'
);
