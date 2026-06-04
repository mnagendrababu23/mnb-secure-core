<?php
namespace Mnb\SecurityCore\Database;

class TableSecurityPolicy
{
    public function __construct(
        public readonly string $table,
        public readonly string $resourceType,
        public readonly array $selectableColumns,
        public readonly array $insertableColumns,
        public readonly array $updatableColumns,
        public readonly array $searchableColumns = [],
        public readonly array $orderableColumns = [],
        public readonly string $primaryKey = 'id',
        public readonly array $tenantColumns = [
            'school_id' => 'schoolId',
            'branch_id' => 'branchId',
            'academic_year_id' => 'academicYearId',
        ],
        public readonly bool $softDeletes = true,
        public readonly string $deletedAtColumn = 'deleted_at'
    ) {}
}
