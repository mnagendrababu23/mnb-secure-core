<?php
namespace Mnb\SecurityCore\Authz;

class TenantGuard
{
    public function recordBelongsToContext(array $record, TenantContext $context, array $fields = ['school_id', 'branch_id', 'academic_year_id']): bool
    {
        $map = [
            'school_id' => $context->schoolId,
            'branch_id' => $context->branchId,
            'academic_year_id' => $context->academicYearId,
        ];
        foreach ($fields as $field) {
            if (array_key_exists($field, $record) && $map[$field] !== null && (string)$record[$field] !== (string)$map[$field]) {
                return false;
            }
        }
        return true;
    }

    public function classSectionAllowed(array $record, TenantContext $context): bool
    {
        if ($context->classIds && isset($record['class_id']) && !in_array((string)$record['class_id'], array_map('strval', $context->classIds), true)) {
            return false;
        }
        if ($context->sectionIds && isset($record['section_id']) && !in_array((string)$record['section_id'], array_map('strval', $context->sectionIds), true)) {
            return false;
        }
        return true;
    }
}
