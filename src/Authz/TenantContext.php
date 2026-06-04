<?php
namespace Mnb\SecurityCore\Authz;

class TenantContext
{
    public function __construct(
        public readonly int|string|null $userId,
        public readonly int|string|null $schoolId = null,
        public readonly int|string|null $branchId = null,
        public readonly int|string|null $academicYearId = null,
        public readonly array $roles = [],
        public readonly array $permissions = [],
        public readonly array $classIds = [],
        public readonly array $sectionIds = []
    ) {}

    public static function fromSession(): self
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            @session_start();
        }
        return new self(
            $_SESSION['user_id'] ?? null,
            $_SESSION['school_id'] ?? null,
            $_SESSION['branch_id'] ?? null,
            $_SESSION['academic_year_id'] ?? null,
            (array)($_SESSION['roles'] ?? []),
            (array)($_SESSION['permissions'] ?? [])
        );
    }
}
