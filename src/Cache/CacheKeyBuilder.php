<?php
namespace Mnb\SecurityCore\Cache;

use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Http\Request;

class CacheKeyBuilder
{
    public function __construct(private string $prefix = 'mnb')
    {
        $this->prefix = trim($prefix, ':');
        if ($this->prefix === '') {
            $this->prefix = 'mnb';
        }
    }

    /** @param array<string,mixed> $context */
    public function build(CachePolicy $policy, array $context = [], ?Request $request = null): string
    {
        $context = $this->contextFromRequest($context, $request);
        $parts = [$this->prefix, 'policy:' . $policy->name(), 'class:' . $policy->dataClass()];
        foreach ($policy->scope() as $scope) {
            $parts[] = $scope . ':' . $this->scopeValue($scope, $context);
        }
        if (isset($context['resource_id'])) {
            $parts[] = 'resource:' . $this->safe((string)$context['resource_id']);
        }
        if (isset($context['key'])) {
            $parts[] = 'key:' . $this->safe((string)$context['key']);
        }
        $fingerprint = hash('sha256', json_encode($this->stable($context), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '[]');
        $parts[] = 'ctx:' . substr($fingerprint, 0, 24);
        return implode(':', $parts);
    }

    /** @param array<string,mixed> $context @return array<string,mixed> */
    public function contextFromRequest(array $context = [], ?Request $request = null): array
    {
        if (!$request) {
            return $context;
        }
        $auth = $request->attribute('auth');
        if (!isset($context['user_id'])) {
            if (is_object($auth) && method_exists($auth, 'id')) {
                $context['user_id'] = $auth->id();
            } elseif ($request->attribute('auth_user_id') !== null) {
                $context['user_id'] = $request->attribute('auth_user_id');
            }
        }
        $tenant = $request->attribute('tenant_context');
        if ($tenant instanceof TenantContext) {
            $context += [
                'school_id' => $tenant->schoolId,
                'branch_id' => $tenant->branchId,
                'academic_year_id' => $tenant->academicYearId,
            ];
        }
        return $context;
    }

    /** @param array<string,mixed> $context */
    private function scopeValue(string $scope, array $context): string
    {
        return match ($scope) {
            'global' => 'all',
            'tenant' => $this->safe((string)($context['tenant_id'] ?? $context['school_id'] ?? 'missing')),
            'school' => $this->safe((string)($context['school_id'] ?? 'missing')),
            'branch' => $this->safe((string)($context['branch_id'] ?? 'missing')),
            'year', 'academic_year' => $this->safe((string)($context['academic_year_id'] ?? 'missing')),
            'user' => $this->safe((string)($context['user_id'] ?? 'anonymous')),
            'route' => $this->safe((string)($context['route'] ?? $context['route_name'] ?? 'unknown')),
            default => $this->safe((string)($context[$scope . '_id'] ?? $context[$scope] ?? 'missing')),
        };
    }

    private function safe(string $value): string
    {
        $value = trim($value);
        if ($value === '') {
            return 'empty';
        }
        $safe = preg_replace('/[^A-Za-z0-9_.:-]+/', '_', $value) ?: 'value';
        return strlen($safe) > 80 ? substr(hash('sha256', $value), 0, 24) : $safe;
    }

    /** @param array<string,mixed> $value @return array<string,mixed> */
    private function stable(array $value): array
    {
        ksort($value);
        foreach ($value as $key => $item) {
            if (is_array($item)) {
                $value[$key] = $this->stable($item);
            } elseif (is_object($item)) {
                $value[$key] = method_exists($item, '__toString') ? (string)$item : get_class($item);
            }
        }
        return $value;
    }
}
