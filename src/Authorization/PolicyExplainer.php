<?php
namespace Mnb\SecurityCore\Authorization;

class PolicyExplainer
{
    public static function explain(AuthorizationPolicy $policy): array
    {
        return [
            'name' => $policy->name(),
            'resource' => $policy->resource(),
            'actions' => $policy->actions(),
            'roles' => $policy->roles(),
            'permissions' => $policy->permissions(),
            'scopes' => $policy->scopes(),
            'tenant_required' => $policy->tenantRequired(),
            'data_classes' => $policy->dataClasses(),
            'trust_boundary' => $policy->trustBoundary(),
            'audit' => $policy->audit(),
            'fields' => $policy->fields(),
        ];
    }
}
