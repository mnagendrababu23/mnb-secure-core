<?php
namespace Mnb\SecurityCore\Production;

final class EnvChecklistBuilder
{
    public function __construct(private ProductionReadinessPolicy $policy) {}

    /** @return array<string,mixed> */
    public function build(): array
    {
        $items = [];
        foreach ($this->policy->requiredSecrets() as $secret) {
            $items[] = ['name' => $secret, 'required' => true, 'minimum' => '32+ random characters', 'example_command' => 'php bin/mnb-secure key:generate'];
        }
        $items[] = ['name' => 'APP_ENV', 'required' => true, 'expected' => 'production'];
        $items[] = ['name' => 'APP_DEBUG', 'required' => true, 'expected' => 'false'];
        $items[] = ['name' => 'FORCE_HTTPS', 'required' => true, 'expected' => 'true after TLS is valid'];
        $items[] = ['name' => 'TRUSTED_HOSTS', 'required' => true, 'expected' => 'explicit public host list'];
        $items[] = ['name' => 'TRUSTED_PROXIES', 'required' => false, 'expected' => 'CDN/proxy CIDR ranges when behind proxy'];
        return ['passed' => true, 'event' => ProductionAuditEvents::ENV_CHECKLIST_CREATED, 'items' => $items];
    }
}
