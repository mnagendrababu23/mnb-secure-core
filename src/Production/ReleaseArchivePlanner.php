<?php
namespace Mnb\SecurityCore\Production;

final class ReleaseArchivePlanner
{
    /** @return array<string,mixed> */
    public function plan(string $outputName = 'mnb-secure-core-v1.0.1-final-merged.zip'): array
    {
        return [
            'passed' => true,
            'output' => $outputName,
            'event' => ProductionAuditEvents::RELEASE_PLAN_CREATED,
            'include' => ['src/', 'config/', 'bin/', 'docs/', 'demos/', 'tests/', 'composer.json', 'README.md', 'SECURITY.md', 'CHANGELOG.md'],
            'exclude' => ['.git/', 'vendor/', '.env', 'storage/logs/*', 'storage/audit/*', 'storage/cache/*', 'storage/queue/*', 'storage/tokens/*', 'storage/backups/*', 'storage/private/*', 'storage/quarantine/*'],
            'command_hint' => 'zip -r ' . $outputName . ' . -x vendor/* .git/* .env storage/logs/* storage/audit/* storage/cache/* storage/queue/* storage/tokens/* storage/backups/* storage/private/* storage/quarantine/*',
        ];
    }
}
