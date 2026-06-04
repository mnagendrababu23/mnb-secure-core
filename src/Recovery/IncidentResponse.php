<?php
namespace Mnb\SecurityCore\Recovery;

class IncidentResponse
{
    public function checklist(string $incidentType): array
    {
        return [
            'Identify affected users, records, APIs, and time window.',
            'Contain the incident: disable keys/accounts/routes if needed.',
            'Preserve logs, audit records, backups, and evidence.',
            'Eradicate root cause and patch the vulnerable path.',
            'Restore from verified backup if integrity is affected.',
            'Rotate secrets/tokens/passwords as appropriate.',
            'Notify stakeholders according to legal and school policy.',
            'Write post-incident report and add regression tests for ' . $incidentType . '.',
        ];
    }
}
