<?php
namespace Mnb\SecurityCore\Logging;

class AuditIntegrityVerifier
{
    public function __construct(private string $auditFile) {}

    /** @return array<string,mixed> */
    public function verify(): array
    {
        if (!is_file($this->auditFile)) {
            return ['passed' => false, 'valid' => false, 'file' => $this->auditFile, 'entries' => 0, 'failed_line' => null, 'error' => 'audit_file_missing'];
        }
        $logger = new TamperEvidentAuditLogger($this->auditFile);
        $result = $logger->verifyDetailed();
        return [
            'passed' => (bool)$result['valid'],
            'valid' => (bool)$result['valid'],
            'file' => $this->auditFile,
            'entries' => (int)$result['entries'],
            'failed_line' => $result['failed_line'],
            'error' => $result['error'],
        ];
    }
}
