<?php
namespace Mnb\SecurityCore\Production;

final class ReleaseConsolidationManifest
{
    /** @param list<string> $upgrades */
    public function __construct(private array $upgrades) {}

    public static function default(): self
    {
        return new self([
            '27 Runtime Execution and Outbound Network Security Engine',
            '28 Secure Database Governance and Query Lifecycle Engine',
            '29 Security Verification, Remediation, and Evidence Automation Engine',
            '30 Safe Error Response and Technical Log Isolation Engine',
            '31 Memory Governance and Resource Safety Engine',
            '32 Throughput Governance and Performance Capacity Engine',
            '33 Origin Identity Protection and Exposure Hardening Engine',
            '34 Async Request, Response Queue, and Background Job Orchestration Engine',
            '35 Token Revocation and Session Control Engine',
            '36 Final Production Readiness, XSS Enforcement, and Release Consolidation Patch',
        ]);
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return ['release_line' => 'MNB Secure Core v1.0.1', 'count' => count($this->upgrades), 'upgrades' => $this->upgrades];
    }
}
