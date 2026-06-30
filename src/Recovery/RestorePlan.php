<?php
namespace Mnb\SecurityCore\Recovery;

class RestorePlan
{
    /** @param array<string,mixed> $options */
    public function __construct(public readonly string $backupPath, public readonly string $targetPath, public readonly bool $dryRun = true, public readonly array $options = []) {}
    /** @return array<string,mixed> */ public function toArray(): array { return ['backup_path'=>$this->backupPath,'target_path'=>$this->targetPath,'dry_run'=>$this->dryRun,'options'=>$this->options]; }
}
