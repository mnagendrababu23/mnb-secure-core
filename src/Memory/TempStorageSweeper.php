<?php
namespace Mnb\SecurityCore\Memory;

class TempStorageSweeper
{
    public function __construct(private TemporaryFileManager $manager) {}
    public function plan(): array { return $this->manager->cleanupOld(true); }
    public function sweep(): array { return $this->manager->cleanupOld(false); }
}
