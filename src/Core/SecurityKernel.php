<?php
namespace Mnb\SecurityCore\Core;

use Mnb\SecurityCore\Cache\FileCache;
use Mnb\SecurityCore\Files\FileUploadPolicy;
use Mnb\SecurityCore\Files\LocalPrivateStorage;
use Mnb\SecurityCore\Files\SecureFileManager;
use Mnb\SecurityCore\RateLimit\FileRateLimiter;
use Mnb\SecurityCore\Memory\MemoryConfig;
use Mnb\SecurityCore\Memory\MemoryGuard;
use Mnb\SecurityCore\Logging\FileLogger;
use Mnb\SecurityCore\Security\ServerIdentityHider;

class SecurityKernel
{
    public function __construct(private array $config) {}

    public function fileCache(): FileCache
    {
        return new FileCache($this->config['paths']['cache']);
    }

    public function fileRateLimiter(): FileRateLimiter
    {
        return new FileRateLimiter($this->config['paths']['cache'] . '/rate_limits');
    }

    public function secureFileManager(): SecureFileManager
    {
        $storage = new LocalPrivateStorage($this->config['paths']['private_storage']);
        $policy = FileUploadPolicy::fromConfig($this->config['uploads'], $this->config['limits']['upload_max_bytes']);
        return new SecureFileManager($storage, $policy, $this->config['paths']['quarantine']);
    }

    public function memoryGuard(): MemoryGuard
    {
        $logger = new FileLogger($this->config['paths']['logs'] . '/memory.log');
        return new MemoryGuard(MemoryConfig::fromArray($this->config['memory'] ?? []), $logger);
    }

    public function serverIdentityHider(): ServerIdentityHider
    {
        return new ServerIdentityHider($this->config['origin_protection'] ?? []);
    }
}
