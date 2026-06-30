<?php
namespace Mnb\SecurityCore\Logging;

class LogRetentionManager
{
    public function __construct(private LogRetentionPolicy $policy, private string $logPath, private string $auditPath) {}

    /** @return array<string,mixed> */
    public function purge(?string $channel = null): array
    {
        $channels = $channel ? [$channel] : array_keys($this->policy->all());
        $deleted = [];
        foreach ($channels as $name) {
            $path = $name === 'audit' ? $this->auditPath : $this->logPath;
            $days = $this->policy->days((string)$name);
            $deleted = array_merge($deleted, $this->purgeDirectory($path, $days));
        }
        return ['passed' => true, 'deleted' => $deleted, 'deleted_count' => count($deleted)];
    }

    /** @return list<string> */
    private function purgeDirectory(string $dir, int $days): array
    {
        if ($days <= 0 || !is_dir($dir)) {
            return [];
        }
        $cutoff = time() - ($days * 86400);
        $deleted = [];
        foreach (glob(rtrim($dir, '/\\') . '/*') ?: [] as $file) {
            if (!is_file($file)) { continue; }
            if (!preg_match('/\.(log|jsonl|txt)$/i', $file)) { continue; }
            if ((filemtime($file) ?: time()) < $cutoff) {
                @unlink($file);
                $deleted[] = $file;
            }
        }
        return $deleted;
    }
}
