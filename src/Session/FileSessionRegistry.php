<?php
namespace Mnb\SecurityCore\Session;

final class FileSessionRegistry implements SessionRegistryInterface
{
    public function __construct(private string $path) { if (!is_dir($this->path)) { @mkdir($this->path, 0775, true); } }
    public function save(SessionRecord $record): void { file_put_contents($this->file($record->id()), json_encode($record->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)); }
    public function find(string $sessionId): ?SessionRecord { $file=$this->file($sessionId); if (!is_file($file)) return null; $data=json_decode((string)file_get_contents($file), true); return is_array($data)?SessionRecord::fromArray($data):null; }
    public function revoke(string $sessionId, string $reason = 'revoked'): bool { $r=$this->find($sessionId); if (!$r) return false; $this->save($r->withStatus($reason === 'forced_logout' ? SessionStatus::FORCED_LOGOUT : SessionStatus::REVOKED)); return true; }
    public function all(): array { $out=[]; foreach (glob(rtrim($this->path,'/\\').'/*.json') ?: [] as $f) { $data=json_decode((string)file_get_contents($f), true); if (is_array($data)) $out[]=SessionRecord::fromArray($data); } return $out; }
    public function forUserHash(string $userHash): array { return array_values(array_filter($this->all(), fn(SessionRecord $r)=>$r->userHash()===$userHash)); }
    public function cleanupExpired(?int $now = null): int { $n=0; foreach ($this->all() as $r) { if (!$r->active($now)) { @unlink($this->file($r->id())); $n++; } } return $n; }
    private function file(string $id): string { return rtrim($this->path,'/\\') . '/' . SessionId::safe($id) . '.json'; }
}
