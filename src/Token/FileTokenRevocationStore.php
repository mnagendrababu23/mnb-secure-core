<?php
namespace Mnb\SecurityCore\Token;

final class FileTokenRevocationStore implements TokenRevocationStoreInterface
{
    public function __construct(private string $path) { if (!is_dir($this->path)) { @mkdir($this->path, 0775, true); } }
    public function revoke(TokenRevocationRecord $record): void { file_put_contents($this->file($record->tokenId()), json_encode($record->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)); }
    public function find(string $tokenId): ?TokenRevocationRecord { $file=$this->file($tokenId); if (!is_file($file)) { return null; } $data=json_decode((string)file_get_contents($file), true); return is_array($data)?TokenRevocationRecord::fromArray($data):null; }
    public function isRevoked(string $tokenId): bool { $r=$this->find($tokenId); return $r!==null && !$r->expired(); }
    public function all(): array { $out=[]; foreach (glob(rtrim($this->path,'/\\').'/*.json') ?: [] as $f) { $data=json_decode((string)file_get_contents($f), true); if (is_array($data)) { $out[] = TokenRevocationRecord::fromArray($data); } } return $out; }
    public function forFamily(string $familyId): array { return array_values(array_filter($this->all(), fn(TokenRevocationRecord $r)=>$r->familyId()===$familyId)); }
    public function cleanupExpired(?int $now = null): int { $n=0; foreach ($this->all() as $r) { if ($r->expired($now)) { @unlink($this->file($r->tokenId())); $n++; } } return $n; }
    private function file(string $id): string { return rtrim($this->path,'/\\') . '/' . TokenId::safe($id) . '.json'; }
}
