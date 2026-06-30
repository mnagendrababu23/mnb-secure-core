<?php
namespace Mnb\SecurityCore\Session;

final class RememberMeTokenManager
{
    /** @var array<string,array<string,mixed>> */ private array $tokens=[];
    public function issue(string $userId, int $ttlSeconds): array { $plain=bin2hex(random_bytes(32)); $id='rm_'.bin2hex(random_bytes(8)); $this->tokens[$id]=['hash'=>password_hash($plain, PASSWORD_DEFAULT),'user_hash'=>SessionRecord::hashUser($userId),'expires_at'=>time()+$ttlSeconds,'active'=>true]; return ['id'=>$id,'token'=>$plain,'expires_at'=>$this->tokens[$id]['expires_at']]; }
    public function validate(string $id, string $plain): bool { $r=$this->tokens[$id] ?? null; return is_array($r) && !empty($r['active']) && time() < (int)$r['expires_at'] && password_verify($plain, (string)$r['hash']); }
    public function rotate(string $id, string $plain, int $ttlSeconds): ?array { if (!$this->validate($id,$plain)) return null; $userHash=(string)$this->tokens[$id]['user_hash']; $this->tokens[$id]['active']=false; $new=bin2hex(random_bytes(32)); $newId='rm_'.bin2hex(random_bytes(8)); $this->tokens[$newId]=['hash'=>password_hash($new, PASSWORD_DEFAULT),'user_hash'=>$userHash,'expires_at'=>time()+$ttlSeconds,'active'=>true]; return ['id'=>$newId,'token'=>$new,'expires_at'=>$this->tokens[$newId]['expires_at']]; }
    public function revoke(string $id): bool { if (!isset($this->tokens[$id])) return false; $this->tokens[$id]['active']=false; return true; }
}
