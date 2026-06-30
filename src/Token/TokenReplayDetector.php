<?php
namespace Mnb\SecurityCore\Token;

final class TokenReplayDetector
{
    /** @var array<string,int> */ private array $seen = [];
    public function markSeen(string $tokenId): void { $this->seen[$tokenId] = time(); }
    public function seen(string $tokenId): bool { return isset($this->seen[$tokenId]); }
    public function checkAndMark(string $tokenId): array { $replay=$this->seen($tokenId); $this->markSeen($tokenId); return ['replay'=>$replay,'token_id'=>$tokenId]; }
}
