<?php
namespace Mnb\SecurityCore\Token;

final class TokenFamily
{
    /** @param list<TokenRecord> $tokens */
    public function __construct(private string $id, private array $tokens = [], private bool $revoked = false) {}
    public static function create(): self { return new self('fam_' . bin2hex(random_bytes(12))); }
    public function id(): string { return $this->id; }
    public function tokens(): array { return $this->tokens; }
    public function revoked(): bool { return $this->revoked; }
    public function withToken(TokenRecord $record): self { $copy = clone $this; $copy->tokens[] = $record; return $copy; }
    public function revoke(): self { $copy = clone $this; $copy->revoked = true; return $copy; }
    public function toArray(): array { return ['id'=>$this->id,'revoked'=>$this->revoked,'tokens'=>array_map(fn(TokenRecord $t)=>$t->toArray(), $this->tokens)]; }
}
