<?php
namespace Mnb\SecurityCore\Token;

final class DatabaseTokenRevocationStore extends InMemoryTokenRevocationStore
{
    public function __construct(private mixed $connection = null, private string $table = 'mnb_revoked_tokens') {}
    public function driver(): string { return 'database_stub'; }
    public function table(): string { return $this->table; }
}
