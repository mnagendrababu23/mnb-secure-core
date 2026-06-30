<?php
namespace Mnb\SecurityCore\Session;

final class DatabaseSessionRegistry extends InMemorySessionRegistry
{
    public function __construct(private mixed $connection = null, private string $table = 'mnb_sessions') {}
    public function driver(): string { return 'database_stub'; }
}
