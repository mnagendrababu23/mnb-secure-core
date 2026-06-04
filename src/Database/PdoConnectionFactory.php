<?php
namespace Mnb\SecurityCore\Database;

use PDO;

class PdoConnectionFactory
{
    public function create(DatabaseConfig $config): PdoDatabaseConnection
    {
        $pdo = new PDO($config->dsn, $config->username, $config->password, $config->securePdoOptions());
        return new PdoDatabaseConnection($pdo);
    }
}
