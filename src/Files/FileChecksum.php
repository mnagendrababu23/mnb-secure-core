<?php
namespace Mnb\SecurityCore\Files;

use Mnb\SecurityCore\Exceptions\SecurityException;

class FileChecksum
{
    public static function sha256(string $path): string
    {
        if (!is_file($path)) {
            throw new SecurityException('File does not exist for checksum calculation');
        }
        $hash = hash_file('sha256', $path);
        if (!is_string($hash) || $hash === '') {
            throw new SecurityException('Unable to calculate file checksum');
        }
        return $hash;
    }

    public static function contentsSha256(string $contents): string
    {
        return hash('sha256', $contents);
    }
}
