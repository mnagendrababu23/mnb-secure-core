<?php
namespace Mnb\SecurityCore\Auth;

class Csrf
{
    public function __construct(private string $sessionKey = '_csrf_token')
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            @session_start();
        }
    }

    public function token(): string
    {
        if (empty($_SESSION[$this->sessionKey])) {
            $_SESSION[$this->sessionKey] = bin2hex(random_bytes(32));
        }
        return $_SESSION[$this->sessionKey];
    }

    public function verify(string $token): bool
    {
        return isset($_SESSION[$this->sessionKey]) && hash_equals($_SESSION[$this->sessionKey], $token);
    }
}
