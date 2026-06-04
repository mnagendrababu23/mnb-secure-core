<?php
namespace Mnb\SecurityCore\Auth;

class SessionGuard
{
    public function start(array $cookieOptions = []): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        if ($cookieOptions) {
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => '/',
                'secure' => (bool)($cookieOptions['secure'] ?? false),
                'httponly' => (bool)($cookieOptions['http_only'] ?? true),
                'samesite' => $cookieOptions['same_site'] ?? 'Lax',
            ]);
        }
        session_start();
    }

    public function login(array $user, array $permissions = []): void
    {
        $this->start();
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'] ?? null;
        $_SESSION['school_id'] = $user['school_id'] ?? null;
        $_SESSION['role'] = $user['role'] ?? null;
        $_SESSION['permissions'] = $permissions;
        $_SESSION['logged_in_at'] = time();
    }

    public function logout(): void
    {
        $this->start();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'] ?? '', $params['secure'], $params['httponly']);
        }
        session_destroy();
    }

    public function check(): bool
    {
        $this->start();
        return !empty($_SESSION['user_id']);
    }

    public function userId(): int|string|null
    {
        $this->start();
        return $_SESSION['user_id'] ?? null;
    }
}
