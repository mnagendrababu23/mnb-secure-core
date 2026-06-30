<?php
namespace Mnb\SecurityCore\Auth;

class PasswordPolicy
{
    /** @var list<string> */
    private array $commonPasswords;

    public function __construct(private array $config = [])
    {
        $this->commonPasswords = array_map('strtolower', array_filter(array_map('strval', $config['common_passwords'] ?? [
            'password', 'password123', '12345678', '123456789', 'qwerty123', 'admin123', 'letmein123', 'welcome123', 'iloveyou', 'secret123',
        ])));
    }

    /** @param array<string,mixed> $context */
    public function validate(string $password, array $context = []): PasswordPolicyResult
    {
        $errors = [];
        $min = max(1, (int)($this->config['min_length'] ?? 12));
        $max = max($min, (int)($this->config['max_length'] ?? 128));

        if (strlen($password) < $min) {
            $errors['min_length'] = "Password must be at least {$min} characters.";
        }
        if (strlen($password) > $max) {
            $errors['max_length'] = "Password must be no more than {$max} characters.";
        }
        if (!empty($this->config['require_mixed_case']) && (!preg_match('/[a-z]/', $password) || !preg_match('/[A-Z]/', $password))) {
            $errors['mixed_case'] = 'Password must contain upper and lower case letters.';
        }
        if (!empty($this->config['require_number']) && !preg_match('/\d/', $password)) {
            $errors['number'] = 'Password must contain at least one number.';
        }
        if (!empty($this->config['require_symbol']) && !preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors['symbol'] = 'Password must contain at least one symbol.';
        }
        if (!empty($this->config['block_common_passwords']) && in_array(strtolower($password), $this->commonPasswords, true)) {
            $errors['common'] = 'Password is too common.';
        }
        if (!empty($this->config['block_user_context'])) {
            $lower = strtolower($password);
            foreach (['email', 'name', 'username', 'identifier'] as $key) {
                $value = strtolower(trim((string)($context[$key] ?? '')));
                if ($value === '') { continue; }
                $parts = array_filter(preg_split('/[^a-z0-9]+/i', $value) ?: []);
                $parts[] = $value;
                foreach ($parts as $part) {
                    $part = strtolower((string)$part);
                    if (strlen($part) >= 4 && str_contains($lower, $part)) {
                        $errors['user_context'] = 'Password must not contain obvious user information.';
                        break 2;
                    }
                }
            }
        }

        return $errors === [] ? PasswordPolicyResult::pass() : PasswordPolicyResult::fail($errors);
    }
}
