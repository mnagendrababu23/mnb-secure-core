<?php
namespace Mnb\SecurityCore\Data;

class DataMasker
{
    public function email(string $email): string
    {
        if (!str_contains($email, '@')) {
            return '***';
        }
        [$name, $domain] = explode('@', $email, 2);
        return substr($name, 0, 1) . str_repeat('*', max(2, strlen($name) - 1)) . '@' . $domain;
    }

    public function phone(string $phone): string
    {
        $digits = preg_replace('/\D+/', '', $phone) ?? '';
        if (strlen($digits) <= 4) {
            return '****';
        }
        return str_repeat('*', strlen($digits) - 4) . substr($digits, -4);
    }

    public function value(mixed $value, string $classification): mixed
    {
        if ($value === null) {
            return null;
        }
        if ($classification === DataClassifier::HIGHLY_SENSITIVE) {
            return '[hidden]';
        }
        if ($classification === DataClassifier::SENSITIVE) {
            return '[masked]';
        }
        return $value;
    }
}
