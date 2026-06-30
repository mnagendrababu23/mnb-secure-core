<?php
namespace Mnb\SecurityCore\Token;

final class TokenType
{
    public const ACCESS = 'access';
    public const REFRESH = 'refresh';
    public const API = 'api';
    public const REMEMBER_ME = 'remember_me';
    public const PASSWORD_RESET = 'password_reset';
    public const EMAIL_VERIFICATION = 'email_verification';
    public const OTP_CHALLENGE = 'otp_challenge';

    public static function known(): array
    {
        return [self::ACCESS, self::REFRESH, self::API, self::REMEMBER_ME, self::PASSWORD_RESET, self::EMAIL_VERIFICATION, self::OTP_CHALLENGE];
    }

    public static function normalize(string $type): string
    {
        $type = strtolower(trim($type));
        return in_array($type, self::known(), true) ? $type : self::ACCESS;
    }
}
