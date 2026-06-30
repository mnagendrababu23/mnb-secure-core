<?php
namespace Mnb\SecurityCore\Auth;

final class AuthAuditEvents
{
    public const LOGIN_SUCCESS = 'login.success';
    public const LOGIN_FAILED = 'login.failed';
    public const REGISTER_SUCCESS = 'register.success';
    public const REGISTER_FAILED = 'register.failed';
    public const PASSWORD_POLICY_FAILED = 'password.policy_failed';
    public const PASSWORD_VERIFY_FAILED = 'password.verify_failed';
    public const TOKEN_ISSUED = 'token.issued';
    public const TOKEN_VALIDATED = 'token.validated';
    public const TOKEN_REJECTED = 'token.rejected';
    public const TOKEN_REVOKED = 'token.revoked';
    public const AUTH_ALLOWED = 'auth.allowed';
    public const AUTH_DENIED = 'auth.denied';
    public const SESSION_AUTHENTICATED = 'session.authenticated';
    public const SIGNATURE_AUTHENTICATED = 'signature.authenticated';

    private function __construct() {}
}
