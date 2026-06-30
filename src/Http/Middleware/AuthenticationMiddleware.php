<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Auth\AuthenticationStrategy;
use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Http\WebhookSignatureVerifier;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class AuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthenticationStrategy $strategy,
        private ?OpaqueTokenService $tokens = null,
        private ?WebhookSignatureVerifier $signatureVerifier = null,
        private ?SecurityAuditTrail $audit = null
    ) {}

    public function process(Request $request, callable $next): Response
    {
        $result = match ($this->strategy->type()) {
            AuthenticationStrategy::TYPE_NONE => AuthContext::guest(),
            AuthenticationStrategy::TYPE_SESSION => AuthContext::fromSession(),
            AuthenticationStrategy::TYPE_SIGNATURE => $this->authenticateSignature($request),
            default => $this->authenticateBearer($request),
        };

        if (!$result->isAuthenticated()) {
            if (!$this->strategy->required()) {
                return $next($request->withAttribute(AuthContext::ATTRIBUTE, AuthContext::guest())->withAttribute('auth_strategy', $this->strategy->name()));
            }
            $this->auditDenied($request, 'missing_or_invalid_credentials');
            return Response::json(['status' => false, 'message' => $this->strategy->failureMessage()], 401);
        }

        $denial = $this->authorizationDenial($result);
        if ($denial !== null) {
            $this->auditDenied($request, $denial, $result);
            return Response::json(['status' => false, 'message' => 'Forbidden'], 403);
        }

        $request = $request
            ->withAttribute(AuthContext::ATTRIBUTE, $result)
            ->withAttribute('auth_strategy', $this->strategy->name())
            ->withAttribute('auth_user_id', $result->id())
            ->withAttribute('auth_scopes', $result->scopes())
            ->withAttribute('auth_roles', $result->roles())
            ->withAttribute('auth_permissions', $result->permissions());

        if ($result->tokenRecord() !== null) {
            $request = $request->withAttribute('auth_token', $result->tokenRecord());
        }

        if ($this->strategy->audit()) {
            $this->audit?->record(SecurityAuditEvent::make(SecurityAuditEvent::CATEGORY_AUTH, 'strategy.allowed', SecurityAuditEvent::OUTCOME_SUCCESS, SecurityAuditEvent::SEVERITY_INFO, ['user_id' => $result->id()], [], SecurityAuditEvent::contextFromRequest($request), ['strategy' => $this->strategy->name(), 'type' => $this->strategy->type()]));
        }

        return $next($request);
    }

    private function authenticateBearer(Request $request): AuthContext
    {
        $plain = $request->bearerToken();
        if (!$plain || !$this->tokens) {
            return AuthContext::guest();
        }
        $record = $this->tokens->validate($plain, $request->ip(), (string)$request->header('user-agent', ''));
        return $record ? AuthContext::fromTokenRecord($record) : AuthContext::guest();
    }

    private function authenticateSignature(Request $request): AuthContext
    {
        if ($this->signatureVerifier === null) {
            return !empty($request->attribute('webhook_signature_verified'))
                ? new AuthContext(true, 'webhook', ['webhook:receive'], [], ['webhook'], null, ['source' => 'signature'])
                : AuthContext::guest();
        }
        $raw = $request->attribute('raw_body');
        $result = $this->signatureVerifier->verify($request, is_string($raw) ? $raw : '');
        return !empty($result['valid'])
            ? new AuthContext(true, 'webhook', ['webhook:receive'], [], ['webhook'], null, ['source' => 'signature'])
            : AuthContext::guest();
    }

    private function authorizationDenial(AuthContext $auth): ?string
    {
        if ($this->strategy->roles() !== [] && !$auth->hasAnyRole($this->strategy->roles())) {
            return 'missing_role';
        }
        if ($this->strategy->permissions() !== [] && !$auth->canAny($this->strategy->permissions())) {
            return 'missing_permission';
        }
        if ($this->strategy->scopes() !== [] && !$auth->hasAnyScope($this->strategy->scopes())) {
            return 'missing_scope';
        }
        return null;
    }

    private function auditDenied(Request $request, string $reason, ?AuthContext $auth = null): void
    {
        if (!$this->strategy->audit()) { return; }
        $this->audit?->record(SecurityAuditEvent::make(SecurityAuditEvent::CATEGORY_AUTH, 'strategy.denied', SecurityAuditEvent::OUTCOME_DENIED, SecurityAuditEvent::SEVERITY_WARNING, ['user_id' => $auth?->id()], [], SecurityAuditEvent::contextFromRequest($request), ['strategy' => $this->strategy->name(), 'type' => $this->strategy->type(), 'reason' => $reason]));
    }
}
