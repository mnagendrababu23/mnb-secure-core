<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Errors\ErrorContext;
use Mnb\SecurityCore\Errors\ErrorDeduplicator;
use Mnb\SecurityCore\Errors\ErrorEventFactory;
use Mnb\SecurityCore\Errors\ExceptionMapper;
use Mnb\SecurityCore\Errors\ProblemDetailsResponseFactory;
use Mnb\SecurityCore\Errors\SafeErrorHandler;
use Mnb\SecurityCore\Exceptions\SecurityException;
use Mnb\SecurityCore\Exceptions\ValidationException;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Logging\FileLogger;

function demo34_contains_no_sensitive_frontend(string $body): bool
{
    return !str_contains($body, 'SQLSTATE') && !str_contains($body, 'password=secret') && !str_contains($body, '/var/www');
}

demo_title('34. Safe Error Response and Technical Log Isolation Engine');

$config = require __DIR__ . '/../config/security.php';
$config['app']['env'] = 'production';
$config['app']['debug'] = false;
$config['errors']['response_format'] = 'json';
$config['errors']['escalation']['critical_error_threshold'] = 2;
$log = demo_storage_path('logs/demo34-errors.log');
@unlink($log);

$kernel = new SecurityKernel($config);
demo_step('Error policy loaded', $kernel->errorPolicy()->toArray());
demo_step('Error catalog loaded', array_keys($kernel->errorCatalog()->all()));

$handler = new SafeErrorHandler(new FileLogger($log), $config);
$request = new Request('GET', '/demo/errors/internal', [], [], ['accept' => 'application/json'], ['REMOTE_ADDR' => '203.0.113.20']);
$exception = new RuntimeException('SQLSTATE[HY000] password=secret /var/www/private.php token=abc123');
$response = $handler->renderThrowable($exception, $request);
demo_step('Internal exception mapped to safe frontend response', json_decode($response->body(), true));
demo_step('Request ID included', $response->headers()['X-Request-Id'] ?? null);

$logText = file_get_contents($log) ?: '';
demo_step('Technical log written internally', str_contains($logText, 'Application exception handled'));
demo_step('Secrets and paths redacted from logs', !str_contains($logText, 'password=secret') && !str_contains($logText, '/var/www/private.php'));

$validation = new ValidationException([
    'password_hash' => ['users.password_hash column invalid'],
    'tenant_internal_id' => ['Internal tenant field failed'],
    'email' => ['Email is required'],
]);
$validationResponse = $handler->renderThrowable($validation, new Request('POST', '/demo/errors/validation', [], [], ['accept' => 'application/json']));
demo_step('Validation errors normalized safely', json_decode($validationResponse->body(), true));

$problemConfig = $config;
$problemConfig['errors']['response_format'] = 'problem_json';
$problemHandler = new SafeErrorHandler(new FileLogger($log), $problemConfig);
$problem = $problemHandler->renderThrowable(new SecurityException('Blocked SSRF token=secret'), new Request('GET', '/demo/errors/security', [], [], ['accept' => 'application/problem+json']));
demo_step('Problem+JSON response generated', ['content_type' => $problem->headers()['Content-Type'] ?? null, 'body' => json_decode($problem->body(), true)]);

$htmlConfig = $config;
$htmlConfig['errors']['response_format'] = 'html';
$htmlHandler = new SafeErrorHandler(new FileLogger($log), $htmlConfig);
$html = $htmlHandler->renderThrowable(new RuntimeException('<script>alert(1)</script> password=secret'), new Request('GET', '/demo/errors/html', [], [], ['accept' => 'text/html']));
demo_step('HTML error page rendered safely', !str_contains($html->body(), '<script>alert(1)</script>'));

$policy = $kernel->errorPolicy();
$context = ErrorContext::fromRequest($request, $config);
$mapper = new ExceptionMapper($kernel->errorCatalog(), $kernel->validationErrorNormalizer());
$mapped = $mapper->map($exception);
$fingerprint = $kernel->errorFingerprint()->create($exception, $context, $mapped, ['path' => '/demo/errors/internal']);
$dedup = new ErrorDeduplicator();
$count1 = $dedup->record($fingerprint);
$count2 = $dedup->record($fingerprint);
demo_step('Error fingerprint and deduplication generated', ['fingerprint' => $fingerprint, 'count' => $count2]);

$eventFactory = new ErrorEventFactory($policy, $mapper, $kernel->errorFingerprint(), $kernel->errorLogSanitizer(), $kernel->stackTraceSanitizer());
$event = $eventFactory->create(new SecurityException('Blocked request token=secret'), $context, ['path' => '/demo/errors/security']);
$escalates = $kernel->errorEscalationPolicy()->shouldEscalate($event->toArray(), 1);
demo_step('Security error escalation policy evaluated', $escalates);

$vulnerability = $kernel->vulnerabilityMatrix()->find('error_disclosure');
demo_step('Vulnerability matrix includes error disclosure coverage', $vulnerability?->toArray());

demo_result(
    $response->status() === 500
    && demo34_contains_no_sensitive_frontend($response->body())
    && str_contains($logText, 'fingerprint')
    && !str_contains($logText, 'password=secret')
    && !str_contains($logText, '/var/www/private.php')
    && !str_contains($validationResponse->body(), 'password_hash')
    && ($problem->headers()['Content-Type'] ?? '') === 'application/problem+json; charset=UTF-8'
    && !str_contains($html->body(), '<script>alert(1)</script>')
    && $count1 === 1
    && $count2 === 2
    && $escalates
    && $vulnerability !== null,
    'Safe responses, hidden technical logs, redaction, validation normalization, problem+json, HTML rendering, fingerprinting, escalation, and matrix coverage are working.'
);
