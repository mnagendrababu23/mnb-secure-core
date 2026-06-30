<?php
namespace Mnb\SecurityCore\Errors;

use ErrorException;
use Mnb\SecurityCore\Contracts\LoggerInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Throwable;

class SafeErrorHandler
{
    private ErrorPolicy $policy;
    private ErrorLogSanitizer $logSanitizer;
    private StackTraceSanitizer $stackTraceSanitizer;
    private ErrorFingerprint $fingerprint;
    private ErrorDeduplicator $deduplicator;
    private ErrorEscalationPolicy $escalationPolicy;
    private ErrorAlertDispatcher $alertDispatcher;
    private ErrorEventFactory $eventFactory;

    public function __construct(
        private LoggerInterface $logger,
        private array $config = [],
        private ?ErrorResponseFactory $responseFactory = null
    ) {
        $this->policy = ErrorPolicy::fromConfig($config);
        $catalog = ErrorCatalog::fromConfig($config);
        $normalizer = new ValidationErrorNormalizer($this->policy);
        $mapper = new ExceptionMapper($catalog, $normalizer);
        $this->responseFactory ??= new ErrorResponseFactory($mapper, new ProblemDetailsResponseFactory($catalog), new SafeErrorPageRenderer());
        $this->logSanitizer = new ErrorLogSanitizer($this->policy);
        $this->stackTraceSanitizer = new StackTraceSanitizer($this->policy, $this->logSanitizer);
        $this->fingerprint = new ErrorFingerprint($this->policy, $this->logSanitizer);
        $this->deduplicator = new ErrorDeduplicator();
        $this->escalationPolicy = ErrorEscalationPolicy::fromConfig($config);
        $this->alertDispatcher = new ErrorAlertDispatcher($logger);
        $this->eventFactory = new ErrorEventFactory($this->policy, $mapper, $this->fingerprint, $this->logSanitizer, $this->stackTraceSanitizer);
    }

    public function register(): void
    {
        $this->configurePhpErrorVisibility();

        set_error_handler(function (int $severity, string $message, string $file, int $line): bool {
            if (!(error_reporting() & $severity)) {
                return false;
            }
            throw new ErrorException($message, 0, $severity, $file, $line);
        });

        set_exception_handler(function (Throwable $throwable): void {
            $request = Request::fromGlobals();
            $this->renderThrowable($throwable, $request)->send();
        });

        register_shutdown_function(function (): void {
            $error = error_get_last();
            if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
                $throwable = new ErrorException($error['message'], 0, $error['type'], $error['file'], $error['line']);
                $request = Request::fromGlobals();
                $this->renderThrowable($throwable, $request)->send();
            }
        });
    }

    public function renderThrowable(Throwable $throwable, ?Request $request = null, array $extraLogContext = []): Response
    {
        $request ??= new Request('GET', '/');
        $context = ErrorContext::fromRequest($request, $this->config);
        $this->log($throwable, $context, $extraLogContext + [
            'path' => $request->path(),
            'method' => $request->method(),
            'ip' => $request->ip(),
        ]);
        return $this->responseFactory->fromThrowable($throwable, $context);
    }

    public function configurePhpErrorVisibility(): void
    {
        $show = $this->policy->shouldExposeDebug();
        ini_set('display_errors', $show ? '1' : '0');
        ini_set('display_startup_errors', $show ? '1' : '0');
        ini_set('log_errors', '1');
    }

    private function log(Throwable $throwable, ErrorContext $context, array $extra = []): void
    {
        $event = $this->eventFactory->create($throwable, $context, $extra);
        $payload = $event->toArray();
        $count = $this->deduplicator->record($event->fingerprint());
        $payload['occurrence_count'] = $count;

        match ($event->severity()) {
            'info' => $this->logger->info('Application exception handled', $payload),
            'warning' => $this->logger->warning('Application exception handled', $payload),
            default => $this->logger->error('Application exception handled', $payload),
        };

        if ($this->escalationPolicy->shouldEscalate($payload, $count)) {
            $this->alertDispatcher->dispatch($payload);
        }
    }
}
