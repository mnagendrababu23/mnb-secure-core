<?php
namespace Mnb\SecurityCore\Errors;

use ErrorException;
use Mnb\SecurityCore\Contracts\LoggerInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Throwable;

class SafeErrorHandler
{
    public function __construct(
        private LoggerInterface $logger,
        private array $config = [],
        private ErrorResponseFactory $responseFactory = new ErrorResponseFactory()
    ) {}

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
        $debug = (bool)($this->config['app']['debug'] ?? false);
        $env = (string)($this->config['app']['env'] ?? 'production');
        $show = $debug && $env !== 'production';
        ini_set('display_errors', $show ? '1' : '0');
        ini_set('display_startup_errors', $show ? '1' : '0');
        ini_set('log_errors', '1');
    }

    private function log(Throwable $throwable, ErrorContext $context, array $extra = []): void
    {
        $level = $this->responseFactory->logLevel($throwable);
        $payload = $context->logContext($throwable, $extra);
        match ($level) {
            'info' => $this->logger->info('Application exception handled', $payload),
            'warning' => $this->logger->warning('Application exception handled', $payload),
            default => $this->logger->error('Application exception handled', $payload),
        };
    }
}
