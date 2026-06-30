<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class RequestIdMiddleware implements MiddlewareInterface
{
    public function __construct(
        private string $headerName = 'X-Request-ID',
        private bool $acceptIncoming = true,
        private int $maxLength = 80
    ) {}

    public function process(Request $request, callable $next): Response
    {
        $incoming = $this->acceptIncoming ? $request->header($this->headerName) : null;
        $requestId = is_scalar($incoming) ? trim((string)$incoming) : '';
        if (!$this->isSafeRequestId($requestId)) {
            $requestId = $this->newRequestId();
        }

        $request = $request->withAttribute('request_id', $requestId)
            ->withAttribute('correlation_id', $requestId);

        return $next($request)->withHeader($this->headerName, $requestId);
    }

    private function isSafeRequestId(string $value): bool
    {
        return $value !== ''
            && strlen($value) <= $this->maxLength
            && !preg_match('/[\r\n]/', $value)
            && (bool)preg_match('/^[A-Za-z0-9_.:-]+$/', $value);
    }

    private function newRequestId(): string
    {
        try {
            return bin2hex(random_bytes(16));
        } catch (\Throwable) {
            return str_replace('.', '', uniqid('req_', true));
        }
    }
}
