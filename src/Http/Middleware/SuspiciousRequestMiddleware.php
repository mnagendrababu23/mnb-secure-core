<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class SuspiciousRequestMiddleware implements MiddlewareInterface
{
    /** @var list<string> */
    private array $patterns;

    public function __construct(private array $config = [], private ?SecurityAuditTrail $audit = null)
    {
        $this->patterns = is_array($config['patterns'] ?? null) ? $config['patterns'] : [
            '../', '..\\', '%2e%2e', '<script', 'union select', 'information_schema', '<?php', 'cmd=', 'powershell', 'etc/passwd'
        ];
    }

    public function process(Request $request, callable $next): Response
    {
        $reasons = $this->reasons($request);
        if ($reasons !== []) {
            $this->audit?->record(SecurityAuditEvent::make(
                SecurityAuditEvent::CATEGORY_SYSTEM,
                'request.suspicious',
                SecurityAuditEvent::OUTCOME_WARNING,
                SecurityAuditEvent::SEVERITY_WARNING,
                [],
                ['path' => $request->path(), 'method' => $request->method()],
                SecurityAuditEvent::contextFromRequest($request),
                ['reasons' => $reasons]
            ));
            if (($this->config['mode'] ?? 'block') === 'block') {
                return Response::json(['status' => false, 'message' => 'Suspicious request rejected'], 400);
            }
            $request = $request->withAttribute('suspicious_request_reasons', $reasons);
        }
        return $next($request);
    }

    /** @return list<string> */
    private function reasons(Request $request): array
    {
        $reasons = [];
        $path = $request->path();
        if ($path === '' || preg_match('/[\x00-\x1F\x7F]/', $path)) {
            $reasons[] = 'path_control_chars';
        }
        if (strlen($path) > (int)($this->config['max_path_length'] ?? 2048)) {
            $reasons[] = 'path_too_long';
        }
        if (str_contains($path, '..') || str_contains(strtolower(rawurldecode($path)), '../')) {
            $reasons[] = 'path_traversal';
        }
        $paramLimit = (int)($this->config['max_parameters'] ?? 200);
        if (count($request->all()) > $paramLimit) {
            $reasons[] = 'too_many_parameters';
        }
        $haystack = strtolower($path . ' ' . $this->flatten($request->queryParams()) . ' ' . $this->flatten($request->body()));
        foreach ($this->patterns as $pattern) {
            $needle = strtolower((string)$pattern);
            if ($needle !== '' && str_contains($haystack, $needle)) {
                $reasons[] = 'suspicious_pattern:' . $needle;
                break;
            }
        }
        return array_values(array_unique($reasons));
    }

    private function flatten(mixed $value): string
    {
        if (is_scalar($value) || $value === null) {
            return (string)$value;
        }
        if (!is_array($value)) {
            return '';
        }
        $out = '';
        foreach ($value as $k => $v) {
            $out .= ' ' . (string)$k . ' ' . $this->flatten($v);
            if (strlen($out) > 10000) { return substr($out, 0, 10000); }
        }
        return $out;
    }
}
