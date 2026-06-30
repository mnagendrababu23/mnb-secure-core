<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Exceptions\ValidationException;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Validation\InputSanitizer;
use Mnb\SecurityCore\Validation\InputValidator;

class InputValidationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private array $config = [],
        private ?InputValidator $validator = null,
        private ?InputSanitizer $sanitizer = null
    ) {
        $this->validator ??= new InputValidator();
        $this->sanitizer ??= new InputSanitizer();
    }

    public function process(Request $request, callable $next): Response
    {
        if (array_key_exists('enabled', $this->config) && $this->config['enabled'] === false) {
            return $next($request);
        }

        $policy = $this->policyFor($request);
        if ($policy === []) {
            return $next($request);
        }

        try {
            $request = $this->applyPolicy($request, $policy);
        } catch (ValidationException $e) {
            if (($this->config['throw'] ?? false) === true || ($policy['throw'] ?? false) === true) {
                throw $e;
            }

            return Response::json([
                'status' => false,
                'message' => (string)($this->config['message'] ?? 'Validation failed'),
                'errors' => $e->errors(),
            ], (int)($this->config['error_status'] ?? 422));
        }

        return $next($request);
    }

    /** @return array<string,mixed> */
    private function policyFor(Request $request): array
    {
        $routeName = (string)($request->attribute('route_name') ?? '');
        $routes = is_array($this->config['routes'] ?? null) ? $this->config['routes'] : [];

        if ($routeName !== '' && isset($routes[$routeName]) && is_array($routes[$routeName])) {
            return $routes[$routeName];
        }

        foreach ($routes as $policy) {
            if (!is_array($policy)) {
                continue;
            }
            if ($this->matches($request, $policy)) {
                return $policy;
            }
        }

        $default = is_array($this->config['default'] ?? null) ? $this->config['default'] : [];
        if ($default !== [] && $this->matches($request, $default, allowMissingMatchers: true)) {
            return $default;
        }

        return [];
    }

    /** @param array<string,mixed> $policy */
    private function matches(Request $request, array $policy, bool $allowMissingMatchers = false): bool
    {
        $hasMatcher = false;
        if (isset($policy['methods'])) {
            $hasMatcher = true;
            $methods = is_array($policy['methods']) ? $policy['methods'] : explode(',', (string)$policy['methods']);
            $methods = array_map(fn($method): string => strtoupper(trim((string)$method)), $methods);
            if (!in_array($request->method(), $methods, true)) {
                return false;
            }
        }

        if (isset($policy['path'])) {
            $hasMatcher = true;
            if ($request->path() !== (string)$policy['path']) {
                return false;
            }
        }

        if (isset($policy['path_pattern'])) {
            $hasMatcher = true;
            $pattern = (string)$policy['path_pattern'];
            set_error_handler(static fn(): bool => true);
            try {
                $matched = preg_match($pattern, $request->path()) === 1;
            } finally {
                restore_error_handler();
            }
            if (!$matched) {
                return false;
            }
        }

        return $hasMatcher || $allowMissingMatchers;
    }

    /** @param array<string,mixed> $policy */
    private function applyPolicy(Request $request, array $policy): Request
    {
        $maxDepth = max(1, (int)($policy['max_depth'] ?? $this->config['max_depth'] ?? 10));
        $maxStringLength = max(1, (int)($policy['max_string_length'] ?? $this->config['max_string_length'] ?? 10000));
        $blockedKeys = $policy['blocked_keys'] ?? $this->config['blocked_keys'] ?? ['__proto__', 'prototype', 'constructor'];
        $validated = [];

        foreach (['query', 'body', 'all'] as $location) {
            $locationConfig = is_array($policy[$location] ?? null) ? $policy[$location] : [];
            if ($locationConfig === []) {
                continue;
            }

            $data = match ($location) {
                'query' => $request->queryParams(),
                'body' => $request->body(),
                default => $request->all(),
            };

            if (($locationConfig['sanitize'] ?? $policy['sanitize'] ?? $this->config['sanitize'] ?? true) !== false) {
                $data = $this->sanitizer->sanitize($data, is_array($locationConfig['sanitize_rules'] ?? null) ? $locationConfig['sanitize_rules'] : [], [
                    'allowed_fields' => is_array($locationConfig['allowed_fields'] ?? null) ? $locationConfig['allowed_fields'] : null,
                    'blocked_keys' => is_array($blockedKeys) ? $blockedKeys : [],
                    'max_depth' => $maxDepth,
                    'max_string_length' => $maxStringLength,
                ]);
            }

            $rules = is_array($locationConfig['rules'] ?? null) ? $locationConfig['rules'] : [];
            if ($rules !== []) {
                $this->validator->validate($data, $rules);
            }

            if (($locationConfig['strict'] ?? false) === true && isset($locationConfig['allowed_fields']) && is_array($locationConfig['allowed_fields'])) {
                $data = array_intersect_key($data, array_flip(array_map('strval', $locationConfig['allowed_fields'])));
            }

            if ($location === 'query') {
                $request = $request->withQuery($data);
            } elseif ($location === 'body') {
                $request = $request->withBody($data);
            }
            $validated[$location] = $data;
        }

        return $request->withAttribute('validated_input', $validated)
            ->withAttribute('input_validated', true);
    }
}
