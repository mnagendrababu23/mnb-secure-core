<?php
namespace Mnb\SecurityCore\Web;

final class SafeTemplateRenderer
{
    public function __construct(private OutputEncodingPolicy $policy, private OutputEscaper $escaper) {}

    /** @param array<string,mixed> $data */
    public function renderString(string $template, array $data): string
    {
        return preg_replace_callback('/\{\{\s*([A-Za-z0-9_.-]+)(?:\|([a-z]+))?\s*\}\}/', function (array $matches) use ($data): string {
            $key = $matches[1];
            $context = $matches[2] ?? 'html';
            $value = $data[$key] ?? '';
            if ($value instanceof TemplateSafeValue) {
                return $value->value();
            }
            return match ($context) {
                'attr' => $this->escaper->attr($value),
                'url' => $this->escaper->url($value),
                'js' => $this->escaper->js($value),
                'css' => $this->escaper->css($value),
                'raw' => in_array($key, $this->policy->allowedRawVariables(), true) ? (string)$value : $this->escaper->html($value),
                default => $this->escaper->html($value),
            };
        }, $template) ?? '';
    }

    public function safeValue(mixed $value, string $context = 'html'): TemplateSafeValue
    {
        return new TemplateSafeValue(match ($context) {
            'attr' => $this->escaper->attr($value),
            'url' => $this->escaper->url($value),
            'js' => $this->escaper->js($value),
            'css' => $this->escaper->css($value),
            default => $this->escaper->html($value),
        }, $context);
    }
}
