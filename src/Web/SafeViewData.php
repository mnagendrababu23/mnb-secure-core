<?php
namespace Mnb\SecurityCore\Web;

final class SafeViewData
{
    /** @var array<string,TemplateSafeValue|mixed> */
    private array $data = [];

    public function __construct(private OutputEscaper $escaper) {}

    public function html(string $key, mixed $value): self { $this->data[$key] = new TemplateSafeValue($this->escaper->html($value), 'html'); return $this; }
    public function attr(string $key, mixed $value): self { $this->data[$key] = new TemplateSafeValue($this->escaper->attr($value), 'attr'); return $this; }
    public function url(string $key, mixed $value): self { $this->data[$key] = new TemplateSafeValue($this->escaper->url($value), 'url'); return $this; }
    public function js(string $key, mixed $value): self { $this->data[$key] = new TemplateSafeValue($this->escaper->js($value), 'js'); return $this; }
    public function css(string $key, mixed $value): self { $this->data[$key] = new TemplateSafeValue($this->escaper->css($value), 'css'); return $this; }

    public function rawTrusted(string $key, string $alreadySafeValue): self
    {
        $this->data[$key] = new TemplateSafeValue($alreadySafeValue, 'trusted_raw');
        return $this;
    }

    /** @return array<string,TemplateSafeValue|mixed> */
    public function all(): array { return $this->data; }

    /** @return array<string,string> */
    public function strings(): array
    {
        $out = [];
        foreach ($this->data as $key => $value) {
            $out[$key] = $value instanceof TemplateSafeValue ? $value->value() : (string)$value;
        }
        return $out;
    }
}
