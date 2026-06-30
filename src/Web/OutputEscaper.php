<?php
namespace Mnb\SecurityCore\Web;

class OutputEscaper
{
    public function html(mixed $value): string
    {
        return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }

    public function attr(mixed $value): string
    {
        return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }

    public function url(mixed $value): string
    {
        $value = (string)($value ?? '');
        return rawurlencode($value);
    }

    public function js(mixed $value): string
    {
        return json_encode((string)($value ?? ''), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES) ?: '""';
    }

    public function css(mixed $value): string
    {
        $value = (string)($value ?? '');
        return preg_replace_callback('/[^a-zA-Z0-9 _.,#%()\-]/u', static function (array $matches): string {
            $char = $matches[0];
            $code = strtoupper(dechex(mb_ord($char, 'UTF-8')));
            return '\\' . $code . ' ';
        }, $value) ?? '';
    }
}
