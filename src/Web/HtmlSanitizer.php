<?php
namespace Mnb\SecurityCore\Web;

class HtmlSanitizer
{
    /** @var list<string> */
    private array $allowedTags;
    /** @var list<string> */
    private array $allowedAttributes;
    private bool $allowDataImages;

    /** @param array<string,mixed> $config */
    public function __construct(array $config = [])
    {
        $this->allowedTags = array_values(array_unique(array_map('strtolower', array_map('strval', $config['allowed_tags'] ?? ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'a']))));
        $this->allowedAttributes = array_values(array_unique(array_map('strtolower', array_map('strval', $config['allowed_attributes'] ?? ['href', 'title']))));
        $this->allowDataImages = (bool)($config['allow_data_images'] ?? false);
    }

    public function sanitize(string $html): string
    {
        $html = $this->removeDangerousBlocks($html);
        $allowed = '<' . implode('><', $this->allowedTags) . '>';
        $html = strip_tags($html, $allowed);

        return preg_replace_callback('/<\/?([a-zA-Z0-9]+)([^>]*)>/u', function (array $matches): string {
            $full = $matches[0];
            $tag = strtolower($matches[1]);
            if (!in_array($tag, $this->allowedTags, true)) {
                return '';
            }
            if (str_starts_with($full, '</')) {
                return '</' . $tag . '>';
            }

            $attrs = $this->sanitizeAttributes($matches[2] ?? '');
            return '<' . $tag . ($attrs !== '' ? ' ' . $attrs : '') . '>';
        }, $html) ?? '';
    }

    private function removeDangerousBlocks(string $html): string
    {
        $patterns = [
            '/<\s*(script|style|iframe|object|embed|link|meta|base|form)[^>]*>.*?<\s*\/\s*\1\s*>/is',
            '/<\s*(script|style|iframe|object|embed|link|meta|base|form)[^>]*\/?>/is',
            '/<!--[\s\S]*?-->/u',
        ];
        return preg_replace($patterns, '', $html) ?? '';
    }

    private function sanitizeAttributes(string $raw): string
    {
        if (trim($raw) === '') {
            return '';
        }
        $safe = [];
        preg_match_all('/([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("[^"]*"|\'[^\']*\'|[^\s"\'>]+)/u', $raw, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $name = strtolower($match[1]);
            if (str_starts_with($name, 'on') || !in_array($name, $this->allowedAttributes, true)) {
                continue;
            }
            $value = trim($match[2], " \t\n\r\0\x0B\"'");
            if (!$this->isSafeAttributeValue($name, $value)) {
                continue;
            }
            $safe[] = $name . '="' . htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '"';
        }
        return implode(' ', $safe);
    }

    private function isSafeAttributeValue(string $name, string $value): bool
    {
        if (preg_match('/[\x00-\x1F\x7F]/', $value)) {
            return false;
        }
        if (in_array($name, ['href', 'src', 'action', 'formaction'], true)) {
            $normalized = strtolower(trim(html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8')));
            if (str_starts_with($normalized, 'javascript:') || str_starts_with($normalized, 'vbscript:') || str_starts_with($normalized, 'file:')) {
                return false;
            }
            if (str_starts_with($normalized, 'data:')) {
                return $this->allowDataImages && preg_match('/^data:image\/(png|gif|jpeg|webp);base64,[a-z0-9+\/]+=*$/i', $normalized) === 1;
            }
        }
        return true;
    }
}
