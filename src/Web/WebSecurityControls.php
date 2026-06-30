<?php
namespace Mnb\SecurityCore\Web;

class WebSecurityControls
{
    public function __construct(
        private WebSecurityProfile $profile,
        private OutputEscaper $escaper,
        private HtmlSanitizer $sanitizer,
        private SafeRedirector $redirector,
        private SecureCookieBuilder $cookies,
        private CacheControlPolicy $cache,
        private SignedUrl $signedUrl
    ) {}

    public function profile(): WebSecurityProfile { return $this->profile; }
    public function escaper(): OutputEscaper { return $this->escaper; }
    public function sanitizer(): HtmlSanitizer { return $this->sanitizer; }
    public function redirector(): SafeRedirector { return $this->redirector; }
    public function cookies(): SecureCookieBuilder { return $this->cookies; }
    public function cache(): CacheControlPolicy { return $this->cache; }
    public function signedUrl(): SignedUrl { return $this->signedUrl; }

    public function escapeHtml(mixed $value): string { return $this->escaper->html($value); }
    public function sanitizeHtml(string $html): string { return $this->sanitizer->sanitize($html); }
    public function safeRedirect(?string $target, string $fallback = '/'): string { return $this->redirector->to($target, $fallback); }
}
