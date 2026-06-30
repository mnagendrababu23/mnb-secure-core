<?php
namespace Mnb\SecurityCore\Web;

final class TemplateSafeValue implements \Stringable
{
    public function __construct(private string $value, private string $context = 'html') {}
    public function value(): string { return $this->value; }
    public function context(): string { return $this->context; }
    public function __toString(): string { return $this->value; }
    public function toArray(): array { return ['value' => $this->value, 'context' => $this->context, 'safe' => true]; }
}
