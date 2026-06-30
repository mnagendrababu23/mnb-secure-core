<?php
namespace Mnb\SecurityCore\Data;

interface KeyProviderInterface
{
    public function currentKeyId(): string;

    /** @return array<string,string> */
    public function keys(): array;
}
