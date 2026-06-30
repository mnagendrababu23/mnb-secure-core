<?php
namespace Mnb\SecurityCore\Origin;

class OriginExposureFinding
{
    public function __construct(public string $key, public string $level, public string $message, public string $recommendation = '') {}
    public function toArray(): array { return ['key'=>$this->key,'level'=>$this->level,'message'=>$this->message,'recommendation'=>$this->recommendation]; }
}
