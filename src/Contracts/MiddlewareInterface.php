<?php
namespace Mnb\SecurityCore\Contracts;

use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

interface MiddlewareInterface
{
    public function process(Request $request, callable $next): Response;
}
