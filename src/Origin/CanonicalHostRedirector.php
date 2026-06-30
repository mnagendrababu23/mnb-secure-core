<?php
namespace Mnb\SecurityCore\Origin;

use Mnb\SecurityCore\Http\Response;

class CanonicalHostRedirector
{
    public function redirect(OriginProtectionDecision $decision, string $path = '/'): ?Response
    {
        if ($decision->action() !== 'redirect' || !$decision->targetHost()) { return null; }
        return Response::text('', $decision->status(), ['Location' => 'https://' . $decision->targetHost() . ($path !== '' ? $path : '/')]);
    }
}
