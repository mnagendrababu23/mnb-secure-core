<?php
namespace Mnb\SecurityCore\Authorization;

use Mnb\SecurityCore\Http\Request;

interface ResourceResolverInterface
{
    /** @return array<string,mixed>|object|null */
    public function resolve(Request $request, string $policyName): array|object|null;
}
