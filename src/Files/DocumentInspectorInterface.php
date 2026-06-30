<?php
namespace Mnb\SecurityCore\Files;

interface DocumentInspectorInterface
{
    public function inspect(string $path, string $mime, string $extension): DocumentInspectionResult;
}
