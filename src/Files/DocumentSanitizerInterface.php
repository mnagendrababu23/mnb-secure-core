<?php
namespace Mnb\SecurityCore\Files;

interface DocumentSanitizerInterface
{
    public function sanitize(string $path, string $mime, string $extension): DocumentInspectionResult;
}
