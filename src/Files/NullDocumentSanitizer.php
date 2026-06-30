<?php
namespace Mnb\SecurityCore\Files;

class NullDocumentSanitizer implements DocumentSanitizerInterface
{
    public function sanitize(string $path, string $mime, string $extension): DocumentInspectionResult
    {
        return DocumentInspectionResult::pass('document sanitization skipped');
    }
}
