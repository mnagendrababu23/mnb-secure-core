<?php
namespace Mnb\SecurityCore\Files;

use Mnb\SecurityCore\Http\Response;

class SafeDownloadResponse
{
    /** @param array<string,string> $headers */
    public static function make(string $contents, FileSecurityRecord $record, string $disposition = 'attachment', array $headers = []): Response
    {
        $filename = FileSecurityRecord::safeOriginalName($record->originalName());
        $disposition = $disposition === 'inline' ? 'inline' : 'attachment';
        $baseHeaders = [
            'Content-Type' => self::safeMime($record->mime()),
            'Content-Disposition' => self::contentDisposition($disposition, $filename),
            'X-Content-Type-Options' => 'nosniff',
            'Cache-Control' => 'private, no-store',
            'Pragma' => 'no-cache',
            'Expires' => '0',
            'Content-Length' => (string)strlen($contents),
        ];
        if ($record->checksum()) {
            $baseHeaders['Digest'] = 'sha-256=' . base64_encode(hex2bin($record->checksum()) ?: '');
            $baseHeaders['ETag'] = '"sha256-' . $record->checksum() . '"';
        }
        return new Response($contents, 200, array_replace($baseHeaders, $headers));
    }

    public static function contentDisposition(string $disposition, string $filename): string
    {
        $fallback = str_replace(['"', '\\'], '_', $filename);
        $encoded = rawurlencode($filename);
        return $disposition . '; filename="' . $fallback . '"; filename*=UTF-8\'\'' . $encoded;
    }

    private static function safeMime(string $mime): string
    {
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9!#$&^_.+\/-]{0,120}$/', $mime) || str_contains($mime, '..')) {
            return 'application/octet-stream';
        }
        return $mime;
    }
}
