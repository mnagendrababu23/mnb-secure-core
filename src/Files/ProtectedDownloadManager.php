<?php
namespace Mnb\SecurityCore\Files;

use Mnb\SecurityCore\Contracts\StorageInterface;
use Mnb\SecurityCore\Exceptions\SecurityException;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Web\CacheControlPolicy;
use Mnb\SecurityCore\Web\SignedUrl;

class ProtectedDownloadManager
{
    public function __construct(
        private StorageInterface $storage,
        private FileSecurityRegistry $registry,
        private CacheControlPolicy $cache,
        private SignedUrl $signedUrl
    ) {}

    /** @param array<string,mixed>|FileSecurityRecord $fileRecord */
    public function download(Request $request, array|FileSecurityRecord $fileRecord, string $policyName = 'files.download', ?string $disposition = null): Response
    {
        $record = $fileRecord instanceof FileSecurityRecord ? $fileRecord : FileSecurityRecord::fromArray($fileRecord);
        $decision = $this->registry->decide($policyName, $request, $record, 'download');
        if ($decision->denied()) {
            return Response::json(['status' => false, 'message' => $decision->safeMessage(), 'code' => $decision->code()], $decision->statusCode());
        }
        if ($record->storagePath() === '' || !$this->storage->exists($record->storagePath())) {
            throw new SecurityException('Protected download file does not exist');
        }
        $policy = $this->registry->get($policyName);
        $contents = $this->storage->read($record->storagePath());
        $headers = $this->cache->headers($policy->cachePolicy());
        $response = SafeDownloadResponse::make($contents, $record, $policy->dispositionFor($record, $disposition), $headers);
        return $response->withHeader('X-Download-Policy', $policyName);
    }

    /** @param array<string,mixed>|FileSecurityRecord $fileRecord @param array<string,mixed> $params */
    public function signedUrl(array|FileSecurityRecord $fileRecord, string $path, string $policyName = 'files.download', array $params = [], ?int $ttlSeconds = null): string
    {
        $record = $fileRecord instanceof FileSecurityRecord ? $fileRecord : FileSecurityRecord::fromArray($fileRecord);
        $policy = $this->registry->get($policyName);
        $ttl = $ttlSeconds ?? $policy->signedUrlTtl();
        $params = array_merge($params, array_filter([
            'file_id' => $record->fileId(),
            'policy' => $policyName,
            'storage' => substr(hash('sha256', $record->storagePath()), 0, 16),
        ]));
        return $this->signedUrl->sign($path, $params, time() + $ttl, 'file-download:' . $policyName);
    }

    public function verifySignedUrl(string $url, string $policyName = 'files.download'): bool
    {
        return $this->signedUrl->verify($url, 'file-download:' . $policyName);
    }
}
