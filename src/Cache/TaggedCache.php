<?php
namespace Mnb\SecurityCore\Cache;

use Mnb\SecurityCore\Contracts\CacheInterface;

class TaggedCache
{
    public function __construct(private CacheInterface $cache, private string $tagPrefix = 'mnb:tag:') {}

    /** @param list<string> $tags */
    public function put(string $key, mixed $value, int $ttlSeconds, array $tags = []): void
    {
        $this->cache->put($key, $value, $ttlSeconds);
        foreach ($this->safeTags($tags) as $tag) {
            $indexKey = $this->indexKey($tag);
            $keys = $this->cache->get($indexKey, []);
            $keys = is_array($keys) ? $keys : [];
            $keys[$key] = time() + max(1, $ttlSeconds);
            $this->cache->put($indexKey, $keys, max(86400, $ttlSeconds));
        }
    }

    public function get(string $key, mixed $default = null): mixed { return $this->cache->get($key, $default); }
    public function forget(string $key): void { $this->cache->forget($key); }

    /** @param list<string> $tags @return int */
    public function flushTags(array $tags): int
    {
        $count = 0;
        foreach ($this->safeTags($tags) as $tag) {
            $indexKey = $this->indexKey($tag);
            $keys = $this->cache->get($indexKey, []);
            if (is_array($keys)) {
                foreach (array_keys($keys) as $key) {
                    if (is_string($key) && $key !== '') {
                        $this->cache->forget($key);
                        $count++;
                    }
                }
            }
            $this->cache->forget($indexKey);
        }
        return $count;
    }

    private function indexKey(string $tag): string
    {
        return $this->tagPrefix . hash('sha256', $tag);
    }

    /** @param array<int,mixed> $tags @return list<string> */
    private function safeTags(array $tags): array
    {
        $safe = [];
        foreach ($tags as $tag) {
            if (is_scalar($tag) && preg_match('/^[A-Za-z0-9_.:-]{1,120}$/', (string)$tag)) {
                $safe[] = (string)$tag;
            }
        }
        return array_values(array_unique($safe));
    }
}
