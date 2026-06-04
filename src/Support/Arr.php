<?php
namespace Mnb\SecurityCore\Support;

class Arr
{
    public static function only(array $data, array $keys): array
    {
        return array_intersect_key($data, array_flip($keys));
    }

    public static function except(array $data, array $keys): array
    {
        return array_diff_key($data, array_flip($keys));
    }

    public static function get(array $data, string $key, mixed $default = null): mixed
    {
        if (array_key_exists($key, $data)) {
            return $data[$key];
        }
        foreach (explode('.', $key) as $segment) {
            if (!is_array($data) || !array_key_exists($segment, $data)) {
                return $default;
            }
            $data = $data[$segment];
        }
        return $data;
    }
}
