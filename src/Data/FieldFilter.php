<?php
namespace Mnb\SecurityCore\Data;

use Mnb\SecurityCore\Support\Arr;

class FieldFilter
{
    public function __construct(private ?DataClassifier $classifier = null, private ?DataMasker $masker = null)
    {
        $this->classifier ??= new DataClassifier();
        $this->masker ??= new DataMasker();
    }

    public function allowOnly(array $data, array $allowedFields): array
    {
        return Arr::only($data, $allowedFields);
    }

    public function remove(array $data, array $blockedFields): array
    {
        return Arr::except($data, $blockedFields);
    }

    public function maskSensitive(array $data): array
    {
        foreach ($data as $field => $value) {
            $data[$field] = $this->masker->value($value, $this->classifier->classify((string)$field));
        }
        return $data;
    }
}
