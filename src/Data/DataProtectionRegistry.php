<?php
namespace Mnb\SecurityCore\Data;

use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class DataProtectionRegistry
{
    /** @var array<string,DataProtectionPolicy> */
    private array $policies;
    private DataMasker $masker;

    /** @param array<string,DataProtectionPolicy|array<string,mixed>> $policies @param array<string,mixed> $options */
    public function __construct(array $policies = [], private ?KeyRing $keyRing = null, private ?SearchHash $searchHash = null, private ?SecurityAuditTrail $audit = null, private array $options = [])
    {
        $this->policies = [];
        foreach ($policies as $resource => $policy) {
            if ($policy instanceof DataProtectionPolicy) {
                $this->policies[$policy->resource()] = $policy;
            } elseif (is_string($resource) && is_array($policy)) {
                $this->policies[$resource] = DataProtectionPolicy::fromArray($resource, $policy);
            }
        }
        $this->masker = new DataMasker();
    }

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config, ?SecurityAuditTrail $audit = null): self
    {
        $dp = is_array($config['data_protection'] ?? null) ? $config['data_protection'] : [];
        $appKey = (string)($config['app']['key'] ?? '');
        $keyRing = null;
        $search = null;
        if (!empty($dp['encryption']['enabled']) || !empty($dp['enabled'])) {
            $keyRing = KeyRing::fromConfig(is_array($dp['encryption'] ?? null) ? $dp['encryption'] : [], $appKey);
            $search = new SearchHash((string)($dp['search_hash']['key'] ?? $appKey), (string)($dp['search_hash']['prefix'] ?? 'mnb:search'));
        }
        return new self(
            is_array($dp['resources'] ?? null) ? $dp['resources'] : [],
            $keyRing,
            $search,
            $audit,
            $dp
        );
    }

    public function has(string $resource): bool
    {
        return isset($this->policies[$resource]);
    }

    public function policy(string $resource): DataProtectionPolicy
    {
        if (isset($this->policies[$resource])) {
            return $this->policies[$resource];
        }
        $default = (string)($this->options['default_class'] ?? DataClassifier::INTERNAL);
        return new DataProtectionPolicy($resource, $default);
    }

    /** @return array<string,DataProtectionPolicy> */
    public function policies(): array
    {
        return $this->policies;
    }

    /** @param array<string,mixed> $data @return array<string,mixed> */
    public function protectForStorage(string $resource, array $data): array
    {
        $policy = $this->policy($resource);
        $out = $data;
        foreach ($data as $name => $value) {
            $field = $policy->field((string)$name);
            if (!$field->write) {
                unset($out[$name]);
                continue;
            }
            if ($field->searchHash && $this->searchHash !== null && $value !== null && !is_array($value) && !is_object($value)) {
                $out[$field->hashFieldName()] = $this->searchHash->hash($resource, $field->name, $value);
            }
            if ($field->encrypt && $value !== null) {
                if ($this->keyRing === null) {
                    throw new \RuntimeException('Data protection encryption is enabled for a field, but no key ring is configured.');
                }
                if (!is_scalar($value)) {
                    $value = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                }
                $out[$name] = $this->keyRing->isEncrypted($value) ? $value : $this->keyRing->encrypt((string)$value, $this->aad($resource, $field->name));
            }
        }
        $this->audit('protected.storage', $resource, ['field_count' => count($out)]);
        return $out;
    }

    /** @param array<string,mixed> $data @return array<string,mixed> */
    public function unprotectFromStorage(string $resource, array $data): array
    {
        $policy = $this->policy($resource);
        $out = $data;
        foreach ($data as $name => $value) {
            $field = $policy->field((string)$name);
            if ($field->encrypt && is_string($value) && $this->keyRing?->isEncrypted($value)) {
                $out[$name] = $this->keyRing->decrypt($value, $this->aad($resource, $field->name));
            }
        }
        return $out;
    }

    /** @param array<string,mixed> $data @return array<string,mixed> */
    public function protectForResponse(string $resource, array $data, ?Request $request = null, string $mode = 'read'): array
    {
        $plain = $this->unprotectFromStorage($resource, $data);
        $policy = $this->policy($resource);
        $out = [];
        foreach ($plain as $name => $value) {
            if (str_ends_with((string)$name, '_hash')) {
                continue;
            }
            $field = $policy->field((string)$name);
            if (!$field->read || $field->classification === DataClassifier::HIGHLY_SENSITIVE) {
                continue;
            }
            $out[$name] = $this->applyMask($value, $field, 'response');
        }
        return $out;
    }

    /** @param array<string,mixed> $data @return array<string,mixed> */
    public function protectForLog(string $resource, array $data): array
    {
        $plain = $this->unprotectFromStorage($resource, $data);
        $policy = $this->policy($resource);
        $out = [];
        foreach ($plain as $name => $value) {
            if (str_ends_with((string)$name, '_hash')) {
                continue;
            }
            $field = $policy->field((string)$name);
            if (!$field->log || $field->classification === DataClassifier::HIGHLY_SENSITIVE) {
                $out[$name] = '[redacted]';
                continue;
            }
            $out[$name] = $this->applyMask($value, $field, 'log');
        }
        return $out;
    }

    /** @param array<string,mixed> $data @return array<string,mixed> */
    public function protectForExport(string $resource, array $data): array
    {
        $plain = $this->unprotectFromStorage($resource, $data);
        $policy = $this->policy($resource);
        $out = [];
        foreach ($plain as $name => $value) {
            if (str_ends_with((string)$name, '_hash')) {
                continue;
            }
            $field = $policy->field((string)$name);
            if ($field->export === false || $field->classification === DataClassifier::HIGHLY_SENSITIVE) {
                continue;
            }
            $out[$name] = $field->export === 'masked' ? $this->applyMask($value, $field, 'export') : $value;
        }
        $this->audit('protected.export', $resource, ['field_count' => count($out)]);
        return $out;
    }

    public function searchHash(string $resource, string $field, mixed $value): string
    {
        if ($this->searchHash === null) {
            throw new \RuntimeException('Search hashing is not configured.');
        }
        return $this->searchHash->hash($resource, $field, $value);
    }

    private function applyMask(mixed $value, ProtectedField $field, string $mode): mixed
    {
        if ($value === null) { return null; }
        $mask = $field->mask;
        if ($mask === false) { return $value; }
        if ($mask === null && in_array($field->classification, [DataClassifier::SENSITIVE, DataClassifier::HIGHLY_SENSITIVE], true)) {
            return $this->masker->value($value, $field->classification);
        }
        if ($mask === null || $mask === '') {
            return $value;
        }
        $string = (string)$value;
        return match ($mask) {
            'email' => $this->masker->email($string),
            'phone', 'last4' => $this->masker->phone($string),
            'hidden' => '[hidden]',
            'masked' => '[masked]',
            default => $this->masker->value($value, $field->classification),
        };
    }

    private function aad(string $resource, string $field): string
    {
        return !empty($this->options['encryption']['aad']) ? $resource . ':' . $field : '';
    }

    /** @param array<string,mixed> $meta */
    private function audit(string $action, string $resource, array $meta = []): void
    {
        if (!$this->audit || empty($this->options['audit'])) {
            return;
        }
        $this->audit->record(SecurityAuditEvent::sensitive($action, SecurityAuditEvent::OUTCOME_SUCCESS, [], ['resource' => $resource], [], $meta));
    }
}
