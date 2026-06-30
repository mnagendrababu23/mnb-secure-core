<?php
namespace Mnb\SecurityCore\Files;

class FileSecurityRecord
{
    /** @param array<string,mixed> $data */
    public function __construct(private array $data)
    {
        $this->data['original_name'] = isset($this->data['original_name']) ? self::safeOriginalName((string)$this->data['original_name']) : 'download.bin';
        $this->data['storage_path'] = (string)($this->data['storage_path'] ?? '');
        $this->data['mime'] = (string)($this->data['mime'] ?? 'application/octet-stream');
        $this->data['extension'] = strtolower((string)($this->data['extension'] ?? pathinfo($this->data['original_name'], PATHINFO_EXTENSION)));
        $this->data['profile'] = (string)($this->data['profile'] ?? 'default');
        $this->data['data_class'] = (string)($this->data['data_class'] ?? 'internal');
        $this->data['scan_status'] = (string)($this->data['scan_status'] ?? 'passed');
    }

    /** @param array<string,mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self($data);
    }

    public static function safeOriginalName(string $name): string
    {
        $base = basename(str_replace('\\', '/', $name));
        $base = preg_replace('/[\x00-\x1F\x7F]+/', '', $base) ?: 'download.bin';
        $base = preg_replace('/[^A-Za-z0-9._ -]+/', '_', $base) ?: 'download.bin';
        $base = trim($base, " .\t\n\r\0\x0B");
        if ($base === '' || $base === '.' || $base === '..') {
            return 'download.bin';
        }
        return strlen($base) > 180 ? substr($base, 0, 180) : $base;
    }

    public function fileId(): ?string { return isset($this->data['file_id']) ? (string)$this->data['file_id'] : null; }
    public function storagePath(): string { return (string)$this->data['storage_path']; }
    public function originalName(): string { return (string)$this->data['original_name']; }
    public function mime(): string { return (string)$this->data['mime']; }
    public function extension(): string { return (string)$this->data['extension']; }
    public function profile(): string { return (string)$this->data['profile']; }
    public function dataClass(): string { return (string)$this->data['data_class']; }
    public function scanStatus(): string { return (string)$this->data['scan_status']; }
    public function checksum(): ?string { return isset($this->data['checksum_sha256']) ? (string)$this->data['checksum_sha256'] : null; }
    public function size(): int { return (int)($this->data['size'] ?? 0); }
    public function ownerUserId(): int|string|null { return $this->data['owner_user_id'] ?? $this->data['user_id'] ?? null; }
    public function schoolId(): int|string|null { return $this->data['school_id'] ?? null; }
    public function branchId(): int|string|null { return $this->data['branch_id'] ?? null; }
    public function academicYearId(): int|string|null { return $this->data['academic_year_id'] ?? null; }

    /** @return array<string,mixed> */
    public function tenantResource(): array
    {
        return array_filter([
            'school_id' => $this->schoolId(),
            'branch_id' => $this->branchId(),
            'academic_year_id' => $this->academicYearId(),
        ], fn(mixed $value): bool => $value !== null && $value !== '');
    }

    /** @return array<string,mixed> */
    public function toArray(): array { return $this->data; }
}
