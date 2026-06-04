<?php
namespace Mnb\SecurityCore\Http;

use Mnb\SecurityCore\Data\FieldFilter;

class SafeResponseBuilder
{
    public function __construct(private FieldFilter $filter) {}

    public function success(array $data = [], string $message = 'OK', array $allowedFields = []): Response
    {
        if ($allowedFields) {
            $data = $this->filter->allowOnly($data, $allowedFields);
        }
        return Response::json(['status' => true, 'message' => $message, 'data' => $data]);
    }

    public function error(string $message, int $status = 400, array $errors = []): Response
    {
        return Response::json(['status' => false, 'message' => $message, 'errors' => $errors], $status);
    }
}
