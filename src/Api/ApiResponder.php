<?php
namespace Mnb\SecurityCore\Api;

use Mnb\SecurityCore\Http\Response;

class ApiResponder
{
    public function ok(array $data = [], string $message = 'OK'): Response
    {
        return Response::json(['status' => true, 'message' => $message, 'data' => $data]);
    }

    public function fail(string $message, int $status = 400, array $errors = []): Response
    {
        return Response::json(['status' => false, 'message' => $message, 'errors' => $errors], $status);
    }
}
