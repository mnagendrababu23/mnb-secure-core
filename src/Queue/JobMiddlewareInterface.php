<?php
namespace Mnb\SecurityCore\Queue;

interface JobMiddlewareInterface
{
    public function before(Job $job): void;
    public function after(Job $job, JobResult $result): void;
}
