<?php
namespace Mnb\SecurityCore\Queue;

interface JobHandlerInterface
{
    public function handle(Job $job): JobResult;
}
