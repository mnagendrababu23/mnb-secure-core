<?php
namespace Mnb\SecurityCore\Queue;

final class QueuePressureGuard
{
    public function __construct(private QueuePolicy $policy, private QueueStoreInterface $store) {}
    public function check(string $queue): array
    {
        $depth = $this->store->metrics()->depthForQueue($queue);
        $max = $this->policy->maxDepth($queue);
        $ratio = $max > 0 ? $depth / $max : 0;
        return ['passed'=>$ratio < 0.90, 'queue'=>$queue, 'depth'=>$depth, 'max_depth'=>$max, 'status'=>$ratio >= 1 ? 'critical' : ($ratio >= .75 ? 'warning' : 'ok')];
    }
}
