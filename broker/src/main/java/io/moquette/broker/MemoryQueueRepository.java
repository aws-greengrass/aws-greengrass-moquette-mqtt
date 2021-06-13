package io.moquette.broker;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;

import io.moquette.BrokerConstants;
import io.moquette.broker.config.IConfig;

public class MemoryQueueRepository implements IQueueRepository {
    int capacity;

    public MemoryQueueRepository() {
        capacity = 0;
    }

    public MemoryQueueRepository(IConfig props) {
        int capacity = Integer.parseInt(props.getProperty(BrokerConstants.SESSION_QUEUE_SIZE, "0"));
        if (capacity < 0) {
            capacity = 0;
        }
        this.capacity = capacity;
    }

    // TODO: Clients connecting with random client IDs will leak
    // these sessions. There should be logic to remove these
    private Map<String, Queue<SessionRegistry.EnqueuedMessage>> queues = new HashMap<>();

    @Override
    public Queue<SessionRegistry.EnqueuedMessage> createQueue(String cli, boolean clean) {
        if (capacity == 0) {
            final ConcurrentLinkedQueue<SessionRegistry.EnqueuedMessage> queue = new ConcurrentLinkedQueue<>();
            queues.put(cli, queue);
            return queue;
        } else {
            // Cannot specify capacity on ConcurrentLinkedQueue
            final LinkedBlockingQueue<SessionRegistry.EnqueuedMessage> queue = new LinkedBlockingQueue<>(capacity);
            queues.put(cli, queue);
            return queue;
        }
    }

    @Override
    public Map<String, Queue<SessionRegistry.EnqueuedMessage>> listAllQueues() {
        return Collections.unmodifiableMap(queues);
    }
}
