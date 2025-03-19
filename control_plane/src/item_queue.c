#include <rte_common.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "item_queue.h"
#include "cache.h"

item_queue *
item_queue_create(void) 
{
	item_queue *iq;

	iq = calloc(1, sizeof(item_queue));
	if (!iq) {
		perror("Fail to allocate memory for item_queue");
		return NULL;
	}

	TAILQ_INIT(&iq->h);
	rte_spinlock_init(&iq->sl);
	return iq;
}

inline void
item_enqueue(item_queue *iq, item *it)
{
	rte_spinlock_lock(&iq->sl);
	TAILQ_INSERT_HEAD(&iq->h, it, queueLink);
	iq->sz++;
	rte_spinlock_unlock(&iq->sl);
}

inline item *
item_dequeue(item_queue *iq)
{
	item *it;
	rte_spinlock_lock(&iq->sl);
	it = TAILQ_LAST(&iq->h, item_queue_head_s);
	if (!it) {
		rte_spinlock_unlock(&iq->sl);
		return NULL;
	}
	TAILQ_REMOVE(&iq->h, it, queueLink);
	iq->sz--;
	rte_spinlock_unlock(&iq->sl);
	return it;
}

inline void
item_queue_remove(item_queue *iq, item *it)
{
	rte_spinlock_lock(&iq->sl);
	TAILQ_REMOVE(&iq->h, it, queueLink);
	rte_spinlock_unlock(&iq->sl);
}

void
item_queue_destroy(item_queue *iq) {
	rte_spinlock_unlock(&iq->sl);
	free(iq);
}

size_t 
item_queue_total_element_size(item_queue *iq)
{
	size_t total_size = 0;
	item *it;
	rte_spinlock_lock(&iq->sl);

	TAILQ_FOREACH(it, &iq->h, queueLink)
		total_size += it->sv->sz;

	rte_spinlock_unlock(&iq->sl);
	return total_size;
}

void
item_queue_consume_blocks(item_queue *iq) {
	item *it;
	int ret;
	rte_spinlock_lock(&iq->sl);
	TAILQ_FOREACH(it, &iq->h, queueLink) {
		ret = cache_ctrl_consume_blocks(it);
		assert(ret >= 0);
	}
	rte_spinlock_unlock(&iq->sl);
}
