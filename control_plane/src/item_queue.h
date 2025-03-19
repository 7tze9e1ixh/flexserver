#ifndef __ITEM_QUEUE_H__
#define __ITEM_QUEUE_H__

#include <rte_spinlock.h>
#include "item.h"

typedef struct item_queue_head_s item_head;
TAILQ_HEAD(item_queue_head_s, item_s);

typedef struct item_queue_s {
	item_head h;
	size_t sz;
	rte_spinlock_t sl;
} item_queue;

item_queue *item_queue_create(void);
void item_enqueue(item_queue *iq, item *it);
item *item_dequeue(item_queue *iq);
void item_queue_destroy(item_queue *iq);
size_t item_queue_total_element_size(item_queue *iq);
void item_queue_remove(item_queue *iq, item *it);
void item_queue_consume_blocks(item_queue *iq);
#endif
