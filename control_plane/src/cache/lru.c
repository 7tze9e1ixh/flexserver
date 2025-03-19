#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "lru.h"
#include "item_queue.h"

typedef struct lru_cache_s {
	item_queue *lruq;
} lru_cache;

void *
lru_cache_setup(void *arg) 
{
	(void)arg;
	lru_cache *lc;

	lc = calloc(1, sizeof(lru_cache));
	if (!lc) {
		perror("Fail to allocate memory of lru cache");
		exit(EXIT_FAILURE);
	}

	lc->lruq = item_queue_create();
	return lc;
}

void 
lru_cache_insert(void *cache, item *it)
{
	item_enqueue((item_queue *)cache, it);
}

void 
lru_cache_delete(void *cache, item *it)
{
	item_remove((item_queue *)cache, it);
}

item *
lru_cache_offloading_candidate(void *cache)
{
}

item *
lru_cache_eviction_candidate(void *cache)
{
}

void
lru_cache_access_item(void *cache)
{
}

void
lru_cache_destroy(void *cache) 
{
}
