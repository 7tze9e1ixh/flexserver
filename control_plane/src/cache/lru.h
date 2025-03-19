#ifndef __LFU_H__
#define __LFU_H__

#include "item.h"

void *lru_cache_setup(void *arg);
void lru_cache_insert(void *cache, item *it);
void lru_cache_delete(void *cache, item *it);
item *lru_cache_offloading_candidate(void *cache);
item *lru_cache_eviction_candidate(void *cache);
void lru_cache_destroy(void *cache);

#endif
