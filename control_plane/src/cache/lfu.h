#ifndef __LFU_H__
#define __LFU_H__

#include "item.h"

void *lfu_cache_setup(void *arg);
void lfu_cache_insert(void *cache, item *it);
void lfu_cache_delete(void *cache, item *it);
item *lfu_cache_offloading_candidate(void *cache);
item *lfu_cache_eviction_candidate(void *cache);
void lfu_cache_destroy(void *cache);
void lfu_cache_access_item(void *cache, item *it);
#endif
