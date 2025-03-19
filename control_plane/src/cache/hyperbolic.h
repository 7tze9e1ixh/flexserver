#ifndef __HYPERBOLIC_H__
#define __HYPERBOLIC_H__

#include "item.h"

void *hyperbolic_cache_setup(const char *name, void *args);
void hyperbolic_cache_insert(void *cache, item *it);
void hyperbolic_cache_delete(void *cache, item *it);
item *hyperbolic_cache_offloading_candidate(void *cache);
item *hyperbolic_cache_eviction_candidate(void *cache);
void hyperbolic_cache_access_item(void *cache, item *it);
void  hyperbolic_cache_free_item(void *cache, item *it);
void hyperbolic_cache_destroy(void *cache);
item *hyperbolic_get_oc_for_control_plane(void *cache);
void hyperbolic_show_all(void *cache);
#endif
