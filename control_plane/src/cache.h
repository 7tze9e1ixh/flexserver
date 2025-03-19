#ifndef __CACHE_H__
#define __CACHE_H__

#include "item.h"

enum cache_type {
	AT_DISK,
	HOST_CACHE,
	NIC_CACHE,
};

typedef struct cache_method_s {
	void (*insert)(void *cache, item *it);
	void (*delete)(void *cache, item *it);
	void (*access)(void *cache, item *it);
	void (*free)(void *cache, item *it);
	item *(*get_oc)(void *cache);
	item *(*get_ec)(void *cache);
	void (*show_all)(void *cache);
} cache_method;

cache_method *cache_create(void *arg, enum cache_type ct, void **cache);
void cache_destroy(void *cache);

void cache_ctrl_setup(void);
int cache_ctrl_consume_blocks(item *it);
void cache_ctrl_free_blocks(item *it);
void cache_ctrl_teardown(void);
uint32_t cache_ctrl_get_free_blocks(void);

#endif
