#ifndef __CACHE_BUFFER_H__
#define __CACHE_BUFFER_H__

#include <stdint.h>
#include <sys/queue.h>
#include <pthread.h>
#include "mtcp.h"
#include "nic_cache.h"

#if USE_DPDK_MEMPOOL
#include "memory_mgt.h"
#endif

enum cb_type {
	CACHE_BUFFER_L1,
	CACHE_BUFFER_L2,
};

typedef struct cache_buffer {
	uint64_t hv;
	void **l2_block_map;
	int numBlocks;
	enum cb_type type;
#if !USE_DPDK_MEMPOOL
	TAILQ_ENTRY(cache_buffer) cache_buffer_link;
#endif
} cache_buffer;

typedef struct cache_buffer_pool {
	uint32_t numCacheBuffer;
#if USE_DPDK_MEMPOOL
	mem_pool_t mp_cb;
	mem_pool_t mp_map;
#else
	TAILQ_HEAD(, cache_buffer) cache_buffer_free_list;
	cache_buffer *cb_ptr;
	void **block_map_ptr;
	pthread_spinlock_t cbp_sl;
#endif
} cache_buffer_pool;

void
cache_buffer_pool_create(mtcp_manager_t mtcp, uint32_t thresh);

void
cache_buffer_pool_destroy(mtcp_manager_t mtcp);

extern cache_buffer *
cache_buffer_l1_alloc(mtcp_manager_t mtcp);

extern cache_buffer *
cache_buffer_l2_alloc(mtcp_manager_t mtcp);

extern void
cache_buffer_free(mtcp_manager_t mtcp, cache_buffer *cb);


#endif /* __CACHE_BUFFER_H__ */
