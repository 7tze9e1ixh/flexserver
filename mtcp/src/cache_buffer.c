#include <stdio.h>
#include <stdlib.h>

#include "debug.h"
#include "cache_buffer.h"

#define MAX_MAP_SIZE 128

cache_buffer_pool *g_cbp[MAX_CPUS] = {NULL};

void
cache_buffer_pool_create(mtcp_manager_t mtcp, uint32_t thresh) {

	cache_buffer_pool *cbp;

	cbp = calloc(1, sizeof(cache_buffer_pool));
	if (!cbp) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}
	cbp->numCacheBuffer = thresh;
#if USE_DPDK_MEMPOOL
	char tmpbuf[256];
	sprintf(tmpbuf, "cbp-%d", mtcp->ctx->cpu);
	cbp->mp_cb = MPCreate(tmpbuf, sizeof(cache_buffer), (uint64_t)thresh * sizeof(cache_buffer));
	if (!cbp->mp_cb) {
		TRACE_ERROR("MPCreate()\n");
		exit(EXIT_FAILURE);
	}

	sprintf(tmpbuf, "map-pool-%d", mtcp->ctx->cpu);
	cbp->mp_map = MPCreate(tmpbuf, sizeof(void *) * MAX_MAP_SIZE, 
			(uint64_t)thresh * sizeof(void *) * MAX_MAP_SIZE);
	if (!cbp->mp_map) {
		TRACE_ERROR("MPCreate()\n");
		exit(EXIT_FAILURE);
	}
#else
	int i;
	cbp->cb_ptr = calloc(thresh, sizeof(cache_buffer));
	if (!cbp->cb_ptr) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < thresh; i++) 
		TAILQ_INSERT_TAIL(&cbp->cache_buffer_free_list, &cbp->cb_ptr[i], cache_buffer_link);
	pthread_spin_init(&cbp->cbp_sl, PTHREAD_PROCESS_PRIVATE);
#endif
	g_cbp[mtcp->ctx->cpu] = cbp;
}

void
cache_buffer_pool_destroy(mtcp_manager_t mtcp) {

	cache_buffer_pool *cbp = g_cbp[mtcp->ctx->cpu];
#if USE_DPDK_MEMPOOL
	MPDestroy(cbp->mp_cb);
	MPDestroy(cbp->mp_map);
#else
	free(cbp->cb_ptr);
#endif
	free(cbp);
}

inline static cache_buffer *
__cache_buffer_alloc(mtcp_manager_t mtcp, enum cb_type type) {

	cache_buffer *cb;
	cache_buffer_pool *cbp = g_cbp[mtcp->ctx->cpu];
#if USE_DPDK_MEMPOOL
	cb = MPAllocateChunk(cbp->mp_cb);
	if (!cb) 
		return NULL;
	
	cb->type = type;

	if (type == CACHE_BUFFER_L1) {
		cb->l2_block_map = NULL;
	} else {
		cb->l2_block_map = MPAllocateChunk(cbp->mp_map);
		cb->numBlocks = 0;
		if (!cb->l2_block_map) {
			MPFreeChunk(cbp->mp_cb, cb);
			return NULL;
		}
	}
#else
	pthread_spin_lock(&cbp->cbp_sl);
	cb = TAILQ_FIRST(&cbp->cache_buffer_free_list);
	if (!cb) goto out;
	TAILQ_REMOVE(&cbp->cache_buffer_free_list, cb, cache_buffer_link);
out :
	pthread_spin_unlock(&cbp->cbp_sl);
#endif
	return cb;
}

inline cache_buffer *
cache_buffer_l1_alloc(mtcp_manager_t mtcp) {
	return __cache_buffer_alloc(mtcp, CACHE_BUFFER_L1);
}

inline cache_buffer *
cache_buffer_l2_alloc(mtcp_manager_t mtcp) {
	return __cache_buffer_alloc(mtcp, CACHE_BUFFER_L2);
}

inline void
cache_buffer_free(mtcp_manager_t mtcp, cache_buffer *cb) {

	cache_buffer_pool *cbp = g_cbp[mtcp->ctx->cpu];
#if USE_DPDK_MEMPOOL
	if (cb->type == CACHE_BUFFER_L2)
		MPFreeChunk(cbp->mp_map, cb->l2_block_map);
	MPFreeChunk(cbp->mp_cb, cb);
#else
	pthread_spin_lock(&cbp->cbp_sl);
	TAILQ_INSERT_TAIL(&cbp->cache_buffer_free_list, cb, cache_buffer_link);
	pthread_spin_unlock(&cbp->cbp_sl);
#endif
}
