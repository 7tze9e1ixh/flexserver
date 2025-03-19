#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>

#include "debug.h"
#include "memory_mgt.h"
/*----------------------------------------------------------------------------*/
mem_pool_t
MPCreate(char *name, int chunk_size, size_t total_size)
{
	struct rte_mempool *mp;
	size_t sz, items;
	
	items = total_size / chunk_size;
	sz = RTE_ALIGN_CEIL(chunk_size, RTE_CACHE_LINE_SIZE);
	mp = rte_mempool_create(name, items, sz, 0, 0, NULL,
				0, NULL, 0, rte_socket_id(),
				MEMPOOL_F_NO_SPREAD);

	if (mp == NULL) {
		log_error("Can't allocate memory for mempool!, rte_errno=%d (%s)\n",
				rte_errno, rte_strerror(rte_errno));
		exit(EXIT_FAILURE);
	}

	return mp;
}
/*----------------------------------------------------------------------------*/
void *
MPAllocateChunk(mem_pool_t mp)
{
	int rc;
	void *buf;

	rc = rte_mempool_get(mp, (void **)&buf);

	if (rc != 0)
		return NULL;

	return buf;
}
/*----------------------------------------------------------------------------*/
void
MPFreeChunk(mem_pool_t mp, void *p)
{
	rte_mempool_put(mp, p);
}
/*----------------------------------------------------------------------------*/
void
MPDestroy(mem_pool_t mp)
{
#if RTE_VERSION < RTE_VERSION_NUM(16, 7, 0, 0)
	/* do nothing.. old versions don't have a method to reclaim back mem */
#else
	rte_mempool_free(mp);
#endif
}
/*----------------------------------------------------------------------------*/
int
MPGetFreeChunks(mem_pool_t mp)
{
#if RTE_VERSION <= RTE_VERSION_NUM(16, 7, 0, 0)
	return (int)rte_mempool_free_count(mp);
#else
	return (int)rte_mempool_avail_count(mp);
#endif
}
/*----------------------------------------------------------------------------*/
