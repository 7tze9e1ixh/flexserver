#ifndef __ALIGNED_MEMPOOL_H__
#define __ALIGNED_MEMPOOL_H__

#include <pthread.h>
#include <sys/queue.h>
#include <stdbool.h>
#include <stdint.h>

#include <rte_memzone.h>

typedef struct aligned_memchunk {
	rte_iova_t iova;
	void *addr;
	SLIST_ENTRY(aligned_memchunk) am_link;
} aligned_memchunk;

typedef struct aligned_mempool {
	uint32_t numChunks;
	size_t chunkSize;
	size_t memzone_length;
	rte_spinlock_t amp_sl;
	aligned_memchunk *amPtr;
	const struct rte_memzone *mz;
	SLIST_HEAD(, aligned_memchunk) free_list;
} aligned_mempool;

aligned_mempool *
aligned_mempool_create(const char name[], size_t chunkSize, size_t total_memory_size);

void
aligned_mempool_destroy(aligned_mempool *amp);

extern aligned_memchunk *
aligned_mempool_alloc_memchunk(aligned_mempool *amp);

extern void
aligned_mempool_free_memchunk(aligned_mempool *amp, aligned_memchunk *am);

#endif /* __ALIGNED_MEMPOOL_H__ */
