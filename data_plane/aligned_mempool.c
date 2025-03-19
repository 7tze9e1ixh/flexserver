#include <stdlib.h>
#include <stdio.h>
#include <sys/param.h>

#include <rte_errno.h>
#include <rte_common.h>
#include <rte_spinlock.h>

#include "aligned_mempool.h"

#define ALIGNED_MEMPOOL_ALIGNED_SIZE (2LU * 1024 * 1024)

aligned_mempool *
aligned_mempool_create(const char name[], size_t chunkSize, size_t total_memory_size) {

	aligned_mempool *amp;
	uint32_t i;

	amp = calloc(1, sizeof(aligned_mempool));
	if (!amp) {
		perror("calloc() error");
		return NULL;
	}
	//rte_spinlock_init(&amp->amp_sl);

	amp->memzone_length = RTE_ALIGN_CEIL(total_memory_size, 
			ALIGNED_MEMPOOL_ALIGNED_SIZE);
	amp->numChunks = howmany(amp->memzone_length, chunkSize);
	amp->chunkSize = chunkSize;

	amp->amPtr = calloc(amp->numChunks, sizeof(aligned_memchunk));
	if (!amp->amPtr) {
		perror("calloc() error");
		free(amp);
		return NULL;
	}

	rte_spinlock_init(&amp->amp_sl);
	SLIST_INIT(&amp->free_list);

	amp->mz = rte_memzone_reserve_aligned(name, amp->memzone_length, rte_socket_id(),
			RTE_MEMZONE_2MB, ALIGNED_MEMPOOL_ALIGNED_SIZE);
	if (!amp->mz) {
		fprintf(stderr, "rte_memzone_reserve_aligned() error, rte_errno=%d, %s\n",
				rte_errno, rte_strerror(rte_errno));
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < amp->numChunks; i++) {
		amp->amPtr[i].addr = amp->mz->addr + i * chunkSize; 
		amp->amPtr[i].iova = amp->mz->iova + i * chunkSize;
		SLIST_INSERT_HEAD(&amp->free_list, &amp->amPtr[i], am_link);
	}

	return amp;
}

void
aligned_mempool_destroy(aligned_mempool *amp) {
	rte_memzone_free(amp->mz);
	free(amp);
}

inline aligned_memchunk *
aligned_mempool_alloc_memchunk(aligned_mempool *amp)
{
	aligned_memchunk *am;

	rte_spinlock_lock(&amp->amp_sl);
	am = SLIST_FIRST(&amp->free_list);
	if (am)
		SLIST_REMOVE_HEAD(&amp->free_list, am_link);

	rte_spinlock_unlock(&amp->amp_sl);
	return am;
}

inline void
aligned_mempool_free_memchunk(aligned_mempool *amp, aligned_memchunk *am) {
	rte_spinlock_lock(&amp->amp_sl);
	SLIST_INSERT_HEAD(&amp->free_list, am, am_link);
	rte_spinlock_unlock(&amp->amp_sl);
}
