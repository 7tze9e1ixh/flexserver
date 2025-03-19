#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_memzone.h>
#include <rte_errno.h>
#include <rte_spinlock.h>
#include <rte_branch_prediction.h> 

#include "blk.h"
#include "config.h"
#include "dataplane.h"
#include "debug.h"

static const struct rte_memzone *mz;

struct blk_pool_s {
	size_t tot_blk_sz;
	size_t blk_sz;
	size_t blk_dat_sz;
	size_t nb_blks;
	size_t nb_free_blks;
	uint8_t *addr_base;
	rte_iova_t iova_base;
	blk *free_blk;
	rte_spinlock_t sl;
};

blk_pool *
blk_setup(void)
{
	int i;
	blk_pool *bp;
	blk *walk;

	bp = calloc(1, sizeof(blk_pool));
	if (!bp) {
		rte_exit(EXIT_FAILURE, 
				"Fail to allocate memory for blk_pool, errno=%d (%s)\n", 
				errno, strerror(errno));
	}

	mz = rte_memzone_reserve("Cache Memory", (size_t)d_CONFIG.tot_cache_mem_sz, 0, RTE_MEMZONE_2MB);
	if (!mz) {
		rte_exit(EXIT_FAILURE,
				"Fail to reserve cache momory, errno=%d, (%s)\n", 
				rte_errno, rte_strerror(rte_errno));
	}

	bp->tot_blk_sz = d_CONFIG.tot_cache_mem_sz;
	bp->blk_sz = CACHE_BLOCK_SIZE + sizeof(blk_meta);
	bp->blk_dat_sz = CACHE_BLOCK_SIZE;
	bp->nb_blks = bp->tot_blk_sz / bp->blk_sz;
	bp->nb_free_blks = bp->nb_blks;

	bp->addr_base = mz->addr;
	bp->iova_base = mz->iova;
	bp->free_blk = (blk *)bp->addr_base;

	for (i = 0; i < bp->nb_blks - 1; i++) {
		walk = (blk *)(bp->addr_base + i * bp->blk_sz);
		walk->meta.b_next = (blk *)(bp->addr_base + (i + 1) * bp->blk_sz);
		walk->meta.b_iova = bp->iova_base + bp->blk_sz * i;
	}

	/* Process Last Block */
	walk = (blk *)(bp->addr_base + (bp->nb_blks - 1) * bp->blk_sz);
	walk->meta.b_next = NULL;
	walk->meta.b_iova = bp->iova_base + bp->blk_sz * (bp->nb_blks - 1);

#if 0
	printf("Block Allocator Setup Complete\n");
	printf("---------------------------------------------\n");
	printf("Total Block Size : %lu\n", bp->tot_blk_sz);
	printf("Single Block Size : %lu\n", bp->blk_sz);
	printf("Single Block Data Size : %lu\n", bp->blk_dat_sz);
	printf("Total Enable Data Size : %.2f (MB)\n", (float)bp->blk_dat_sz * bp->nb_blks / (1024 * 1024));
	printf("Number of Total Block : %lu\n", bp->nb_blks);
	printf("---------------------------------------------\n");
#endif

	rte_spinlock_init(&bp->sl);

	return bp;
}

blk *
blk_alloc(blk_pool *bp)
{
	blk *p_blk;

	rte_spinlock_lock(&bp->sl);
	if (unlikely(!bp->nb_free_blks))  {
		/* Error */
		rte_spinlock_unlock(&bp->sl);
		rte_exit(EXIT_FAILURE,
				"Fail to control memory block state at host\n");
	}

	p_blk = bp->free_blk;
	bp->free_blk = p_blk->meta.b_next;

	p_blk->meta.b_next = NULL;
	p_blk->meta.b_seq = (uint16_t)(-1);

	bp->nb_free_blks--;

	LOG_BLK("Allocate block %p, # of total blocks=%lu, # of free blocks=%lu "
			"b_seq=%u, iova=%lu, " 
			"addr_base=%p, iova_base=%lu\n",
			p_blk, bp->nb_blks, bp->nb_free_blks, 
			p_blk->meta.b_seq, (uint64_t)p_blk->meta.b_iova,
			bp->addr_base, bp->iova_base);

	rte_spinlock_unlock(&bp->sl);

	return p_blk;
}

void 
blk_free(blk_pool *bp, blk *b)
{
	rte_spinlock_lock(&bp->sl);

	LOG_BLK("Free block %p, # of total blocks=%lu, # of free blocks=%lu "
			"b_seq=%u, iova=%lu, ",
			"addr_base=%p, iova_base=%lu\n",
			b, bp->nb_blks, bp->nb_free_blks, 
			b->meta.b_seq, (uint64_t)b->meta.b_iova,
			bp->addr_base, (uint64_t)bp->iova_base);

	if (unlikely(!bp->free_blk)) {
		/* There is no free blocks in block pool(bp)
		 * Head of blk_pool points freed block */
		assert(!bp->nb_free_blks);
		b->meta.b_next = NULL;
	} else {
		b->meta.b_next = bp->free_blk;
	}
	
	bp->free_blk = b;
	bp->nb_free_blks++;

	rte_spinlock_unlock(&bp->sl);
}

void
blk_destroy(blk_pool *bp)
{
	rte_spinlock_unlock(&bp->sl);
	rte_memzone_free(mz);
	free(bp);
}

inline size_t
blk_get_dat_sz(blk_pool *bp) {
	return bp->blk_dat_sz;
}

void
blk_get_status(blk_pool *bp, size_t *nb_tots, size_t *nb_free, size_t *nb_used) {
	*nb_tots = bp->nb_blks;
	*nb_free = bp->nb_free_blks;
	*nb_used = bp->nb_blks - bp->nb_free_blks;
}
