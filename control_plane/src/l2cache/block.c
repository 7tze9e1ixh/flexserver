#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <rte_errno.h>

#include "block.h"
#include "debug.h"
#include "core.h"

block_pool *
block_create_pool(uint16_t core_index, size_t max_mem_size) {

	block_pool *bp;
	char tempbuf[256];
	size_t sz, numTotBlocks;

	bp = calloc(1, sizeof(block_pool));
	if (!bp) {
		perror("Fail to allocate memory for block_pool");
		return NULL;
	}

	sz = RTE_ALIGN_CEIL(sizeof(block_meta) + CONTROL_PLANE_BLOCK_SIZE, RTE_CACHE_LINE_SIZE);
	//printf( "max_mem_size : %d sz : %d\n", max_mem_size, sz ); // 
	numTotBlocks = max_mem_size / sz;
	sprintf(tempbuf, "block_pool%u", core_index);

	if (numTotBlocks == 0)
		goto disable_l2cache;

	bp->mp_block = rte_mempool_create(tempbuf, numTotBlocks, sz, 0, 0, NULL,
			0, NULL, 0, rte_socket_id(), MEMPOOL_F_NO_SPREAD);
	if (!bp->mp_block) {
		LOG_ERROR("Fail to create memory pool for control plane block "
				"rte_errno=%d (%s)\n",
				rte_errno, rte_strerror(rte_errno));
		return NULL;
	}
disable_l2cache :
	bp->core_index = core_index;
	bp->numFree = numTotBlocks;
	bp->numUsed = 0;
	bp->numTotBlocks = numTotBlocks;
	bp->blockSize = CONTROL_PLANE_BLOCK_SIZE;

	return bp;
}

block *
block_alloc(block_pool *bp) {

	int ret;
	void *obj_p;

	ret = rte_mempool_get(bp->mp_block, (void **)&obj_p);
	if (ret != 0) {
		LOG_ERROR("Not enough block for control plane\n");
		return NULL;
	}

	bp->numUsed++;
	bp->numFree--;

	DBG_TRACE("numTotBlocks : %lu, numUsed : %lu, numFree : %lu\n", 
			bp->numTotBlocks, bp->numUsed, bp->numFree);

	return obj_p;
}

void
block_free(block_pool *bp, block *b) {
	rte_mempool_put(bp->mp_block, b);
	bp->numUsed--;
	bp->numFree++;

	DBG_TRACE("numTotBlocks : %lu, numUsed : %lu, numFree : %lu\n", 
			bp->numTotBlocks, bp->numUsed, bp->numFree);
}

void
block_pool_destroy(block_pool *bp) {
	/* TODO */
}
