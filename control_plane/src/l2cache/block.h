#ifndef __BLOCK_H__
#define __BLOCK_H__

#include <rte_common.h>
#include <rte_mempool.h>
#include <stdint.h>

typedef struct block_pool block_pool;
typedef struct block_meta block_meta;
typedef struct block block;

struct block_pool {
	uint16_t core_index;
	size_t numFree;
	size_t numUsed;
	size_t numTotBlocks;
	size_t blockSize;
	struct rte_mempool *mp_block;
};

struct block_meta {
	uint16_t seq;
	block *next;
} __rte_packed;

struct block {
	block_meta meta;
	unsigned char data[];
};

block_pool *block_create_pool(uint16_t core_index, size_t max_mem_size);
block *block_alloc(block_pool *bp);
void block_free(block_pool *bp, block *b);
void block_pool_destroy(block_pool *bp);
#endif
