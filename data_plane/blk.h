#ifndef __BLK_H__
#define __BLK_H__

#include <stdint.h>
#include <rte_common.h>

typedef struct blk_pool_s blk_pool;
typedef struct blk_s blk;
typedef struct blk_meta_s blk_meta;

struct blk_meta_s {
	blk *b_next;
	uint16_t b_seq;
	rte_iova_t b_iova;
} __rte_packed;

struct blk_s {
	blk_meta meta;
	uint8_t data[];
};

blk_pool *blk_setup(void);
blk *blk_alloc(blk_pool *bp);
void blk_free(blk_pool *bp, blk *b);
void blk_destroy(blk_pool *bp);
size_t blk_get_dat_sz(blk_pool *bp);
void blk_get_status(blk_pool *bp, size_t *nb_tots, size_t *nb_free, size_t *nb_used);
#endif
