#include <stdlib.h>
#include <stdio.h>
#include <sys/param.h>

#include <rte_lcore.h>

#include "debug.h"
#include "fb.h"

struct fb_pool *
fb_pool_create(uint32_t max_fb) {

	char pool_name[RTE_MEMZONE_NAMESIZE];
	struct fb_pool *fbp;

	fbp = calloc(1, sizeof(struct fb_pool));
	if (!fbp) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	sprintf(pool_name, "fbp-amp-%u", rte_lcore_id());
	fbp->amp = aligned_mempool_create(pool_name, FB_SIZE, FB_SIZE * max_fb);
	if (!fbp->amp) {
		log_error("aligned_mempool_create()\n");
		exit(EXIT_FAILURE);
	}

	sprintf(pool_name, "fbp-uamp-%u", rte_lcore_id());
	fbp->mp = MPCreate(pool_name, sizeof(struct fb), sizeof(struct fb) * max_fb);
	if (!fbp->mp) {
		log_error("MPCreate() error\n");
		exit(EXIT_FAILURE);
	}

	return fbp;
}

void
fb_pool_destroy(struct fb_pool *fbp) {
	/* TODO */
}

struct fb *
fb_alloc(struct fb_pool *fbp, size_t sz) {

	struct fb *b;
	uint16_t i;

	b = MPAllocateChunk(fbp->mp);
	if (!b) {
		log_error("Increase # of chunks\n");
		exit(EXIT_FAILURE);
	}

	b->numChunks = howmany(sz, fbp->amp->chunkSize);
	for (i = 0; i < b->numChunks; i++) {
		b->am[i] = aligned_mempool_alloc_memchunk(fbp->amp);
		if (!b->am[i]) {
			log_error("Increase # of chunks\n");
			exit(EXIT_FAILURE);
		}
	}

	return b;
}

void
fb_free(struct fb_pool *fbp, struct fb *b) {

	uint16_t i;

	for (i = 0; i < b->numChunks; i++)
		aligned_mempool_free_memchunk(fbp->amp, b->am[i]);
	MPFreeChunk(fbp->mp, b);
}
