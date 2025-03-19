#include <stdio.h>
#include <stdlib.h>
#include "file_buffer.h"
#include "debug.h"
#include "util.h"

file_buffer_pool *
fb_pool_create(uint16_t cid, uint16_t wid, uint32_t max_fb) {

	char pool_name[RTE_MEMZONE_NAMESIZE];
	file_buffer_pool *fbp;

	fbp = calloc(1, sizeof(file_buffer_pool));
	if (!fbp) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	sprintf(pool_name, "fbp-mc-%u-%u", cid, wid);

	fbp->amp = aligned_mempool_create(pool_name, FILE_BUFFER_SIZE, 
			FILE_BUFFER_SIZE * max_fb);
	if (!fbp->amp) {
		TRACE_ERROR("aligned_mempool_create()\n");
		exit(EXIT_FAILURE);
	}

	sprintf(pool_name, "fbp-fb-%u-%u", cid, wid);
	fbp->mp = MPCreate(pool_name, sizeof(file_buffer), sizeof(file_buffer) * max_fb);
	if (!fbp->mp) {
		TRACE_ERROR("MPCreate() error\n");
		exit(EXIT_FAILURE);
	}

	return fbp;
}

void 
fb_pool_destroy(file_buffer_pool *fbp) {
	/* TODO */
}

file_buffer *
fb_alloc(file_buffer_pool *fbp, size_t size) {

	file_buffer *fb;
	uint16_t i;

	fb = MPAllocateChunk(fbp->mp);
	if (!fb) {
		TRACE_ERROR("Increase # of chunks\n");
		exit(EXIT_FAILURE);
	}

	fb->numChunks = get_howmany(size, fbp->amp->chunkSize);
	fb->fbp = fbp;

	for (i = 0; i < fb->numChunks; i++) {
		fb->am[i] = aligned_mempool_alloc_memchunk(fbp->amp);
		if (!fb->am[i]) {
			TRACE_ERROR("Increase # of chunks\n");
			exit(EXIT_FAILURE);
		}
	}

	return fb;
}

void
fb_clean_up(file_buffer *fb) {
	uint16_t i;
	file_buffer_pool *fbp = fb->fbp;
	for (i = 0; i < fb->numChunks; i++)
		aligned_mempool_free_memchunk(fbp->amp, fb->am[i]);
	MPFreeChunk(fbp->mp, fb);
}
