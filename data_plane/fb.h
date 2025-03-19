#include "aligned_mempool.h"
#include "memory_mgt.h"

#define FB_MAX_ALIGNED_MEMCHUNKS 64
#define FB_SIZE (256LU * 1024)

struct fb_pool {
	aligned_mempool *amp;
	mem_pool_t mp;
};

struct fb {
	aligned_memchunk *am[FB_MAX_ALIGNED_MEMCHUNKS];
	uint16_t numChunks;
};

struct fb_pool *
fb_pool_create(uint32_t max_fb);

void
fb_pool_destroy(struct fb_pool *fbp);

struct fb *
fb_alloc(struct fb_pool *fbp, size_t sz);

void
fb_free(struct fb_pool *fbp, struct fb *b);
