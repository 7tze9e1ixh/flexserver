#ifndef __FILE_BUFFER_H__
#define __FILE_BUFFER_H__

#include "aligned_mempool.h"
#include "memory_mgt.h"

#define MAX_ALIGNED_MEMCHUNKS 64
#define FILE_BUFFER_SIZE (unsigned long)(2 * 1024 * 1024)
#define MAX_FILE_BUFFERS (unsigned long)1500 //5000 

typedef struct file_buffer file_buffer;
typedef struct file_buffer_pool file_buffer_pool;

struct file_buffer {
	aligned_memchunk *am[MAX_ALIGNED_MEMCHUNKS];
	uint16_t numChunks;
	file_buffer_pool *fbp;
};

struct file_buffer_pool {
	aligned_mempool *amp;
	mem_pool_t mp;
};

file_buffer_pool *
fb_pool_create(uint16_t cid, uint16_t wid, uint32_t max_fb);

void
fb_pool_destroy(file_buffer_pool *fbp);

file_buffer *
fb_alloc(file_buffer_pool *fbp, size_t size);

void
fb_clean_up(file_buffer *fb);

#endif /* __FILE_BUFFER_H__ */
