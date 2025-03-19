#ifndef __META_SEND_BUFFER_H__
#define __META_SEND_BUFFER_H__

#include <rte_mempool.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <string.h>

typedef struct meta_send_buffer_s meta_send_buffer;
typedef struct meta_send_buffer_pool_s meta_send_buffer_pool;

struct meta_send_buffer_pool_s
{
	struct rte_mempool *msbmp;
	uint32_t nb_objs;
};

struct meta_send_buffer_s
{
	uint64_t hv;
	uint32_t size;
	uint32_t already_sent;
	uint32_t head_seq;
	meta_send_buffer *next;
	meta_send_buffer *prev;
	void **block_map;
	int numBlocks;
};

meta_send_buffer_pool *meta_send_buffer_pool_create(const size_t threshold, const int cpu);
meta_send_buffer *meta_send_buffer_get(meta_send_buffer_pool *msbp);
void meta_send_buffer_free(meta_send_buffer_pool *msbp, meta_send_buffer *msb);
void meta_send_buffer_pool_destroy(meta_send_buffer_pool *msbp);
#endif
