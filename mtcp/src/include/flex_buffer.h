#ifndef __FLEX_BUFFER_H__
#define __FLEX_BUFFER_H__

#include <sys/queue.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

#include "file_buffer.h"
#include "frd_offload_ctrl.h"
#include "tcp_stream.h"
#include "mtcp.h"

#if USE_DPDK_MEMPOOL
#include "memory_mgt.h"
#endif

TAILQ_HEAD(flex_buffer_head, flex_buffer);

enum flex_buffer_type {
	GENERAL_DATA_BUFFER = 0,
	L1_CACHE_BUFFER,
	L2_CACHE_BUFFER,
	FRD_OFFLOAD_BUFFER,
	FILE_BUFFER,
};

#define FLEX_BUFFER_TYPE(fb) ((fb)->type == GENERAL_DATA_BUFFER ? "GENERAL_DATA_BUFFER" : \
										 (fb)->type == L1_CACHE_BUFFER ? "L1_CACHE_BUFFER" : \
										 (fb)->type == L2_CACHE_BUFFER ? "L2_CACHE_BUFFER" : \
										 (fb)->type == FRD_OFFLOAD_BUFFER ? "FRD_OFFLOAD_BUFFER" : \
										 "FILE_BUFFER")

typedef struct flex_buffer {
	enum flex_buffer_type type;
	uint32_t head_seq;
	uint32_t already_sent;
	size_t data_len;
	void *opaque;
	TAILQ_ENTRY(flex_buffer) flex_buffer_link;
} flex_buffer;

typedef struct flex_buffer_pool {
#if USE_DPDK_MEMPOOL
	mem_pool_t mp_fbp;
#else
	TAILQ_HEAD(, flex_buffer) fbp_free_list;
	flex_buffer *fb_ptr;
	pthread_spinlock_t fbp_sl;
	uint32_t numWorkers;
#endif
} flex_buffer_pool;

void
flex_buffer_pool_create(mtcp_manager_t mtcp, uint32_t numFlexBuffers);

void
flex_buffer_pool_destroy(mtcp_manager_t mtcp);

extern int
flex_buffer_attach_without_lock(mtcp_manager_t mtcp, struct tcp_send_buffer *buf,
		enum flex_buffer_type type, void *opaque, size_t data_len, uint32_t seq);

extern int
flex_buffer_attach_with_lock(mtcp_manager_t mtcp, tcp_stream *stream,
		 enum flex_buffer_type type, void *opaque, size_t data_len);

extern void
flex_buffer_free(mtcp_manager_t mtcp, flex_buffer *fb);

extern bool
flex_buffer_is_seq_in_range(uint32_t seq, flex_buffer *fb);

extern flex_buffer *
flex_buffer_find_in_range(struct tcp_send_buffer *buf, uint32_t seq);

extern uint32_t
flex_buffer_get_remaining_length(flex_buffer *fb, uint32_t seq);

extern uint32_t
flex_buffer_get_offset(flex_buffer *fb, uint32_t seq);

#if 0
extern uint32_t
flex_buffer_remove_data(flex_buffer *fb, struct tcp_send_buffer *buf, uint32_t len, int32_t *flags);
#endif

#endif /* __FLEX_BUFFER_H__ */
