#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "flex_buffer.h"
#include "flex_debug.h"
#include "frd_offload_ctrl.h"
//#include "util.h"
#include "file_buffer.h"
#include "general_data_buffer.h"
#include "tcp_send_buffer.h"
#include "debug.h"
#include "nic_cache.h"
#include "cache_buffer.h"
#include "frd_rate_limit.h"

flex_buffer_pool *g_fbp[MAX_CPUS] = {NULL};

void
flex_buffer_pool_create(mtcp_manager_t mtcp, uint32_t numFlexBuffers) {

	flex_buffer_pool *fbp;

	fbp = calloc(1, sizeof(flex_buffer_pool));
	if (!fbp) goto err_calloc;

#if USE_DPDK_MEMPOOL
	char tmpbuf[256];
	sprintf(tmpbuf, "flex_buffer_pool-%d", mtcp->ctx->cpu);
	fbp->mp_fbp = MPCreate(tmpbuf, sizeof(flex_buffer), (uint64_t)numFlexBuffers * sizeof(flex_buffer));
	if (!fbp->mp_fbp) {
		TRACE_ERROR("MPCreate()\n");
		exit(EXIT_FAILURE);
	}
#else
	int i;
	TAILQ_INIT(&fbp->fbp_free_list);
	fbp->fb_ptr = calloc(numFlexBuffers, sizeof(flex_buffer_pool));
	if (!fbp->fb_ptr) goto err_calloc;

	for (i = 0; i < numFlexBuffers; i++) 
		TAILQ_INSERT_TAIL(&fbp->fbp_free_list, &fbp->fb_ptr[i], flex_buffer_link);
	pthread_spin_init(&fbp->fbp_sl, PTHREAD_PROCESS_PRIVATE);
#endif

	g_fbp[mtcp->ctx->cpu] = fbp;

	return;

err_calloc :
	perror("calloc()");
	exit(EXIT_FAILURE);
}

void
flex_buffer_pool_destroy(mtcp_manager_t mtcp) {

	flex_buffer_pool *fbp;
	fbp = g_fbp[mtcp->ctx->cpu];
#if USE_DPDK_MEMPOOL
	MPDestroy(fbp->mp_fbp);
#else
	free(fbp->fb_ptr);
#endif
	free(fbp);
}

static inline int
__flex_buffer_attach(mtcp_manager_t mtcp, tcp_stream *stream, struct tcp_send_buffer *buf,
		enum flex_buffer_type type, void *opaque, size_t data_len, uint32_t seq) {

	flex_buffer_pool *fbp;
	flex_buffer *fb;
	TAILQ_HEAD(, flex_buffer) *flex_buffer_list;

	fbp = g_fbp[mtcp->ctx->cpu];
#if USE_DPDK_MEMPOOL
	fb = MPAllocateChunk(fbp->mp_fbp);
	if (!fb) {
		TRACE_ERROR("Fail to allocate flex_buffer\n");
		return -1;
	}
#else
	pthread_spin_lock(&fbp->fbp_sl);
	fb = TAILQ_FIRST(&fbp->fbp_free_list);
	TAILQ_REMOVE(&fbp->fbp_free_list, fb, flex_buffer_link);
	pthread_spin_unlock(&fbp->fbp_sl);
#endif

	fb->data_len = data_len;
	fb->type = type;
	fb->opaque = opaque;
	fb->already_sent = 0;

	if (stream)	
		buf = stream->sndvar->sndbuf;

	if (!buf)
		return -1;

	flex_buffer_list = buf->flex_buffer_list;

	if (stream) {
		SBUF_LOCK(&stream->sndvar->write_lock);
		fb->head_seq = buf->head_seq + buf->total_buf_size;
		TAILQ_INSERT_TAIL(flex_buffer_list, fb, flex_buffer_link);
		SBUF_UNLOCK(&stream->sndvar->write_lock);
	} else {
		fb->head_seq = seq;
		TAILQ_INSERT_TAIL(flex_buffer_list, fb, flex_buffer_link);
	}

	return 0;
}

inline int
flex_buffer_attach_without_lock(mtcp_manager_t mtcp, struct tcp_send_buffer *buf,
		enum flex_buffer_type type, void *opaque, size_t data_len, uint32_t seq) 
{
	return __flex_buffer_attach(mtcp, NULL, buf, type, opaque, data_len, seq);
}

inline int
flex_buffer_attach_with_lock(mtcp_manager_t mtcp, tcp_stream *stream, 
		enum flex_buffer_type type, void *opaque, size_t data_len)
{
	return __flex_buffer_attach(mtcp, stream, NULL, type, opaque, data_len, 0);
}

inline static void
__clear_opqaue(mtcp_manager_t mtcp, flex_buffer *fb) {

	cache_buffer *cb;

	switch(fb->type) {
		case GENERAL_DATA_BUFFER :
			general_data_buffer_free(mtcp, (general_data_buffer *)fb->opaque);
			break;
		case L1_CACHE_BUFFER :
		case L2_CACHE_BUFFER :
			cb = (cache_buffer *)fb->opaque;
			nic_cache_free_obj_by_hv(mtcp->ctx->cpu, 0, cb->hv);
			cache_buffer_free(mtcp, cb);
			break;
		case FRD_OFFLOAD_BUFFER :
			foc_teardown_offload((struct foc_tx_state *)fb->opaque, mtcp->cur_ts);
			break;
		case FILE_BUFFER :
			fb_clean_up((file_buffer *)fb->opaque);
			break;
	}
}

inline void
flex_buffer_free(mtcp_manager_t mtcp, flex_buffer *fb) {

	flex_buffer_pool *fbp = g_fbp[mtcp->ctx->cpu];

	__clear_opqaue(mtcp, fb);

#if USE_DPDK_MEMPOOL
	MPFreeChunk(fbp->mp_fbp, fb);
#else
	pthread_spin_lock(&fbp->fbp_sl);
	TAILQ_INSERT_TAIL(&fbp->fbp_free_list, fb, flex_buffer_link);
	pthread_spin_unlock(&fbp->fbp_sl);
#endif
}

inline bool
flex_buffer_is_seq_in_range(uint32_t seq, flex_buffer *fb) {

	uint32_t next_fb_seq;
	next_fb_seq = fb->head_seq + fb->data_len;

	if (fb->head_seq > seq) {  
		/* Wrapped around occurs 
		 * fb->head_seq --- 0xffffffff --- seq */
		if (fb->head_seq < next_fb_seq) {
			/* fb->head_seq --- fb->head_seq + fb->data_len ---- 0xffffffff --- seq   */
			return false;
		} else {
			/* fb->head_seq --- 0xffffffff --- fb->head_seq + fb->data_len  */
			return seq < next_fb_seq ? true : false;
		}
	}
	/* fb->head_seq <= seq */

	if (fb->head_seq > next_fb_seq) {
		/* Wrapped around occurs 
		 * fb->head_seq <= seq <= 0xffffffff && 0 <= fb->head_seq + fb->data_len
		 * */
		return true;
	}

	if (seq >= fb->head_seq && seq < next_fb_seq) {
		/* fb->head_seq <= seq < fb->head_seq + fb->data_len */
		return true;
	}

	/* fb->head_seq < fb->head_seq + fb->data_len <= seq */
	return false;
}

inline flex_buffer *
flex_buffer_find_in_range(struct tcp_send_buffer *buf, uint32_t seq) {

	flex_buffer *fb = NULL;
	TAILQ_HEAD(, flex_buffer) *flex_buffer_list = buf->flex_buffer_list;

	TAILQ_FOREACH(fb, flex_buffer_list, flex_buffer_link) {
		if (flex_buffer_is_seq_in_range(seq, fb))
			break;
	}

	TRACE_SND("%6s seq:%u\n", FLEX_BUFFER_TYPE(fb), seq);

	return fb;
}

inline uint32_t
flex_buffer_get_remaining_length(flex_buffer *fb, uint32_t seq) {
	// This handles the wrapped-around case when seq < fb->head_seq
	return fb->data_len - (seq - fb->head_seq) & UINT32_MAX;

	/*uint32_t length;
	if (seq >= fb->head_seq) 
		length = fb->data_len - (seq - fb->head_seq);
	else 
		length = fb->data_len - get_wrapped_around_sequence_offset(fb->head_seq, seq);

	return length;*/
}

inline uint32_t
flex_buffer_get_offset(flex_buffer *fb, uint32_t seq) {
	// This handles the wrapped-around case when seq < fb->head_seq
	return (seq - fb->head_seq) & UINT32_MAX;
	
	/*uint32_t offset;
	if (seq >= fb->head_seq) 
		offset = seq - fb->head_seq;
	else 
		offset = get_wrapped_around_sequence_offset(fb->head_seq, seq);

	return offset;*/
}
