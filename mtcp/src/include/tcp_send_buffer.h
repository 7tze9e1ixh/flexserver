#ifndef TCP_SEND_BUFFER_H
#define TCP_SEND_BUFFER_H

#include <stdlib.h>
#include <stdint.h>
#include <rte_common.h>
#include <rte_atomic.h>
#if ENABLE_NIC_CACHE
#include "meta_send_buffer.h"
#endif
//#include "frd_offload_ctrl.h"

#if USE_AIO_READ
#include <aio.h>
#include <pthread.h>
#endif

#include "file_buffer.h"
//#include "flex_buffer.h"
//#include "frd_offload_ctrl.h"

#define MAX_FILE_BUFFER_ENTRIES 8

/*----------------------------------------------------------------------------*/
typedef struct sb_manager* sb_manager_t;
typedef struct mtcp_manager* mtcp_manager_t;
/*----------------------------------------------------------------------------*/
#if USE_AIO_READ
struct SBFragment {
	uint32_t seq;
	uint32_t len;
	uint32_t start;
	uint32_t end;
	struct aiocb frag_aiocb;
	struct SBFragment *next;
};
#endif
/*----------------------------------------------------------------------------*/
struct tcp_send_buffer
{
#if !ENABLE_FLEX_BUFFER
	unsigned char *data;
	unsigned char *head;
	uint32_t head_off;
	uint32_t tail_off;
	uint32_t len;
	uint64_t cum_len;
	uint32_t size;
#endif

	uint32_t head_seq;	/* Send buffer head sequence */
	uint32_t init_seq;

#if ENABLE_NIC_CACHE
	meta_send_buffer *msb_head;
	meta_send_buffer *msb_tail;
	uint32_t total_buf_size;
#endif
	uint32_t numChunks;
	rte_atomic32_t numCompletes;

	file_buffer *fb_ptr[MAX_FILE_BUFFER_ENTRIES + 1];
	int num_fb;

	void *fts;

	void *flex_buffer_list;

	uint8_t prev_type;
#ifdef CHECK_CONTROLPLANE_ACCESS_LATENCY
	uint64_t obj_hv;
#endif
};
/*----------------------------------------------------------------------------*/
uint32_t 
SBGetCurnum(sb_manager_t sbm);
/*----------------------------------------------------------------------------*/
sb_manager_t 
SBManagerCreate(mtcp_manager_t mtcp, size_t chunk_size, uint32_t cnum);
/*----------------------------------------------------------------------------*/
struct tcp_send_buffer *
SBInit(sb_manager_t sbm, uint32_t init_seq);
/*----------------------------------------------------------------------------*/
void 
SBFree(sb_manager_t sbm, struct tcp_send_buffer *buf);
/*----------------------------------------------------------------------------*/
size_t 
SBPut(sb_manager_t sbm, struct tcp_send_buffer *buf, const void *data, size_t len);
/*----------------------------------------------------------------------------*/
#if ENABLE_NIC_CACHE

size_t 
SBRemove(sb_manager_t sbm, struct tcp_send_buffer *buf, size_t len, int cpu, int sockid);

size_t 
SBMetaPut(sb_manager_t sbm, struct tcp_send_buffer *buf, uint64_t hv, uint32_t size, 
		void *block_map, int numBlocks);

#else
size_t 
SBRemove(sb_manager_t sbm, struct tcp_send_buffer *buf, size_t len);
#endif
/*----------------------------------------------------------------------------*/
#if 0
void
SBGetHeadFlexBufferType(struct tcp_send_buffer *buf, uint16_t dport, uint32_t seq);
#endif

bool
SBIsHostPath(struct tcp_send_buffer *buf);

#endif /* TCP_SEND_BUFFER_H */
