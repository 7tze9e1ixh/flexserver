#ifndef __FRD_OFFLOAD_CTRL_H__
#define __FRD_OFFLOAD_CTRL_H__

#include <stdint.h>
#include <sys/queue.h>

#include "mtcp.h"
#include "tcp_stream.h"

//#define ENABLE_FRD_OFFLOAD TRUE
#define FOC_NUM_ENTRIES 2048

#define FOC_STATE_DISK_READ 0
#define FOC_STATE_ACTIVE 1
#define FOC_STATE_FREE 2
#define FOC_STATE_INACTIVE 3

#define FOC_TIMEOUT 500 // ms
#define FOC_MAX_OFFLOADS (800)//(900)
#define FOC_STATIC_THRESH TRUE

#define FOC_BUF_SIZE (256LU * 1024)
#define FOC_NUM_FREE_BUFS 10000 //4000 //9600

#define DBG_FRD_OFFLOAD_CTRL FALSE
#if DBG_FRD_OFFLOAD_CTRL
#define TRACE_FRD_OFFLOAD_CTRL(f, ...) fprintf(stderr, "(%10s:%4d) " f, \
		__func__, __LINE__, ##__VA_ARGS__)
#else
#define TRACE_FRD_OFFLOAD_CTRL(f, ...) (void)0
#endif

#define FOC_LOG_FRD_OFFLOAD FALSE

struct frd_offload_hdr {
	uint32_t toSend;
	uint64_t offset;
	uint32_t id;
	uint16_t path_len;
	char path[];
};

struct foc_tx_state {
	uint32_t id;

#if !ENABLE_FLEX_BUFFER
	uint64_t size;
	uint64_t already_sent;
	uint32_t head_seq;
#endif
	mtcp_manager_t mtcp;
	tcp_stream *stream;

	uint32_t ts_sent;
	uint32_t hv;
	uint8_t state;
	ssize_t file_length;
	char path_name[256];
	TAILQ_ENTRY(foc_tx_state) foc_ht_link;
	TAILQ_ENTRY(foc_tx_state) foc_wait_link;
//	TAILQ_ENTRY(foc_tx_state) foc_tx_state_link;
};

typedef struct frd_offload_control {

	_Atomic uint32_t numOffloads;
	uint32_t thresh;
	TAILQ_HEAD(, foc_tx_state) *fts_entry;
	//TAILQ_HEAD(, tcp_stream) *entry;
	uint32_t numEntries;
	uint32_t mask;
	uint32_t numWaits;
	_Atomic int16_t num_free_bufs;

	pthread_spinlock_t foc_sl;

	struct foc_tx_state *foc_tx_state_ptr;
	uint32_t offload_list_len;
	TAILQ_HEAD(, foc_tx_state) foc_tx_state_offload_list;
	TAILQ_HEAD(, foc_tx_state) foc_tx_state_free_list;
	TAILQ_HEAD(, foc_tx_state) foc_tx_state_wait_list;

} frd_offload_control;

void
foc_setup(mtcp_manager_t mtcp, uint32_t maxOffloads);

void
foc_destroy(mtcp_manager_t mtcp);

int
foc_setup_offload(mtcp_manager_t mtcp, char *path, size_t file_length,
		tcp_stream *stream, uint32_t cur_ts);

void
foc_teardown_offload(struct foc_tx_state *fts, uint32_t cur_ts);

void
foc_transmit(mtcp_manager_t mtcp, uint32_t cur_ts);

int
foc_proc_reply(mtcp_manager_t mtcp, void *in_iph, uint32_t cur_ts, int len);

#endif
