#ifndef __META_OFFLOAD_H__
#define __META_OFFLOAD_H__

#include <rte_mbuf.h>
#include <rte_hash.h>
#include "memory_mgt.h"

#define ENABLE_META_OFFLOAD_SEPARATED_CHANNEL FALSE
#define META_OFFLOAD_NUM_META_CPUS 16U
#define META_OFFLOAD_NB_MBUFS (16 * 1024)
#define META_OFFLOAD_DATAROOM_SIZE (2 * 1024)
#define META_OFFLOAD_MAX_PKT_LEN (9014)
#define META_DUMMY_CMD_PLEN 20

enum meta_offload_type {
	META_OFFLOAD_CACHE,
	META_OFFLOAD_FRD_SETUP,
	META_OFFLOAD_FRD_SEND,
	META_OFFLOAD_FRD_TEARDOWN,
#ifdef ENABLE_DUMMY_CMD
	META_OFFLOAD_DUMMY,
#endif
	META_OFFLOAD_APP_HDR,
};

typedef struct meta_offload_tx_pkt {
	struct rte_mbuf *head;
	struct rte_mbuf *tail;
	uint32_t ts;
	uint16_t nic_rxq;
	uint16_t host_txq;
	uint16_t nif;
} meta_offload_tx_pkt;

typedef struct meta_offload {
	uint16_t cpu;
#ifdef ENABLE_RTT_CHECK
	struct rte_hash *rtt_ht;
	mem_pool_t mp_ts;
#endif
	struct rte_mempool *meta_pktmbuf_pool;
	meta_offload_tx_pkt **cache;
	meta_offload_tx_pkt **frd_meta_a;
	meta_offload_tx_pkt **frd_meta_b;
	meta_offload_tx_pkt **frd_meta_c;
#ifdef ENABLE_DUMMY_CMD
	meta_offload_tx_pkt **dummy;
#endif
} meta_offload;

void
meta_offload_global_setup(void);

void
meta_offload_global_destroy(void);

meta_offload *
meta_offload_setup(uint16_t host_txq);

extern uint8_t *
meta_offload_generate_ipv4_packet(meta_offload *mo, void *cur_stream, 
		uint16_t tcplen, enum meta_offload_type meta_offload_type, uint32_t cur_ts);

extern void
meta_offload_flush(meta_offload *mo, uint32_t cur_ts);

void 
meta_offload_teardown(meta_offload *mo);

extern void
meta_offload_generate_dummy_packet(meta_offload *mo, void *cur_stream,
		void *tcph, uint16_t tcplen, uint32_t cur_ts);

#endif /* __META_OFFLOAD_H__ */
