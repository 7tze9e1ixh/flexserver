#ifndef __META_REPLY_H__
#define __META_REPLY_H__

#include <rte_mbuf.h>

typedef struct meta_reply_pkt {
	struct rte_mbuf *head;
	struct rte_mbuf *tail;
	uint64_t ts;
	uint16_t port;
	uint16_t q_id;
} meta_reply_pkt;  

typedef struct meta_reply {
	struct rte_mempool *meta_pool;
	meta_reply_pkt *pkt;
} meta_reply;

void
meta_reply_setup(uint16_t lcore_id);

extern struct rte_mbuf *
meta_reply_get_wptr(uint16_t lcore_id, uint16_t port_id, uint16_t len);

extern void
meta_reply_flush(uint16_t lcore_id, uint16_t port_id);

void
meta_reply_teardown(uint16_t lcore_id);
#endif
