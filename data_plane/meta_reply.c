#include <stdlib.h>

#include "meta_reply.h"
#include "dataplane.h"
#include "debug.h"
#include "dpdk_io.h"

#define META_REPLY_NB_MBUFS (16 * 1024) //
#define META_REPLY_NB_SEGS_THRESH 50
#define META_REPLY_TIMEOUT 20

static meta_reply *g_meta_reply[MAX_CPUS] = {NULL};

void
meta_reply_setup(uint16_t lcore_id) {

	meta_reply *mr;
	char pool_name[RTE_MEMZONE_NAMESIZE];
	uint16_t numPorts;
	int port;

	mr = calloc(1, sizeof(meta_reply));
	if (!mr) {
		log_error("calloc()\n");
		exit(EXIT_FAILURE);
	}

	sprintf(pool_name, "meta_pool%u", lcore_id);
	mr->meta_pool = rte_pktmbuf_pool_create(pool_name, META_REPLY_NB_MBUFS, 256, 0,
			2048 + RTE_PKTMBUF_HEADROOM, rte_socket_id());
	if (!mr->meta_pool) {
		log_error("rte_pktmbuf_pool_create fail\n");
		exit(EXIT_FAILURE);
	}

	numPorts = rte_eth_dev_count_avail();

	mr->pkt = calloc(numPorts, sizeof(meta_reply_pkt));
	if (!mr->pkt) {
		log_error("calloc()\n");
		exit(EXIT_FAILURE);
	}

	for (port = 0; port < numPorts; port++) {
		mr->pkt[port].ts = GetCurUs();
		mr->pkt[port].port = port;
		mr->pkt[port].q_id = lcore_id;
	}

	g_meta_reply[lcore_id] = mr;
}

inline static void
__meta_reply_flush(meta_reply_pkt *pkt, uint64_t cur_ts) {

	int ret;

	if (!pkt->head && !pkt->tail) 
		return;

	do {
		ret = rte_eth_tx_burst(pkt->port, pkt->q_id, &pkt->head, 1);
	} while (ret != 1);

#if SHOW_STATISTICS && ENABLE_REPLY_BATCH
	g_stat[pkt->q_id].numReply++;
#endif
	pkt->ts = cur_ts;
	pkt->head = NULL;
	pkt->tail = NULL;
}

inline struct rte_mbuf *
meta_reply_get_wptr(uint16_t lcore_id, uint16_t port_id, uint16_t len) {

	meta_reply *mr;
	struct rte_mbuf *m;
	struct meta_reply_pkt *pkt;
	uint64_t ts = GetCurUs();

	mr = g_meta_reply[lcore_id];
	pkt = &mr->pkt[port_id];

	if (pkt->head && pkt->tail &&
			((pkt->head->data_len + len > JUMBO_FRAME_MAX_SIZE + RTE_ETHER_HDR_LEN) ||
			 (pkt->head->nb_segs >= META_REPLY_NB_SEGS_THRESH))) {
		__meta_reply_flush(pkt, ts);
	}

	m = rte_pktmbuf_alloc(mr->meta_pool);
	if (!m) {
		log_error("Increase chunk number of rte_mbuf\n");
		exit(EXIT_FAILURE);
	}

	m->pkt_len = 0;
	m->data_len = len;
	m->nb_segs = 1;
	m->next = NULL;

	if (!pkt->head && !pkt->tail) {
		pkt->head = m;
		pkt->tail = m;
		pkt->head->pkt_len = len;
	} else {
		pkt->head->pkt_len += len;
		pkt->head->nb_segs++;
		pkt->tail->next = m;
		pkt->tail = m;
	}

#if SHOW_STATISTICS && ENABLE_REPLY_BATCH
	g_stat[lcore_id].numReplyHdr++;
#endif

	return m;
}

inline void
meta_reply_flush(uint16_t lcore_id, uint16_t port_id) {

	meta_reply *mr = g_meta_reply[lcore_id];
	meta_reply_pkt *pkt = &mr->pkt[port_id];
	uint64_t ts = GetCurUs();

	if (pkt->head && pkt->tail && 
			((pkt->head->nb_segs >= META_REPLY_NB_SEGS_THRESH) ||
			 (USEC_TO_MSEC(ts - pkt->ts) >= META_REPLY_TIMEOUT)))
		__meta_reply_flush(pkt, ts);
}

void
meta_reply_teardown(uint16_t lcore_id) {

}
