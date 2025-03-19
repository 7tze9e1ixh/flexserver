#ifndef __DPDK_IO_H__
#define __DPDK_IO_H__

#include <rte_hexdump.h>
#include <rte_ether.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_common.h>

#define RTE_TEST_RX_DESC_DEFAULT     (1024*4) // //4096
#define RTE_TEST_TX_DESC_DEFAULT     (1024*4) // //4096

#define RX_PTHRESH 8
#define RX_HTHRESH 8
#define RX_WTHRESH 4

#define TX_PTHRESH 36
#define TX_HTHRESH 0
#define TX_WTHRESH 0

#define MAX_CPUS        16
#define MAX_PKTS_BURST  (8 * 1024) //  //  4096 

#define NB_MBUFS (32 * 1024)
#define MEMPOOL_CACHE_SIZE 256
//#define JUMBO_FRAME_MAX_SIZE (9000 + sizeof(struct rte_ether_hdr))
#define JUMBO_FRAME_MAX_SIZE 9000
#define TO_NET_MTU (1500)
#define FROM_HOST_MTU (JUMBO_FRAME_MAX_SIZE - sizeof(struct rte_ether_hdr))
#define DATAROOM_SIZE (16 * 1024) // RTE_MBUF_DEFAULT_DATAROOM
#define PKTBUF_SIZE (DATAROOM_SIZE + RTE_PKTMBUF_HEADROOM)

#define MAX_NB_XSTATS_ENTRY 128

extern struct dpdk_private_context *g_dpc[];
extern struct rte_ether_addr src_addr[];
extern struct rte_ether_addr host_addr;

struct shinfo_ctx {
	uint16_t core_id;
	struct rte_mbuf_ext_shared_info shinfo;
};

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKTS_BURST];
};

struct dpdk_private_context {
	struct mbuf_table rmbufs[RTE_MAX_ETHPORTS]; // For free received packet
	struct mbuf_table wmbufs[RTE_MAX_ETHPORTS];	 // For forward TX packets
	struct rte_mempool *pktmbuf_pool;			 // pktbuf pools for thread
	struct rte_mempool *shinfo_pool;
	struct rte_mbuf *pkts_burst[MAX_PKTS_BURST]; // Pointer for RX pktbuf
#if RX_IDLE_ENABLE
	uint8_t rx_idle;
#endif
};

void dpdk_free_pkts(struct rte_mbuf **mtable, unsigned len);

void dpdk_setup(void);

void dpdk_teardown(void);

extern int32_t dpdk_recv_pkts(uint16_t core_id, uint16_t port);

extern uint8_t *dpdk_get_rptr(uint16_t core_id, uint16_t port, int index, uint16_t *len);

extern int dpdk_send_pkts(uint16_t core_id, uint16_t port);

extern struct rte_mbuf *dpdk_get_wptr(uint16_t core_id, uint16_t port, uint16_t pktsize);

void dpdk_dump_eth_stats(uint16_t portid, uint16_t coreid, uint64_t us_ts);

//void dpdk_dump_eth_xstats(uint16_t portid, uint16_t coreid, uint64_t us_ts);

void dpdk_dump_pkt(uint8_t *pktbuf, uint16_t pkt_len);

void dpdk_show_eth_stats(uint16_t port_id);

#endif
