#include <stdlib.h>
#include <string.h>

#include <rte_lcore.h>
#include <rte_errno.h>
#include <rte_ethdev.h>

#include "dpdk_io.h"
#include "debug.h"
#include "config.h"

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
	.rx_free_thresh = 32,
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0,
	.tx_rs_thresh = 0,
};

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP | 
				RTE_ETH_RSS_IP | RTE_ETH_RSS_L2_PAYLOAD |
				RTE_ETH_RSS_ETH,
		},
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
        .offloads = (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
				RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
                RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
                RTE_ETH_TX_OFFLOAD_TCP_TSO)
	},
};

struct rte_mempool *pktmbuf_pool[MAX_CPUS];
struct rte_mempool *shinfo_pool[MAX_CPUS];
struct dpdk_private_context *g_dpc[MAX_CPUS];
struct rte_ether_addr src_addr[RTE_MAX_ETHPORTS];
struct rte_eth_link g_link_state[RTE_MAX_ETHPORTS];
struct rte_ether_addr host_addr; /* Host interface mac address */

#if DEBUG_ETH_STATS
static uint64_t us_prev_dump_eth_stats;
#endif

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/*
static uint8_t key[] = {
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
};
*/
// 
static uint8_t key[] = {
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

static struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];

static void PrintRXQInfo(uint16_t portid, uint16_t rxq_id);
static void PrintTXQInfo(uint16_t portid, uint16_t txq_id);

inline static void
PrintRXQInfo(uint16_t portid, uint16_t rxq_id) {
	int ret;
	struct rte_eth_rxq_info rxq_info;

	ret = rte_eth_rx_queue_info_get(portid, rxq_id, &rxq_info);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
				"Fail to get rx_queue information "
				"errno=%d (%s)\n", ret, rte_strerror(ret));
	}
	fprintf(stderr, "-----------------------------------------------\n");
	fprintf(stderr, "RX QUEUE INFORMATION\n");
	fprintf(stderr, "scattered_rx = %s\n", IS_TRUE(rxq_info.scattered_rx));
	fprintf(stderr, "nb_desc = %u\n", rxq_info.nb_desc);
	fprintf(stderr, "rx_buf_size = %u\n", rxq_info.rx_buf_size);
	fprintf(stderr, "rx_drop_en = %s\n", IS_TRUE(rxq_info.conf.rx_drop_en));
	fprintf(stderr, "-----------------------------------------------\n");
}

inline static void
PrintTXQInfo(uint16_t portid, uint16_t txq_id){

}

void
dpdk_dump_eth_stats(uint16_t portid, uint16_t coreid, uint64_t us_ts) {
#if DEBUG_ETH_STATS
	if (coreid != 0)
		return;
	if (USEC_TO_SEC(us_ts) - USEC_TO_SEC(us_prev_dump_eth_stats) >= 1) {
		struct rte_eth_stats e_stats;
		us_prev_dump_eth_stats = us_ts;
		rte_eth_stats_get(portid, &e_stats);
		g_stats.ipackets += e_stats.ipackets;
		g_stats.opackets += e_stats.opackets;
		g_stats.ibytes += e_stats.ibytes;
		g_stats.obytes += e_stats.obytes;
		g_stats.imissed += e_stats.imissed;
		g_stats.ierrors += e_stats.ierrors;
		g_stats.oerrors += e_stats.oerrors;
		g_stats.rx_nombuf += e_stats.rx_nombuf;
		rte_eth_stats_reset(portid);
	}
#endif
}

void __attribute__((unused))
dpdk_show_eth_stats(uint16_t port_id) {

	struct rte_eth_stats eth_stats;
	rte_eth_stats_get(port_id, &eth_stats);
	printf("imissed:%lu, ierrors:%lu, oerrors:%lu, rx_nombuf:%lu\n",
			eth_stats.imissed, eth_stats.ierrors, eth_stats.oerrors, eth_stats.rx_nombuf);
	rte_eth_stats_reset(port_id);
}

void 
dpdk_setup(void)
{
	int nb_ports, num_core, lcore_id, ret;
	uint16_t portid;
	struct rte_eth_fc_conf fc_conf;
	char if_name[RTE_ETH_NAME_MAX_LEN];

	ret = rte_eal_init(d_CONFIG.dpdk_argc, d_CONFIG.dpdk_argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Fail to initialize EAL\n");
	
	num_core = rte_lcore_count();
	if (num_core <= 0) {
		rte_exit(EXIT_FAILURE, "Zero or negative number of core activated\n");
	}

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports <= 0) {
		rte_exit(EXIT_FAILURE, "Zero or negative number of ports activated\n");
	}

	port_conf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)key;
	port_conf.rx_adv_conf.rss_conf.rss_key_len = sizeof(key);

	for (lcore_id = 0; lcore_id < num_core; lcore_id++)
	{
		char name[RTE_MEMPOOL_NAMESIZE];
		sprintf(name, "mbuf_pool-%d", lcore_id);
		pktmbuf_pool[lcore_id] = rte_pktmbuf_pool_create(name, NB_MBUFS * nb_ports,
				MEMPOOL_CACHE_SIZE, 0, PKTBUF_SIZE, rte_socket_id());

		if (pktmbuf_pool[lcore_id] == NULL) {
			rte_exit(EXIT_FAILURE,
					"Cannot init mbuf pool, rte_errno=%d (%s)\n",
					rte_errno, rte_strerror(rte_errno));
		}

		sprintf(name, "shinfo_pool-%d", lcore_id);
		shinfo_pool[lcore_id] = rte_mempool_create(name, NB_MBUFS * nb_ports,
					sizeof(struct shinfo_ctx), 0, 0, NULL, NULL, NULL, NULL,
					rte_socket_id(), 0);

		if (shinfo_pool[lcore_id] == NULL) {
			rte_exit(EXIT_FAILURE,
					"Cannot init shinfo pool, rte_errno=%d, (%s)\n",
					rte_errno, rte_strerror(rte_errno));
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		uint16_t mtu; 
		
		ret = rte_eth_dev_get_name_by_port(portid, if_name);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"Fail to get dev name by port %u, rte_errno=%d (%s)\n",
					portid, ret, rte_strerror(ret));
		}

		log_info("Start to initialize port %u (%s) \n", portid, if_name);

		ret = rte_eth_macaddr_get(portid, &src_addr[portid]);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"Cannot get mac address from port %d (%s), rte_errno=%d (%s)\n",
					portid, if_name, ret, rte_strerror(ret));
		}
		
		ret = rte_eth_dev_info_get(portid, &dev_info[portid]);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"Cannot get dev_info from port %u (%s), rte_errno=%d (%s)\n", 
					portid, if_name, ret, rte_strerror(ret));
		}

		port_conf.rx_adv_conf.rss_conf.rss_hf &=
			dev_info[portid].flow_type_rss_offloads;
		
		ret = rte_eth_dev_configure(portid, num_core, num_core, &port_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"Cannot configure device : rte_errno=%d (%s), port=%u, cores=%u\n",
					ret, rte_strerror(ret), portid, num_core);
		}
#if 1
		mtu = JUMBO_FRAME_MAX_SIZE;
		ret = rte_eth_dev_set_mtu(portid, mtu);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"Fail to set mtu\n");
		}
#endif

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"Fail to reconfigure rxd and txd "
					"rte_errno=%d (%s), port=%u, cores=%u\n",
					rte_errno, rte_strerror(rte_errno), portid, lcore_id);
		}

		for (lcore_id = 0; lcore_id < num_core; lcore_id++) {
			ret = rte_eth_rx_queue_setup(portid, lcore_id, nb_rxd, 
					rte_eth_dev_socket_id(portid), &rx_conf, pktmbuf_pool[lcore_id]);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE,
						"rte_eth_rx_queue_setup fails "
						"rte_errno=%d (%s), port=%u, q_id=%d\n",
						ret, rte_strerror(ret), portid, lcore_id);
			}
		}

		for (lcore_id = 0; lcore_id < num_core; lcore_id++) {
			ret = rte_eth_tx_queue_setup(portid, lcore_id, nb_txd,
					rte_eth_dev_socket_id(portid), &tx_conf);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE,
						"rte_eth_tx_queue_setup fail, "
						"rte_errno=%d (%s), port=%u, q_id=%d\n",
						ret, rte_strerror(ret), portid, lcore_id);
			}
		}

		ret = rte_eth_dev_start(portid);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"Rte_eth_dev_start: rte_errno=%d, port=%u\n", ret, portid);
		}

		rte_eth_promiscuous_enable(portid);
		
		memset(&fc_conf, 0, sizeof(struct rte_eth_fc_conf));
		ret = rte_eth_dev_flow_ctrl_get(portid, &fc_conf);
		if (ret != 0)
			log_warning("Fail to get flow control info!\n");
#if 1
		fc_conf.mode = RTE_ETH_FC_FULL;
		//fc_conf.mode = RTE_FC_NONE;
		ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
		if (ret != 0) {
			log_warning("Fail to set flow control info!\n");
		}
#endif

		ret = rte_eth_dev_get_mtu(portid, &mtu);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Fail to get mtu of port %d (%s)\n", portid, if_name);
		}

		//log_info("MTU of Port %d(%s) is %u\n", portid, if_name, mtu);
		ret = rte_eth_link_get(portid, &g_link_state[portid]);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"Fail to get link information "
					"errno=%d (%s)\n",
					rte_errno, rte_strerror(rte_errno));
		}

#if LIMIT_TXQ_RATE /* Bluefield Does not support this feature */
		uint16_t txq_rate = g_link_state[portid].link_speed / num_core;
		for (lcore_id = 0; lcore_id < num_core; lcore_id++) {
			ret = rte_eth_set_queue_rate_limit(portid, lcore_id, txq_rate);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE,
						"Fail to set tx rate limit "
						"errno=%d (%s)\n", ret, rte_strerror(ret));
			}
		}
		log_info("LIMIT TXQ RATE = %u\n", txq_rate);
#endif

		ret = rte_eth_dev_info_get(portid, &dev_info[portid]);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"Cannot get dev_info from port %u (%s), rte_errno=%d (%s)\n", 
					portid, if_name, ret, rte_strerror(ret));
		}
	}
	//log_info("Port Initialization Completes\n");
	
	memcpy(&host_addr, &d_CONFIG.host_mac_addr, sizeof(struct rte_ether_addr));

#if DEBUG_ETH_STATS
	us_prev_dump_eth_stats = GetCurUs();
#endif
}

void 
dpdk_teardown(void) {
	int portid;

	RTE_ETH_FOREACH_DEV(portid) {
#if DEBUG_ETH_XSTATS
		int nb_entry, i;
		struct rte_eth_xstat xstats[MAX_NB_XSTATS_ENTRY];
		struct rte_eth_xstat_name xstat_name;

		nb_entry = rte_eth_xstats_get(portid, xstats, MAX_NB_XSTATS_ENTRY);
		if (nb_entry < 0) {
			rte_exit(EXIT_FAILURE, "Fail to get xstats from port %u\n", portid);
		}
		fprintf(stderr, "-----------------------------------------------------\n");
		fprintf(stderr, "Extended Statistics \n");
		for (i = 0; i < nb_entry; i++) {
			rte_eth_xstats_get_names_by_id(portid, &xstat_name, 1, &xstats[i].id);
			fprintf(stderr, "%s : %lu\n", xstat_name.name, xstats[i].value);
		}
		fprintf(stderr, "-----------------------------------------------------\n");
#endif
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
	}
}
/*-----------------------------------------------------------------------*/
inline void
dpdk_free_pkts(struct rte_mbuf **mtable, unsigned len)
{
	unsigned i;

	for (i = 0; i < len; i++) {
		rte_pktmbuf_free(mtable[i]);
		RTE_MBUF_PREFETCH_TO_FREE(mtable[i + 1]);
	}
}
/*-----------------------------------------------------------------------*/
inline int32_t
dpdk_recv_pkts(uint16_t core_id, uint16_t port)
{
	struct dpdk_private_context *dpc;
	struct mbuf_table *rmbuf;
	int ret;

	dpc = g_dpc[core_id];
	rmbuf = &dpc->rmbufs[port];

	if (rmbuf->len != 0) {
		dpdk_free_pkts(rmbuf->m_table, rmbuf->len);
		rmbuf->len = 0;
	}

	ret = rte_eth_rx_burst((uint8_t)port, core_id, dpc->pkts_burst, MAX_PKTS_BURST);

#if VERBOSE_TCP
	if (ret > 0) {
		struct rte_mbuf *m;
		uint8_t *ptr;
		int i;

		fprintf(stderr, "\nRECEIVING %d PACKETS\n", ret);

		for (i = 0; i < ret; i++) {
			m = dpc->pkts_burst[i];
			ptr = (void *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			dump_pkt(ptr, m->pkt_len);
		}
	}
#endif /* VERBOSE_TCP */

#ifdef RX_IDLE_ENABLE
	dpc->rx_idle = (ret != 0) ? 0 : dpc->rx_idle + 1;
#endif
	rmbuf->len = ret;

	return ret;
}
/*-----------------------------------------------------------------------*/
inline uint8_t *
dpdk_get_rptr(uint16_t core_id, uint16_t port, int index, uint16_t *len)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *m;
	uint8_t *pktbuf;

	dpc = g_dpc[core_id];

	m = dpc->pkts_burst[index];

	*len = m->pkt_len;
	pktbuf = rte_pktmbuf_mtod(m, uint8_t *);

	dpc->rmbufs[port].m_table[index] = m;

	/*if ((m->ol_flags & (PKT_RX_L4_CKSUM_BAD | PKT_RX_IP_CKSUM_BAD)) != 0) {
		log_error("[CPU %d][Port %d] mbuf(index: %d) with invalid checksum: "
			"%p(%lu);\n", core_id, port, index, m, m->ol_flags);
		pktbuf = NULL;
	}*/
#if SHOW_RSS
#define FORM_IP_ADDR(addr) \
	((addr) & 0x000000ff), \
	((addr) & 0x0000ff00) >> 8, \
	((addr) & 0x00ff0000) >> 16,  \
	((addr) & 0xff000000) >> 24

	struct rte_ether_hdr *ethh = (struct rte_ether_hdr *)pktbuf;
	struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(ethh + 1);
	struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)(iph + 1);
	if (rte_be_to_cpu_16(ethh->ether_type) == RTE_ETHER_TYPE_IPV4) {
		fprintf(stderr, 
				"src_addr = %u.%u.%u.%u, dst_addr = %u.%u.%u.%u \n"
				"src_port = %u, dst_port=%u \n"
				"coreid=%u, rss=%u mapped_value=%u\n", 
				FORM_IP_ADDR(iph->src_addr), FORM_IP_ADDR(iph->dst_addr),
				rte_be_to_cpu_16(tcph->src_port), rte_be_to_cpu_16(tcph->dst_port),
				core_id,  m->hash.rss, m->hash.rss % MAX_CPUS);
	}
#endif

	return pktbuf;
}
/*-----------------------------------------------------------------------*/
inline struct rte_mbuf *
dpdk_get_wptr(uint16_t core_id, uint16_t port, uint16_t pktsize)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *m;
	struct mbuf_table *wmbuf;
	int len_mbuf;
	int send_cnt;

	dpc = g_dpc[core_id];
	wmbuf = &dpc->wmbufs[port];

	if (wmbuf->len == MAX_PKTS_BURST) {
		do {
			send_cnt = dpdk_send_pkts(core_id, port);
		} while (!send_cnt);
	}

	len_mbuf = wmbuf->len;
	m = wmbuf->m_table[len_mbuf];

	m->pkt_len = m->data_len = pktsize;
	m->nb_segs = 1;
	m->next    = NULL;
	wmbuf->len = len_mbuf + 1;

	return m;
}
/*-----------------------------------------------------------------------*/
inline int
dpdk_send_pkts(uint16_t core_id, uint16_t port)
{
	struct dpdk_private_context *dpc;
	struct mbuf_table *wmbuf;
	int ret, i;
#if SHOW_STATISTICS
	uint64_t us_now = GetCurUs();
#endif

	dpc	  = g_dpc[core_id];
	wmbuf = &dpc->wmbufs[port];
	ret   = 0;

	if (wmbuf->len > 0) {
		struct rte_mbuf **pkts;
		int cnt = wmbuf->len;
		pkts = wmbuf->m_table;
		
		do {
			ret   = rte_eth_tx_burst(port, core_id, pkts, cnt);
			pkts += ret;
			cnt  -= ret;
		} while (cnt > 0);
    
		for (i = 0; i < wmbuf->len; i++) {
			wmbuf->m_table[i] = rte_pktmbuf_alloc(pktmbuf_pool[core_id]);
			if (wmbuf->m_table[i] == NULL) {
				rte_exit(EXIT_FAILURE,
						"[CPU %d] Failed to allocate wmbuf[%d] on port %d\n",
						core_id, i, port);
			}
		}
		wmbuf->len = 0;
	}

#if SHOW_STATISTICS
	g_stat[core_id].us_tx_burst += (GetCurUs() - us_now);
	g_stat[core_id].num_tx_burst++;
#endif

	return ret;
}

void
dpdk_select(uint16_t coreid, uint16_t port) {
#if RX_IDLE_ENABLE
	struct dpdk_private_context *dpc;
	dpc = g_dpc[coreid];

	if (dpc->rx_idle > RX_IDLE_THRESH) {
		dpc->rx_idle = 0;
		usleep(RX_IDLE_TIMEOUT);
	}
#endif
}

#ifndef UNUSED
#define UNUSED(_x) (void)(_x)
#endif

void dpdk_dump_pkt(uint8_t *pktbuf, uint16_t pkt_len)
{
#if PACKET_LOG
	char send_dst_hw[20];
	char send_src_hw[20];
	struct rte_ether_hdr *ethh;
	struct rte_ipv4_hdr *iph;
	struct rte_tcp_hdr *tcph;
  
	ethh = (struct rte_ether_hdr *)pktbuf;
	iph = (struct rte_ipv4_hdr *)(ethh + 1);
	tcph = (struct rte_tcp_hdr *)(iph + 1);

	memset(send_dst_hw, 0, 10);
	memset(send_src_hw, 0, 10);

	sprintf(send_dst_hw, "%x:%x:%x:%x:%x:%x", ethh->dst_addr.addr_bytes[0],
		ethh->dst_addr.addr_bytes[1], ethh->dst_addr.addr_bytes[2],
		ethh->dst_addr.addr_bytes[3], ethh->dst_addr.addr_bytes[4],
		ethh->dst_addr.addr_bytes[5]);

	sprintf(send_src_hw, "%x:%x:%x:%x:%x:%x", ethh->src_addr.addr_bytes[0],
		ethh->src_addr.addr_bytes[1], ethh->src_addr.addr_bytes[2],
		ethh->src_addr.addr_bytes[3], ethh->src_addr.addr_bytes[4],
		ethh->src_addr.addr_bytes[5]);

	fprintf(stderr,
		"Packet Info---------------------------------\n"
		"dest hwaddr: %s\n"
		"source hwaddr: %s\n"
		"%u.%u.%u.%u : %u -> %u.%u.%u.%u : %u, id: %u\n"
		"seq: %u, ack: %u, flag: %x\n"
		"total len: %u\n",
		send_dst_hw, send_src_hw, ((ntohl(iph->src_addr) >> 24) & 0xff),
		((ntohl(iph->src_addr) >> 16) & 0xff),
		((ntohl(iph->src_addr) >> 8) & 0xff), ((ntohl(iph->src_addr)) & 0xff),
		ntohs(tcph->src_port), ((ntohl(iph->dst_addr) >> 24) & 0xff),
		((ntohl(iph->dst_addr) >> 16) & 0xff),
		((ntohl(iph->dst_addr) >> 8) & 0xff), ((ntohl(iph->dst_addr)) & 0xff),
		ntohs(tcph->dst_port), ntohs(iph->packet_id), ntohl(tcph->sent_seq),
		ntohl(tcph->recv_ack), tcph->tcp_flags, pkt_len);

	rte_hexdump(stderr, "Packet Hex Dump", pktbuf, RTE_MIN(100,pkt_len));
#else
	UNUSED(pktbuf);
	UNUSED(pkt_len);
#endif
	return;
}
