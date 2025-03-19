#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_jhash.h>

#include "debug.h"
#include "tcp_stream.h"
#include "meta_offload.h"
#include "frd_offload_ctrl.h"
#include "nic_cache.h"
#include "ip_out.h"
#include "ip_in.h"
#include "eth_out.h"
#include "arp.h"
#include "util.h"
#include "mtcp.h"

#define META_OFFLOAD_MAX_BUFFER_SIZE (16 * 1024)

#define META_OFFLOAD_CACHE_META_NB_SEGS_THRESH 40
#define META_OFFLOAD_CACHE_TX_PKTS_TIMEOUT 50
#define META_OFFLOAD_FRD_TX_PKTS_TIMEOUT 50

#define DBG_META_OFFLOAD FALSE
#if DBG_META_OFFLOAD
#define TRACE_META_OFFLOAD(f, ...) fprintf(stderr, "(%10s:%4d) " f, __func__, __LINE__, ##__VA_ARGS__)
#else
#define TRACE_META_OFFLOAD(f, ...) (void)0
#endif

#if ENABLE_META_OFFLOAD_SEPARATED_CHANNEL
struct meta_offload_channel {
	int sfd;
	uint16_t len;
	uint32_t ts;
	uint8_t buf[META_OFFLOAD_MAX_BUFFER_SIZE];
};

static struct meta_offload_channel *g_ch[DATAPLANE_MAX_CPUS];
#endif

#if ENABLE_META_OFFLOAD_SEPARATED_CHANNEL
#define CHNNL_SRV_PORT 65000
#endif

void
meta_offload_global_setup(void) {
#if ENABLE_META_OFFLOAD_SEPARATED_CHANNEL
	int i, ret, optval;
	struct sockaddr_in clnt_addr;

	for (i = 0; i < DATAPLANE_MAX_CPUS; i++) {
		g_ch[i] = calloc(1, sizeof(struct meta_offload_channel));
		if (!g_ch[i]) {
			perror("calloc");
			exit(EXIT_FAILURE);
		}

		g_ch[i]->sfd = socket(AF_INET, SOCK_STREAM, 0);
		if (g_ch[i]->sfd < 0) {
			perror("socket");
			exit(EXIT_FAILURE);
		}

		clnt_addr.sin_family = AF_INET;
		clnt_addr.sin_port = htons(CHNNL_SRV_PORT);
		//inet_pton(AF_INET, "192.168.100.2", &clnt_addr.sin_addr);
		inet_pton(AF_INET, "10.0.30.118", &clnt_addr.sin_addr);

		do {
			ret = connect(g_ch[i]->sfd, (struct sockaddr *)&clnt_addr, 
					sizeof(struct sockaddr_in));
		} while(ret != 0);

		ret = fcntl(g_ch[i]->sfd, F_GETFL, 0);
		if (ret < 0) {
			perror("fcntl, F_GETFL fail.");
			exit(EXIT_FAILURE);
		}

		ret = fcntl(g_ch[i]->sfd, F_SETFL, ret | O_NONBLOCK);
		if (ret < 0) {
			perror("fcntl, fail to set O_NONBLOCK.");
			exit(EXIT_FAILURE);
		}
#if 1
		optval = 1;
		ret = setsockopt(g_ch[i]->sfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
		if (ret < 0) {
			perror("Fail to set TCP_NODELAY\n");
			exit(EXIT_FAILURE);
		}
#endif
	}
	TRACE_INFO("Negotion completes\n");
#endif
}

void
meta_offload_global_destroy(void) {
#if ENABLE_META_OFFLOAD_SEPARATED_CHANNEL
	int i;
	for (i = 0; i < DATAPLANE_MAX_CPUS; i++) {
		close(g_ch[i]->sfd);
		free(g_ch[i]);
	}
#endif
}

#if ENABLE_META_OFFLOAD_SEPARATED_CHANNEL

#define BUFFER_THRESH (8192)

static uint8_t *
_chnnl_get_mem(int cpu, uint16_t len) {

	ssize_t wr_len;
	uint8_t *buf;
	struct  meta_offload_channel *chnnl = g_ch[cpu];

	if (chnnl->len + len >= BUFFER_THRESH ) {
		//chnnl->len = 0;
wr_retry :
		wr_len = write(chnnl->sfd, chnnl->buf, chnnl->len);
		if (wr_len < 0) {
			if (errno == EAGAIN) {
				usleep(1);
				goto wr_retry;
			}
			else {
				perror("write");
				exit(EXIT_FAILURE);
			}
		}

		assert((chnnl->len % 86) == 0);

		chnnl->len = 0;
	}

	buf = chnnl->buf + chnnl->len;
	chnnl->len += len;

	return buf;
}

static void
_flush_meta(int cpu, uint32_t cur_ts) {

	ssize_t wr_len;
	struct meta_offload_channel *chnnl = g_ch[cpu];

	if (cur_ts - chnnl->ts < META_OFFLOAD_CACHE_TX_PKTS_TIMEOUT)
		return;

	chnnl->ts = cur_ts;

	if (chnnl->len <= 0)
		return;

	wr_len = write(chnnl->sfd, chnnl->buf, chnnl->len);
	if (wr_len < 0) {
		perror("write");
		exit(EXIT_FAILURE);
	}

	assert(wr_len == chnnl->len);
	assert((wr_len % 86) == 0);

	chnnl->len = 0;
}

#endif /* ENABLE_META_OFFLOAD_SEPARATED_CHANNEL */

meta_offload *
meta_offload_setup(uint16_t host_txq) {

	meta_offload *mo;
	int i, j;
	char pool_name[RTE_MEMZONE_NAMESIZE];

	sprintf(pool_name, "meta-pool-%d", host_txq);

	mo = calloc(1, sizeof(meta_offload));
	if (!mo) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	mo->cpu = host_txq;
#if ENABLE_META_OFFLOAD_SEPARATED_CHANNEL
	UNUSED(i);
	UNUSED(j);
	UNUSED(pool_name);
#else
	mo->meta_pktmbuf_pool = rte_pktmbuf_pool_create(pool_name, META_OFFLOAD_NB_MBUFS, 256, 0,
			META_OFFLOAD_DATAROOM_SIZE + RTE_PKTMBUF_HEADROOM, rte_socket_id());
	if (!mo->meta_pktmbuf_pool) {
		TRACE_ERROR("Fail to create meta mbuf pool\n");
		exit(EXIT_FAILURE);
	}

	mo->cache = calloc(CONFIG.eths_num, sizeof(struct meta_offload_tx_pkt *));
	if (!mo->cache) {
		TRACE_ERROR("Fail to create meta_offload_tx_pkt");
		exit(EXIT_FAILURE);
	}

	mo->frd_meta_a = calloc(CONFIG.eths_num, sizeof(struct meta_offload_tx_pkt *));
	if (!mo->frd_meta_a) {
		TRACE_ERROR("Fail to create meta_offload_tx_pkt\n");
		exit(EXIT_FAILURE);
	}

	mo->frd_meta_b = calloc(CONFIG.eths_num, sizeof(struct meta_offload_tx_pkt *));
	if (!mo->frd_meta_b) {
		TRACE_ERROR("Fail to create frd_control tx_pkt\n");
		exit(EXIT_FAILURE);
	}

	mo->frd_meta_c = calloc(CONFIG.eths_num, sizeof(struct meta_offload_tx_pkt *));
	if (!mo->frd_meta_b) {
		TRACE_ERROR("Fail to create frd_control tx_pkt\n");
		exit(EXIT_FAILURE);
	}

#ifdef ENABLE_DUMMY_CMD
	mo->dummy = calloc(CONFIG.eths_num, sizeof(struct meta_offload_tx_pkt *));
	if (!mo->dummy) {
		TRACE_ERROR("Fail to create dummy tx_pkt\n");
		exit(EXIT_FAILURE);
	}
#endif

	for (i = 0; i < CONFIG.eths_num; i++) {
		mo->cache[i] = calloc(META_OFFLOAD_NUM_META_CPUS, sizeof(struct meta_offload_tx_pkt));
		if (!mo->cache[i]) {
			TRACE_ERROR("Fail to create meta_offload_tx_pkt");
			exit(EXIT_FAILURE);
		}

		mo->frd_meta_a[i] = calloc(META_OFFLOAD_NUM_META_CPUS, sizeof(struct meta_offload_tx_pkt));
		if (!mo->frd_meta_a[i]) {
			TRACE_ERROR("Fail to create meta_offload_tx_pkt");
			exit(EXIT_FAILURE);
		}

		mo->frd_meta_b[i] = calloc(META_OFFLOAD_NUM_META_CPUS, sizeof(struct meta_offload_tx_pkt));
		if (!mo->frd_meta_b[i]) {
			TRACE_ERROR("Fail to create meta_offload_tx_pkt");
			exit(EXIT_FAILURE);
		}

		mo->frd_meta_c[i] = calloc(META_OFFLOAD_NUM_META_CPUS, sizeof(struct meta_offload_tx_pkt));
		if (!mo->frd_meta_b[i]) {
			TRACE_ERROR("Fail to create meta_offload_tx_pkt");
			exit(EXIT_FAILURE);
		}

#ifdef ENABLE_DUMMY_CMD
		mo->dummy[i] = calloc(META_OFFLOAD_NUM_META_CPUS, sizeof(struct meta_offload_tx_pkt));
		if (!mo->dummy[i]) {
			TRACE_ERROR("Fail to create meta_offload_tx_pkt");
			exit(EXIT_FAILURE);
		}
#endif

		for (j = 0; j < META_OFFLOAD_NUM_META_CPUS; j++) {
			mo->frd_meta_a[i][j].host_txq = host_txq;
			mo->frd_meta_a[i][j].nic_rxq = j;
			mo->frd_meta_a[i][j].nif = i;

			mo->frd_meta_b[i][j].host_txq = host_txq;
			mo->frd_meta_b[i][j].nic_rxq = j;
			mo->frd_meta_b[i][j].nif = i;

			mo->frd_meta_c[i][j].host_txq = host_txq;
			mo->frd_meta_c[i][j].nic_rxq = j;
			mo->frd_meta_c[i][j].nif = i;

			mo->cache[i][j].host_txq = host_txq;
			mo->cache[i][j].nic_rxq = j;
			mo->cache[i][j].nif = i;

#ifdef ENABLE_DUMMY_CMD
			mo->dummy[i][j].host_txq = host_txq;
			mo->dummy[i][j].nic_rxq = j;
			mo->dummy[i][j].nif = i;
#endif
		}
	}


#ifdef ENABLE_RTT_CHECK
	char name[64];
	sprintf(name, "rtt_ht%u", host_txq);
	struct rte_hash_parameters hash_params = {
		.entries = 1024,
		.key_len = sizeof(uint32_t) * 3,
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
		.name = name,
	};

	mo->rtt_ht = rte_hash_create(&hash_params);
	if (!mo->rtt_ht) {
		TRACE_ERROR("Fail to create rtt hash map\n");
		exit(EXIT_FAILURE);
	}
	sprintf(name, "ts-%u", host_txq);
	mo->mp_ts = MPCreate(name, sizeof(uint64_t), 2048 * sizeof(uint64_t));
	if (!mo->mp_ts) {
		TRACE_ERROR("Fail to create memory pool\n");
		exit(EXIT_FAILURE);
	}
#endif

#endif /* ENABLE_META_OFFLOAD_SEPARATED_CHANNEL */

	return mo;
}

inline static void
__meta_offload_send_packet(meta_offload *mo, struct meta_offload_tx_pkt *tx_pkt, uint32_t cur_ts) {

	int ret;
	uint16_t qid, nif;
	if (!tx_pkt->head && !tx_pkt->tail)
		return;

	TRACE_META_OFFLOAD("head:%p, tail:%p, txq:%u, nb_segs:%u\n", 
			tx_pkt->head, tx_pkt->tail, tx_pkt->host_txq, tx_pkt->head->nb_segs);

#ifdef ENABLE_RTT_CHECK
	uint64_t *ts = MPAllocateChunk(mo->mp_ts);
	uint32_t key[3];

	struct ethhdr *ethh = rte_pktmbuf_mtod(tx_pkt->head, struct ethhdr *);
	struct iphdr *iph = (struct iphdr *)(ethh + 1);
	struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

	key[0] = iph->saddr;
	key[1] = iph->daddr;
	key[2] = ((uint32_t)tcph->source << 16) | tcph->dest;
	
	if (!ts) {
		TRACE_ERROR("Fail to allocate chunk, increase number of ts\n");
		exit(EXIT_FAILURE);
	}

	*ts = get_cur_us();
	ret = rte_hash_add_key_data(mo->rtt_ht, key, ts);
	if (ret < 0) {
		TRACE_ERROR("%s\n", strerror(-ret));
		exit(EXIT_FAILURE);
	}
#endif

	nif = tx_pkt->nif;

	do {
#if ENABLE_META_TX_QUEUE
#if ENABLE_MULTI_VFS
		nif = 1;
		qid = tx_pkt->host_txq;
#else
		qid = GET_META_TX_QID(tx_pkt->host_txq);
#endif
		ret = rte_eth_tx_burst(nif, qid, &tx_pkt->head, 1);
		//TRACE_INFO("txq:%u qid:%u\n", tx_pkt->host_txq, GET_META_TX_QID(tx_pkt->host_txq));
#else
		ret = rte_eth_tx_burst(tx_pkt->nif, tx_pkt->host_txq, &tx_pkt->head, 1);
#endif /* ENABLE_META_TX_QUEUE */
	} while (ret != 1);
	
	tx_pkt->head = NULL;
	tx_pkt->tail = NULL;
	tx_pkt->ts = cur_ts;
}

#ifdef ENABLE_RTT_CHECK
void
meta_offload_process_rtt_packet(meta_offload *mo, struct iphdr *iph) {
	int32_t ret;
	uint64_t *ts, elapsed;
	uint32_t key[3];
	struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

	key[0] = iph->daddr;
	key[1] = iph->saddr;
	key[2] = ((uint32_t)tcph->dest << 16) | tcph->source;

	ret = rte_hash_lookup_data(mo->rtt_ht, key, (void **)&ts);
	if (ret < 0) {
		TRACE_INFO("(CPU%u) src_addr:%u, dst_addr:%u, sport:%u, dport:%u\n",
			mo->cpu, iph->saddr, iph->daddr, tcph->source, tcph->dest);
		return;
	}

	ret = rte_hash_del_key(mo->rtt_ht, key);
	if (ret < 0) {
		TRACE_ERROR("(CPU%u) %s\n", mo->cpu, strerror(-ret));
		exit(EXIT_FAILURE);
	}
	elapsed =  get_cur_us() - *ts;
	MPFreeChunk(mo->mp_ts, ts);

#if SHOW_NIC_CACHE_STATISTICS
	g_nic_cache_stat[mo->cpu].num_meta++;
	g_nic_cache_stat[mo->cpu].meta_rtt += elapsed;
#endif

}
#endif

inline uint8_t *
meta_offload_generate_ipv4_packet(meta_offload *mo, void *cur_stream,
		uint16_t tcplen, enum meta_offload_type meta_offload_type, uint32_t cur_ts) {

	struct rte_mbuf *m;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct meta_offload_tx_pkt *tx_pkt;
	tcp_stream *stream = cur_stream;
	unsigned char *haddr = GetDestinationHWaddr(stream->daddr, stream->is_external);
	int i = 0, nif = stream->sndvar->nif_out;
	uint16_t nic_rxq = stream->sndvar->nic_rxq;
	uint16_t data_len = tcplen + sizeof(struct ethhdr) + sizeof(struct iphdr);

#if ENABLE_MULTI_VFS
	nif_out = 1;
#endif

#if ENABLE_META_OFFLOAD_SEPARATED_CHANNEL
	UNUSED(nif);
	UNUSED(tx_pkt);
	UNUSED(m);
	ethh = (struct ethhdr *)_chnnl_get_mem(nic_rxq, data_len);
#else
	switch (meta_offload_type) {
		case META_OFFLOAD_APP_HDR :
		case META_OFFLOAD_CACHE :
			tx_pkt = &mo->cache[nif][nic_rxq];
			break;
		case META_OFFLOAD_FRD_SEND :
			tx_pkt = &mo->frd_meta_c[nif][nic_rxq];
			break;
		case META_OFFLOAD_FRD_TEARDOWN :
			tx_pkt = &mo->frd_meta_a[nif][nic_rxq];
			break;
		case META_OFFLOAD_FRD_SETUP :
			tx_pkt = &mo->frd_meta_b[nif][nic_rxq];
			break;
#ifdef ENABLE_DUMMY_CMD
		case META_OFFLOAD_DUMMY :
			tx_pkt = &mo->dummy[nif][nic_rxq];
			break;
#endif
		default :
			break;
	}

	TRACE_META_OFFLOAD("nif:%u, nic_rxq:%u, tx_pkt:%p, head:%p, tail:%p\n", 
			nif, nic_rxq, tx_pkt, tx_pkt->head, tx_pkt->tail);

	if (tx_pkt->head && tx_pkt->tail &&
			((tx_pkt->head->data_len + data_len > META_OFFLOAD_MAX_PKT_LEN) || 
			(tx_pkt->head->nb_segs >= META_OFFLOAD_CACHE_META_NB_SEGS_THRESH))) {
#if ENABLE_RTT_CHECK && SHOW_NIC_CACHE_STATISTICS
		g_nic_cache_stat[mo->cpu].meta_flush++;
#endif
		__meta_offload_send_packet(mo, tx_pkt, cur_ts);
	}

	m = rte_pktmbuf_alloc(mo->meta_pktmbuf_pool);
	if (!m) {
		TRACE_ERROR("Increase number of packet\n");
		return NULL;
	}

	m->data_len = tcplen + sizeof(struct ethhdr) + sizeof(struct iphdr);
	m->nb_segs = 1;
	m->next = NULL;

	if (!tx_pkt->head && !tx_pkt->tail) {
		tx_pkt->head = m;
		tx_pkt->tail = m;
		tx_pkt->head->pkt_len = m->data_len;
	} else {
		tx_pkt->head->pkt_len += m->data_len;
		tx_pkt->head->nb_segs++;
		tx_pkt->tail->next = m;
		tx_pkt->tail = m;
	}

	ethh = rte_pktmbuf_mtod(m, struct ethhdr *);
#endif /* ENABLE_META_OFFLOAD_SEPARATED_CHANNEL */

	/* Process ethernet layer */
	for (i = 0; i < ETH_ALEN; i++) {
		ethh->h_source[i] = haddr[i];
		ethh->h_dest[i] = dpu_mac_address[i];
	}
	ethh->h_proto = htons(ETH_P_IP);

	/* Process IPV4 Layer */
	iph = (struct iphdr *)(ethh + 1);
	/* Process ip layer */
	iph->ihl = IP_HEADER_LEN >> 2;
	iph->version = 4;

	switch(meta_offload_type) {
		case META_OFFLOAD_CACHE :
			iph->tos = 0;
			break;
		case META_OFFLOAD_APP_HDR :
			iph->tos = 0xf0;
			break;
		case META_OFFLOAD_FRD_SETUP :
			iph->tos = FRD_OFFLOAD_DISK_READ;
			break;
		case META_OFFLOAD_FRD_TEARDOWN :
			iph->tos = FRD_OFFLOAD_FREE_FILE_BUF;
			break;
		case META_OFFLOAD_FRD_SEND :
			iph->tos = FRD_OFFLOAD_TRANSMISSION;
			break;
#ifdef ENABLE_DUMMY_CMD
		case META_OFFLOAD_DUMMY :
			iph->tos = 0;
			break;
#endif
		default :
			break;
	}

	iph->tot_len = htons(IP_HEADER_LEN + tcplen);
	iph->id = htons(stream->sndvar->ip_id++);
	iph->frag_off = htons(0x4000);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = stream->saddr;
	iph->daddr = stream->daddr;
	iph->check = 0;

	return (uint8_t *)(iph + 1);
}

inline void
meta_offload_generate_dummy_packet(meta_offload *mo, void *cur_stream,
		void *in_tcph, uint16_t tcplen, uint32_t cur_ts) {
#ifdef ENABLE_DUMMY_CMD
	void *tcph;
	tcph = meta_offload_generate_ipv4_packet(mo, cur_stream, 
			tcplen + META_DUMMY_CMD_PLEN, META_OFFLOAD_DUMMY, cur_ts);
	memcpy(tcph, in_tcph, tcplen);
#endif
}

inline void
meta_offload_flush(meta_offload *mo, uint32_t cur_ts) {
#if ENABLE_META_OFFLOAD_SEPARATED_CHANNEL
	int i;
	int s = mo->cpu;
	int e = mo->cpu + DATAPLANE_MAX_CPUS / CONFIG.num_cores;

	for (i = s; i < e; i++) 
		_flush_meta(i, cur_ts);
#else
	int i, j;

	for (i = 0; i < CONFIG.eths_num; i++) {
		for (j = 0; j < META_OFFLOAD_NUM_META_CPUS; j++) {
			struct meta_offload_tx_pkt *tx_pkt;

			tx_pkt = &mo->cache[i][j];
			if (tx_pkt->head && tx_pkt->tail &&
				((cur_ts - tx_pkt->ts >= META_OFFLOAD_CACHE_TX_PKTS_TIMEOUT) || 
				(tx_pkt->head->nb_segs >= META_OFFLOAD_CACHE_META_NB_SEGS_THRESH))) {
#if ENABLE_RTT_CHECK && SHOW_NIC_CACHE_STATISTICS
				g_nic_cache_stat[mo->cpu].meta_flush++;
				g_nic_cache_stat[mo->cpu].meta_to++;
#endif
				__meta_offload_send_packet(mo, tx_pkt, cur_ts);
			}

			tx_pkt = &mo->frd_meta_a[i][j];
			if (tx_pkt->head && tx_pkt->tail && 
					((cur_ts - tx_pkt->ts >= META_OFFLOAD_FRD_TX_PKTS_TIMEOUT) || 
					(tx_pkt->head->nb_segs >= META_OFFLOAD_CACHE_META_NB_SEGS_THRESH))) {
#if ENABLE_RTT_CHECK && SHOW_NIC_CACHE_STATISTICS
				g_nic_cache_stat[mo->cpu].meta_flush++;
				g_nic_cache_stat[mo->cpu].meta_to++;
#endif
				__meta_offload_send_packet(mo, tx_pkt, cur_ts);
			}

			tx_pkt = &mo->frd_meta_b[i][j];
			if (tx_pkt->head && tx_pkt->tail && 
					((cur_ts - tx_pkt->ts >= META_OFFLOAD_FRD_TX_PKTS_TIMEOUT) || 
					(tx_pkt->head->nb_segs >= META_OFFLOAD_CACHE_META_NB_SEGS_THRESH))) {
#if ENABLE_RTT_CHECK && SHOW_NIC_CACHE_STATISTICS
				g_nic_cache_stat[mo->cpu].meta_flush++;
				g_nic_cache_stat[mo->cpu].meta_to++;
#endif
				__meta_offload_send_packet(mo, tx_pkt, cur_ts);
			}

			tx_pkt = &mo->frd_meta_c[i][j];
			if (tx_pkt->head && tx_pkt->tail && 
					((cur_ts - tx_pkt->ts >= META_OFFLOAD_FRD_TX_PKTS_TIMEOUT) || 
					(tx_pkt->head->nb_segs >= META_OFFLOAD_CACHE_META_NB_SEGS_THRESH))) {
#if ENABLE_RTT_CHECK && SHOW_NIC_CACHE_STATISTICS
				g_nic_cache_stat[mo->cpu].meta_flush++;
				g_nic_cache_stat[mo->cpu].meta_to++;
#endif
				__meta_offload_send_packet(mo, tx_pkt, cur_ts);
			}
#ifdef ENABLE_DUMMY_CMD
			tx_pkt = &mo->dummy[i][j];
			if (tx_pkt->head && tx_pkt->tail && 
					((cur_ts - tx_pkt->ts >= META_OFFLOAD_CACHE_TX_PKTS_TIMEOUT) || 
					(tx_pkt->head->nb_segs >= META_OFFLOAD_CACHE_META_NB_SEGS_THRESH))) {
				__meta_offload_send_packet(mo, tx_pkt, cur_ts);
			}
#endif
		}
	}
#endif /* ENABLE_META_OFFLOAD_SEPARATED_CHANNEL */
}

void
meta_offload_teardown(meta_offload *mo) {

#if !ENABLE_META_OFFLOAD_SEPARATED_CHANNEL
	int i;
	rte_mempool_free(mo->meta_pktmbuf_pool);
	for (i = 0; i < CONFIG.eths_num; i++) {
		free(mo->cache[i]);
		free(mo->frd_meta_a[i]);
		free(mo->frd_meta_b[i]);
	}
#ifdef ENABLE_RTT_CHECK
	rte_hash_free(mo->rtt_ht);
	MPDestroy(mo->mp_ts);
#endif

#endif /* ENABLE_META_OFFLOAD_SEPARATED_CHANNEL */
	free(mo);
}
