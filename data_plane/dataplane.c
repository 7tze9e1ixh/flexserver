#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <pthread.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_common.h>
#include <rte_cycles.h>

#include "dataplane.h"
#include "chnk_ht.h"
#include "dpdk_io.h"
#include "debug.h"
#include "config.h"
#include "blk.h"
#include "rate_limit.h"
#include "frd_offload.h"
#include "fht.h"
#include "meta_reply.h"

#define SET_TCP_OFFLOAD_FLAGS(_m, _tcph) do {\
	(_m)->l2_len = sizeof(struct rte_ether_hdr);\
	(_m)->l3_len = sizeof(struct rte_ipv4_hdr);\
	(_m)->l4_len = GET_TCP_HDR_LEN(_tcph);\
	(_m)->tso_segsz = MTU - ((_m)->l3_len + (_m)->l4_len);\
	(_m)->ol_flags |= (RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | \
						RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_SEG);\
} while(0)

typedef struct pkt_ctrl_s {
	uint16_t lcore_id;
	bool ready;
	struct dpdk_private_context *dpc;
	frd_offload *fo;
	fht *ht;
} pkt_ctrl; 

enum reply_type {
	REPLY_TYPE_OFFLOAD,
	REPLY_TYPE_EVICTION,
};

#if ENABLE_META_CHANNEL
#define MAX_CHANNEL_BUF_SIZE 8192
struct channel {
	int sfd;
	uint8_t buf[MAX_CHANNEL_BUF_SIZE];
	uint16_t len;
};

struct channel *g_ch[MAX_CPUS];
#endif

static bool run[MAX_CPUS];

extern struct rte_mempool *pktmbuf_pool[];
extern struct rte_mempool *shinfo_pool[];
extern struct rte_ether_addr host_addr;
extern struct rte_ether_addr src_addr[];

void ext_buf_free_callback_fn(void *addr __rte_unused, void *opaque);
static void signal_handler(int signo);
uint64_t GetCurUs(void);

#define PERIOD 1LU
//#define TO_GBPS(b) ((double)(b) * 8 / ((1024LU * 1024LU * 1024LU) * PERIOD))
#define TO_GBPS(b) ((double)(b) * 8 / (1e9 * PERIOD)) // ((1000LU * 1000LU * 1000LU) * PERIOD)
#define TO_NPS(now, prev) ((double)((now) - (prev)) / PERIOD)

#ifdef _NOTIFYING_MBPS
struct dataplane_goodput g_mbps[MAX_CPUS] = {0};
#endif

#ifdef _GOODPUT
struct dataplane_goodput g_goodput[MAX_CPUS] = {0};
#endif

#if SHOW_STATISTICS	
static bool showStat = false;
#if SHOW_CMD_LOG
static FILE *fp_cmd_log;
#endif

struct dataplane_stat g_stat[MAX_CPUS] = {0};

extern _Atomic uint32_t g_numFrdOffloads;

static void *
ShowStatistics(void *arg) {
	
	int i;
	showStat = true;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	struct timespec ts_now;
	struct dataplane_stat stat_prev[MAX_CPUS] = {0};
	uint64_t sumTotBytes, sumMeta, sumMeta_prev, sumPkts, sumPkts_prev, sumFrdMeta;
	uint64_t sumTotBytesPrev, sumFrdMeta_prev;
	uint64_t sumTotBytes_disk, sumTotBytes_disk_prev;
	uint64_t sumFrdSend, sumFrdSend_prev, 
			 sumFrdSetup, sumFrdSetup_prev,
			 sumFrdTeardown, sumFrdTeardown_prev,
			 sumRTOFrdSetup, sumRTOFrdSetup_prev,
			 sumRTOFrdTeardown, sumRTOFrdTeradown_prev,
			 sumFrdTeardownHdr, sumFrdTeardownHdr_prev,
			 sumFrdSetupHdr, sumFrdSetupHdr_prev,
			 sumReplyPkt, sumReplyPkt_prev,
			 sumFrdComplPkt, sumFrdComplPkt_prev,
			 sumFrdFreePkt, sumFrdFreePkt_prev,
			 sumFrdComplHdr, sumFrdComplHdr_prev,
			 sumFrdFreeHdr, sumFrdFreeHdr_prev,
			 sumReplyHdr, sumReplyHdr_prev,
			 sumNumAppHdr, sumNumAppHdr_prev,
			 sumHdrBytes, sumHdrBytes_prev,
			 sum_us_tx_burst, sum_num_tx_burst,
			 sum_us_tx_burst_prev, sum_num_tx_burst_prev,
			 sum_rx_bytes, sum_rx_bytes_prev;

	double gbps, tot_gbps, evict, offload, gbps_disk, tot_gbps_disk;
	double evict_rt, offload_rt;
#if SHOW_ETH_STATS
	uint16_t port_id;
#endif

#ifdef DUMP_DATAPLANE_STATUS
    FILE *fp_dataplane;
    fp_dataplane = fopen("dataplane.csv", "w");
    if (!fp_dataplane) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
#endif

#ifdef ENABLE_TX_LATENCY
    uint64_t sum_tx_lat, sum_tx_lat_prev, sum_num_tx, sum_num_tx_prev;
#endif

#if SHOW_CMD_LOG
	fprintf(fp_cmd_log, "%10s,%10s,%10s,%10s\n",
			"num_offload", "num_offload_rt", "num_evict", "num_evict_rt");
#endif

	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);

	while (showStat) {
		pthread_mutex_lock(&mutex);

		sumTotBytes = sumTotBytesPrev =
			sumFrdSend = sumFrdSend_prev = 
			sumFrdSetup = sumFrdSetup_prev = 
			sumFrdTeardown = sumFrdTeardown_prev = 
			sumFrdMeta = sumFrdMeta_prev = 
			sumPkts = sumPkts_prev = 
			sumMeta = sumMeta_prev =
			sumTotBytes_disk = sumTotBytes_disk_prev =
			sumRTOFrdSetup = sumRTOFrdSetup_prev =
			sumRTOFrdTeardown = sumRTOFrdTeradown_prev =
			sumFrdSetupHdr = sumFrdSetupHdr_prev =
			sumFrdTeardownHdr = sumFrdTeardownHdr_prev = 
			sumReplyPkt = sumReplyPkt_prev = 
			sumFrdComplPkt = sumFrdComplPkt_prev = 
			sumFrdFreePkt = sumFrdFreePkt_prev =
			sumFrdComplHdr = sumFrdComplHdr_prev = 
			sumFrdFreeHdr = sumFrdFreeHdr_prev = 
			sumReplyHdr = sumReplyHdr_prev = 
			sumNumAppHdr = sumNumAppHdr_prev = 
			sumHdrBytes = sumHdrBytes_prev   =
			sum_us_tx_burst = sum_num_tx_burst = 
			sum_us_tx_burst_prev = sum_num_tx_burst_prev = 
			sum_rx_bytes = sum_rx_bytes_prev = 0;

#ifdef ENABLE_TX_LATENCY
		sum_tx_lat = sum_tx_lat_prev =
            sum_num_tx = sum_num_tx_prev = 0;
#endif

		clock_gettime(CLOCK_REALTIME, &ts_now);
		ts_now.tv_sec += PERIOD;

		pthread_cond_timedwait(&cond, &mutex, &ts_now);

		for (i = 0 ; i < d_CONFIG.ncpus; i++) {
			sumTotBytes += g_stat[i].totBytes;
			sumTotBytesPrev += stat_prev[i].totBytes;

			sumTotBytes_disk += g_stat[i].disk_sent_bytes;
			sumTotBytes_disk_prev += stat_prev[i].disk_sent_bytes;

			sumMeta += g_stat[i].numMeta;
			sumMeta_prev += stat_prev[i].numMeta;

			sumPkts += g_stat[i].numPkts;
			sumPkts_prev += stat_prev[i].numPkts;

			sumFrdMeta += g_stat[i].numFrdMeta;
			sumFrdMeta_prev += stat_prev[i].numFrdMeta;

			sumFrdSend += g_stat[i].numFrdSend;
			sumFrdSend_prev += stat_prev[i].numFrdSend;

			sumFrdSetup += g_stat[i].numFrdSetup;
			sumFrdSetup_prev += stat_prev[i].numFrdSetup;

			sumFrdTeardown += g_stat[i].numFrdTeardown;
			sumFrdTeardown_prev += stat_prev[i].numFrdTeardown;

			sumRTOFrdSetup += g_stat[i].numRTOFrdSetup;
			sumRTOFrdSetup_prev += stat_prev[i].numRTOFrdSetup;

			sumRTOFrdTeardown += g_stat[i].numRTOFrdTeardown;
			sumRTOFrdTeradown_prev += stat_prev[i].numRTOFrdTeardown;

			sumFrdSetupHdr += g_stat[i].numFrdSetupHdr;
			sumFrdSetupHdr_prev += stat_prev[i].numFrdSetupHdr;

			sumFrdTeardownHdr += g_stat[i].numFrdTeardownHdr;
			sumFrdTeardownHdr_prev += stat_prev[i].numFrdTeardownHdr;

			sumReplyPkt += g_stat[i].numReply;
			sumReplyPkt_prev += stat_prev[i].numReply;

			sumFrdComplPkt += g_stat[i].numFrdComplPkt;
			sumFrdComplPkt_prev += stat_prev[i].numFrdComplPkt;

			sumFrdFreePkt += g_stat[i].numFrdFreePkt;
			sumFrdFreePkt_prev += stat_prev[i].numFrdFreePkt;

			sumFrdComplHdr += g_stat[i].numFrdComplHdr;
			sumFrdComplHdr_prev += stat_prev[i].numFrdComplHdr;

			sumFrdFreeHdr += g_stat[i].numFrdFreeHdr;
			sumFrdFreeHdr_prev += stat_prev[i].numFrdFreeHdr;

			sumReplyHdr += g_stat[i].numReplyHdr;
			sumReplyHdr_prev += stat_prev[i].numReplyHdr;

			sum_rx_bytes += g_stat[i].rx_bytes;
			sum_rx_bytes_prev += stat_prev[i].rx_bytes;

			sumNumAppHdr += g_stat[i].numAppHdr;
			sumNumAppHdr_prev += stat_prev[i].numAppHdr;

			sumHdrBytes += g_stat[i].appHdrBytes;
			sumHdrBytes_prev += g_stat[i].appHdrBytes;

			sum_num_tx_burst += g_stat[i].num_tx_burst;
			sum_us_tx_burst += g_stat[i].us_tx_burst;

			sum_num_tx_burst_prev += stat_prev[i].num_tx_burst;
			sum_us_tx_burst_prev += stat_prev[i].us_tx_burst;

#ifdef ENABLE_TX_LATENCY
            sum_num_tx += g_stat[i].num_tx;
            sum_num_tx_prev += stat_prev[i].num_tx;
            sum_tx_lat += g_stat[i].sum_tx_lat;
            sum_tx_lat_prev += stat_prev[i].sum_tx_lat;
#endif
		}

		tot_gbps = TO_GBPS(sumTotBytes - sumTotBytesPrev);
		tot_gbps_disk = TO_GBPS(sumTotBytes_disk - sumTotBytes_disk_prev);
		evict = (g_stat[0].numEvict - stat_prev[0].numEvict) / PERIOD; 
		evict_rt = (g_stat[0].numEvictRT - stat_prev[0].numEvictRT) / PERIOD; 

		offload = (g_stat[0].numOffload - stat_prev[0].numOffload) / PERIOD;
		offload_rt = (g_stat[0].numOffloadRT - stat_prev[0].numOffloadRT) / PERIOD;

		fprintf(stdout, "----------------------------------------------------------------------\n");
		for (i = 0; i < d_CONFIG.ncpus; i++) {
			gbps = TO_GBPS(g_stat[i].totBytes - stat_prev[i].totBytes);
			gbps_disk = TO_GBPS(g_stat[i].disk_sent_bytes - stat_prev[i].disk_sent_bytes);
			fprintf(stdout, "(LCORE_ID%d) TX(Cache):%10.2lf(Gbps) TX(Disk):%10.2lf(Gbps)\n", 
					i, gbps, gbps_disk);
		}

		printf("[TX/RX] : CACHE_TX:%-6.2lf(Gbps) FRD_TX:%-6.2lf(Gbps) RX:%6.2lf (Gbps)\n TX_BIT: %ld",
				tot_gbps, tot_gbps_disk, TO_GBPS(sum_rx_bytes - sum_rx_bytes_prev), sumTotBytes - sumTotBytesPrev);

		printf("[CACHE]    : CACHE_SEND:%-6.2lf(%-6.2lf)(/s) EVICT:%-6.2lf(RT:%-6.2lf) OFFLOAD:%-6.2lf(RT:%-6.2lf) "
				"AppHdr:%-6.2lf(%-6.2lfgbps)\n",
				TO_NPS(sumMeta, sumMeta_prev),
				TO_NPS(sumPkts, sumPkts_prev), evict, evict_rt, offload, offload_rt,
				TO_NPS(sumNumAppHdr, sumNumAppHdr_prev), TO_GBPS(sumHdrBytes - sumHdrBytes_prev));
		printf("[TX_BURST] %4.2lf\n", 
				(double)(sum_us_tx_burst - sum_us_tx_burst_prev) / 
				(sum_num_tx_burst - sum_num_tx_burst_prev));
		printf("[TX_BURST_CNT] %ld\n", (sum_num_tx_burst - sum_num_tx_burst_prev));
#if 0
		printf("[FRD_RX]   : FRD_OFFLOAD:%-6u FRD_SETUP:%-6.2lf(RT:%-6.2lf HDR:%-6.2lf)\n",
				g_numFrdOffloads,
				TO_NPS(sumFrdSetup, sumFrdSetup_prev), 
				TO_NPS(sumRTOFrdSetup, sumRTOFrdSetup_prev),
				TO_NPS(sumFrdSetupHdr, sumFrdSetupHdr_prev));
#if SHOW_CMD_LOG
		fprintf(fp_cmd_log, "%10.2lf,%10.2lf,%10.2lf,%10.2lf\n",
				evict, evict_rt, offload, offload_rt);
#endif

		printf("[FRD_RX]   : FRD_SEND:%-6.2lf(HDR:%-6.2lf) "
				"FRD_TEARDOWN:%-6.2lf(RT:%6.2lf, HDR:%-6.2lf)\n",
				TO_NPS(sumFrdSend, sumFrdSend_prev), 
				TO_NPS(sumFrdMeta, sumFrdMeta_prev),
				TO_NPS(sumFrdTeardown, sumFrdTeardown_prev), 
				TO_NPS(sumRTOFrdTeardown, sumRTOFrdSetup_prev),
				TO_NPS(sumFrdTeardownHdr, sumFrdTeardownHdr_prev));

		printf("[FRD_TX]   : REPLY:%-6.2lf(%-6.2lf)/s, COMPLETE:%-6.2lf/s FREE:%-6.2lf/s\n",
				TO_NPS(sumReplyPkt, sumReplyPkt_prev),
				TO_NPS(sumReplyHdr, sumReplyHdr_prev),
				TO_NPS(sumFrdComplHdr, sumFrdComplHdr_prev),
				TO_NPS(sumFrdFreeHdr, sumFrdFreeHdr_prev));
#endif
		memcpy(stat_prev, g_stat, sizeof(struct dataplane_stat) * MAX_CPUS);

		pthread_mutex_unlock(&mutex);
	}
}
#endif /* SHOW_STATISTICS */

__rte_always_inline __rte_hot uint64_t
GetCurUs(void) {
	struct timespec ts_now;
	clock_gettime(CLOCK_REALTIME, &ts_now);
	return ts_now.tv_sec * 1000000 + ts_now.tv_nsec / 1000;
}

static __rte_always_inline __rte_hot uint64_t
GetCurNs(void) {
	struct timespec ts_now;
	clock_gettime(CLOCK_REALTIME, &ts_now);
	return ts_now.tv_nsec + ts_now.tv_sec * 1000000000;
}

void
ext_buf_free_callback_fn(void *addr __rte_unused, void *opaque) {
	
	struct shinfo_ctx *shinfo = opaque;
	if (shinfo) {
#ifdef ENABLE_TX_LATENCY
        if (shinfo->m_seq == 1) {
#if SHOW_STATISTICS
            g_stat[shinfo->core_id].sum_tx_lat += (GetCurUs() - shinfo->ts);
            g_stat[shinfo->core_id].num_tx++;
#endif
        }
#endif
		rte_mempool_put(g_dpc[shinfo->core_id]->shinfo_pool, shinfo);
	}
}

static chnk_ht *cht = NULL;
static pkt_ctrl *g_pkt_ctrl[MAX_CPUS] = {NULL};

#if ENABLE_META_CHANNEL
#define CHNNL_SRV_PORT 65000

static void
_construct_channel(void) {

	int i, fd, ret;
	struct sockaddr_in srv_addr;
	int option;

	for (i = 0 ; i < d_CONFIG.ncpus; i++) {
		g_ch[i] = calloc(1, sizeof(struct channel));
		if (!g_ch[i]) {
			perror("calloc");
			exit(EXIT_FAILURE);
		}
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	option = 1;

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int));
	if (ret < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(CHNNL_SRV_PORT);
	srv_addr.sin_addr.src_addr = htonl(INADDR_ANY);

	ret = bind(fd, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	ret = listen(fd, d_CONFIG.ncpus);
	if (ret < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < d_CONFIG.ncpus; i++) {
		g_ch[i]->sfd = accept(fd, NULL, NULL);
		if (g_ch[i]->sfd < 0) {
			perror("accept");
			exit(EXIT_FAILURE);
		}

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
	}

	log_info("Netgotiaion completes at dataplane");

	close(fd);
}

static void
_destruct_channel(void) {
	int i;
	for (i = 0; i < d_CONFIG.ncpus; i++) {
		close(g_ch[i]->sfd);
		free(g_ch[i]);
	}
}

#endif /* ENABLE_META_CHANNEL */

static void
wait_for_siblings(pkt_ctrl *pc) {
	int i;
	pc->ready = true;
	for (i = 0; i < d_CONFIG.ncpus; i++) {
		while (!g_pkt_ctrl[i] && !g_pkt_ctrl[i]->ready) {
			usleep(50);
		}
	}
}

/* reply to host after offload or eviction */
static void
__generate_reply_packet(pkt_ctrl *pc, uint16_t port_id, uint64_t hv, uint64_t ts, enum reply_type reply_type) {

	struct rte_ether_hdr *ethh;
    struct rte_mbuf *m;

    m = dpdk_get_wptr(pc->lcore_id, port_id, RTE_ETHER_MIN_LEN);
    ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	rte_memcpy(&ethh->src_addr, &src_addr[port_id], sizeof(struct rte_ether_addr));
	rte_memcpy(&ethh->dst_addr, &host_addr, sizeof(struct rte_ether_addr));

	if (reply_type == REPLY_TYPE_OFFLOAD) {
		struct direct_read_header *drh;
        ethh->ether_type = rte_cpu_to_be_16(ETYPE_OFFLOAD);
        drh = (struct direct_read_header *)(ethh + 1);
        drh->hv = hv;
		drh->ts = ts;
    } else {
        struct eviction_meta *emh;
        ethh->ether_type = rte_cpu_to_be_16(ETYPE_EVICTION);
        emh = (struct eviction_meta *)(ethh + 1);
        emh->e_hv = hv;
		emh->ts = ts;
    }
}

inline static void
__process_cache_item_offload(pkt_ctrl *pc, uint16_t port_id, uint8_t *pkt, uint16_t pkt_len) {

    struct rte_ether_hdr *ethh;
    struct direct_read_header *drh;
	int ret;

    ethh = (struct rte_ether_hdr *)pkt;
    drh = (struct direct_read_header *)(ethh + 1);

	ret = chnk_ht_direct_insert(cht, drh->hv, drh->path);
#if SHOW_STATISTICS
	if (ret < 0) {
		g_stat[pc->lcore_id].numOffloadRT++;
	} else {
		g_stat[pc->lcore_id].numOffload++;
	}
#else
	UNUSED(ret);
#endif
	//log_info("lcore_id:%u, %lu\n", pc->lcore_id, drh->hv);
	//fprintf(stderr, "Offload %lu, ts:%lu\n", drh->hv, drh->ts);
    __generate_reply_packet(pc, port_id, drh->hv, drh->ts, REPLY_TYPE_OFFLOAD);
}

inline static void
__process_cache_item_eviction(pkt_ctrl *pc, uint16_t port_id, uint8_t *pkt, uint16_t pkt_len) {

    struct rte_ether_hdr *ethh;
    struct eviction_meta *emh;
	int ret;

    ethh = (struct rte_ether_hdr *)pkt;
    emh = (struct eviction_meta *)(ethh + 1);

	ret = chnk_ht_delete(cht, emh->e_hv);
#if SHOW_STATISTICS
	if (ret < 0) {
		g_stat[pc->lcore_id].numEvictRT++;
	} else {
		g_stat[pc->lcore_id].numEvict++;
	}
#else
	UNUSED(ret);
#endif
	//log_info("lcore_id:%u, %lu\n", pc->lcore_id, emh->e_hv);

    __generate_reply_packet(pc, port_id, emh->e_hv, emh->ts, REPLY_TYPE_EVICTION);
}

static __rte_always_inline __rte_hot uint16_t
__generate_cached_data_segment(pkt_ctrl *pc, uint16_t portid, uint8_t *nph, int nph_len, 
		struct rte_ether_addr *clnt_daddr, uint32_t tcp_seq, uint16_t payloadlen,
		blk *blk_start, off_t blk_off, blk **blk_end, off_t *blk_end_off)
{
	struct rte_mbuf *m, *payloadm, *prev;
	struct rte_ether_hdr *ethh;
	struct rte_ipv4_hdr *iph;
	struct rte_tcp_hdr *tcph;
	//rte_iova_t iova;
	uint32_t len, toSend;
	struct shinfo_ctx *ret_shinfo = NULL;
	blk *walk = blk_start;

	m = dpdk_get_wptr(pc->lcore_id, portid, nph_len);
	ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	iph = (struct rte_ipv4_hdr *)(ethh + 1);
	tcph = (struct rte_tcp_hdr *)(iph + 1);

	rte_memcpy(&ethh->src_addr, &src_addr[portid], sizeof(struct rte_ether_addr));
	rte_memcpy(&ethh->dst_addr, clnt_daddr, sizeof(struct rte_ether_addr));
	ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	rte_memcpy(iph, nph + sizeof(struct rte_ether_hdr), nph_len - sizeof(struct rte_ether_hdr));

	SET_TCP_OFFLOAD_FLAGS(m, tcph);

	//
	iph->hdr_checksum = 0;
	tcph->cksum = 0;

	prev = m;
#if SHOW_STATISTICS
#if SHOW_ONLY_GOODPUT
	g_stat[pc->lcore_id].totBytes += payloadlen;
#else
	g_stat[pc->lcore_id].totBytes += (payloadlen + nph_len);
#endif /* SHOW_ONLY_GOODPUT */
#endif /* SHOW_STATISTICS */
	g_nbu[pc->lcore_id].l1_cache += payloadlen; // (payloadlen + nph_len); //

#ifdef _GOODPUT
	g_goodput[pc->lcore_id].t_cache_now += payloadlen;
#endif

#ifdef _NOTIFYING_MBPS
	g_mbps[pc->lcore_id].t_cache_now += payloadlen;
#endif

	for (toSend = payloadlen; walk && toSend > 0; ) {

		if (unlikely(rte_mempool_get(pc->dpc->shinfo_pool, (void **)&ret_shinfo) < 0)) {
			rte_exit(EXIT_FAILURE, "Fail to get shinfo_ctx from MEMPOOL\n");
		}

		len = RTE_MIN(CACHE_BLOCK_SIZE - blk_off, toSend);

		ret_shinfo->shinfo.free_cb = ext_buf_free_callback_fn;
		ret_shinfo->shinfo.fcb_opaque = ret_shinfo;
		ret_shinfo->core_id = pc->lcore_id;
		rte_mbuf_ext_refcnt_set(&ret_shinfo->shinfo, 1);

		payloadm = rte_pktmbuf_alloc(pc->dpc->pktmbuf_pool);
		if (unlikely(!payloadm)) {
			rte_exit(EXIT_FAILURE,
					"Fail to allocate rte_mbuf for ext_buf (%s)\n", 
					rte_strerror(rte_errno)
					);
		}

		payloadm->nb_segs = 1;
		payloadm->next = NULL;
		prev->next = payloadm;

		m->pkt_len += (uint16_t)len;
		m->nb_segs++;

		prev = payloadm;

		rte_pktmbuf_attach_extbuf(payloadm, walk->data + blk_off, 
				walk->meta.b_iova + blk_off, len, &ret_shinfo->shinfo);
		rte_pktmbuf_reset_headroom(payloadm); 
		rte_pktmbuf_adj(payloadm, len); /* Is necessary ?*/

		payloadm->data_len = len;
		payloadm->data_off = 0;

		if (unlikely(payloadm->ol_flags != RTE_MBUF_F_EXTERNAL)) {
			rte_exit(EXIT_FAILURE,
					"Fail to attach external buffer\n");
		}

		if (blk_off + len == CACHE_BLOCK_SIZE)  /* Needs next block */
			blk_off = 0;
		else 
			blk_off += len;

		toSend -= len;
		if (toSend > 0)
			walk = walk->meta.b_next;

		LOG_PKTMBUF("(PAYLOADM) port=%u, seq=%u, data_len=%u\n", 
				rte_be_to_cpu_16(tcph->dst_port), tcp_seq, payloadm->data_len);
	}

	*blk_end = walk;
	*blk_end_off = blk_off;

	LOG_PKTMBUF("(HEAD) port=%u, seq=%u, tot_len=%u, nb_segs=%u\n", 
			rte_be_to_cpu_16(tcph->dst_port), tcp_seq, m->pkt_len, m->nb_segs);

	iph->total_length = rte_cpu_to_be_16(nph_len + payloadlen - sizeof(struct rte_ether_hdr));
	iph->type_of_service = 0;
	iph->hdr_checksum = 0;
	tcph->cksum = 0;
	tcph->sent_seq = rte_cpu_to_be_32(tcp_seq);
	//pc->pbytes += payloadlen; 

	return payloadlen;
}

static __rte_always_inline __rte_hot uint16_t 
__process_cache_meta(pkt_ctrl *pc, uint16_t port_id, uint8_t *pkt) {

	int32_t ret;
	uint32_t plen, max_plen, tlen, seq_start, seq_off;
	struct rte_ether_hdr *ethh = (struct rte_ether_hdr *)pkt;
	struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(ethh + 1);
	struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)(iph + 1);
	uint16_t hdr_len = sizeof(struct rte_ether_hdr) + 
					sizeof(struct rte_ipv4_hdr) + 
					GET_TCP_HDR_LEN(tcph);
	struct trans_meta *tmh = (struct trans_meta *)(pkt + hdr_len);
	off_t blk_off = 0, blk_end_off = 0;

	blk *pblk, *blk_end = NULL;

	ret = chnk_ht_get_blk(cht, tmh->t_hv, tmh->t_off, &pblk, &blk_off);
	if (ret < 0) {
		log_error("(%10s:%4d) Fail to find the object at hashtable, synchronization fails "
					"hv=%lu off=%lu, len=%u\n",
					__FILE__, __LINE__, tmh->t_hv, tmh->t_off, tmh->t_len);
	}

	max_plen = MAX_TSO_PACKET_SIZE - hdr_len;
	tlen = tmh->t_len;
	seq_start = rte_be_to_cpu_32(tcph->sent_seq);
	seq_off = 0;
	
	while (tlen > 0 && pblk) {
		plen = RTE_MIN(tlen, max_plen);
		ret = __generate_cached_data_segment(pc, port_id, pkt, hdr_len,
					&ethh->src_addr, seq_start + seq_off, plen,
					pblk, blk_off, &blk_end, &blk_end_off);

		INCR_PBYTES(ret + hdr_len);
		tlen -= ret;
		pblk = blk_end;
		seq_off += ret;
		blk_off = blk_end_off;

		dpdk_send_pkts(pc->lcore_id, port_id);
	}
	//usleep(50); 

	return hdr_len + sizeof(struct trans_meta);
}


#if ENABLE_RTT_CHECK
static __rte_always_inline void
__generate_rtt_echo_packet(pkt_ctrl *pc, uint16_t port_id, uint8_t *pkt) {

    struct rte_ether_hdr *ethh, *in_ethh = (struct rte_ether_hdr *)pkt;
    struct rte_ipv4_hdr *iph, *in_iph = (struct rte_ipv4_hdr *)(in_ethh + 1);
    struct rte_tcp_hdr *tcph, *in_tcph = (struct rte_tcp_hdr *)(in_iph + 1);
    struct rte_mbuf *m  = dpdk_get_wptr(pc->lcore_id, port_id,
            sizeof(struct rte_ether_hdr) +
            sizeof(struct rte_ipv4_hdr) +
            sizeof(struct rte_tcp_hdr) + GET_TCP_HDR_LEN(in_tcph));

    ethh = rte_pktmbuf_mtod(m ,struct rte_ether_hdr *);
    iph = (struct rte_ipv4_hdr *)(ethh + 1);
    tcph = (struct rte_tcp_hdr *)(iph + 1);

    rte_memcpy(ethh, pkt, m->pkt_len);
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 0)
    rte_memcpy(&ethh->s_addr, &src_addr[port_id], sizeof(struct rte_ether_addr));
    rte_memcpy(&ethh->d_addr, &host_addr, sizeof(struct rte_ether_addr));
#else
    rte_memcpy(&ethh->src_addr, &src_addr[port_id], sizeof(struct rte_ether_addr));
    rte_memcpy(&ethh->dst_addr, &host_addr, sizeof(struct rte_ether_addr));
#endif
    ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    iph->src_addr = in_iph->dst_addr;
    iph->dst_addr = in_iph->src_addr;
    iph->total_length = m->pkt_len - sizeof(struct rte_ether_hdr);
    iph->hdr_checksum = 0;
    iph->type_of_service = 0xfb;

    tcph->src_port = in_tcph->dst_port;
    tcph->dst_port = in_tcph->src_port;
    tcph->cksum = 0;
    m->l2_len = sizeof(struct rte_ether_hdr);
    m->l3_len = sizeof(struct rte_ipv4_hdr);
    m->l4_len = sizeof(struct rte_tcp_hdr); //GET_TCP_HDR_LEN(tcph);

#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 0)
    m->ol_flags = PKT_TX_IPV4 | PKT_TX_TCP_CKSUM | PKT_TX_IP_CKSUM;
#else
    m->ol_flags = RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
#endif
}
#endif /* ENABLE_RTT_CHECK */

static __rte_always_inline __rte_hot void
_forward_app_payload(pkt_ctrl *pc, uint16_t port_id, uint8_t *pkt, uint16_t pkt_len) {

	struct rte_ether_hdr *ethh, *in_ethh;
	struct rte_ipv4_hdr *iph;
	struct rte_tcp_hdr *tcph;
	struct rte_ether_addr tmp_addr;
	struct rte_mbuf *m;

	in_ethh = (struct rte_ether_hdr *)pkt;

	rte_memcpy(&tmp_addr, &in_ethh->src_addr, sizeof(struct rte_ether_addr));

	m = dpdk_get_wptr(pc->lcore_id, port_id, pkt_len);
	ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	iph = (struct rte_ipv4_hdr *)(ethh + 1);
	tcph = (struct rte_tcp_hdr *)(iph + 1);

	rte_memcpy(ethh, pkt, pkt_len);

	rte_memcpy(&ethh->src_addr, &src_addr[port_id], sizeof(struct rte_ether_addr));
	rte_memcpy(&ethh->dst_addr, &tmp_addr, sizeof(struct rte_ether_addr));

	SET_TCP_OFFLOAD_FLAGS(m, tcph);

	iph->type_of_service = 0;
	iph->hdr_checksum = 0;
	tcph->cksum = 0;

#if SHOW_STATISTICS
	g_stat[pc->lcore_id].numAppHdr++;
	g_stat[pc->lcore_id].appHdrBytes += pkt_len;
#endif
}

static __rte_always_inline __rte_hot void
__process_cache_data(pkt_ctrl *pc, uint16_t port_id, uint8_t *pkt, uint16_t pkt_len) {

	uint16_t mlen = 0;
#if ENABLE_META_CHANNEL
#define FLEX_CACHE_HDR_LEN (66 + sizeof(struct trans_meta))
	int num_bytes;
	ssize_t ret;
	size_t to_read = RTE_ALIGN_MUL_FLOOR(MAX_CHANNEL_BUF_SIZE, FLEX_CACHE_HDR_LEN);
	struct channel *chnnl = g_ch[pc->lcore_id];

	ret = ioctl(chnnl->sfd, FIONREAD, &num_bytes);
	if (ret < 0) {
		perror("ioctl");
		exit(EXIT_FAILURE);
	}

	if (num_bytes == 0 || num_bytes < FLEX_CACHE_HDR_LEN)
		return;

	num_bytes = RTE_MIN(num_bytes, MAX_CHANNEL_BUF_SIZE);
	to_read = RTE_ALIGN_MUL_FLOOR(num_bytes, FLEX_CACHE_HDR_LEN);
	ret = read(chnnl->sfd, chnnl->buf, to_read);
	if (ret == -1) {
		if (errno == EAGAIN) {
			return;
		} else {
			perror("read");
			exit(EXIT_FAILURE);
		}
	}

	pkt_len = (uint16_t)ret;
	pkt = chnnl->buf;
#endif /* ENABLE_META_CHANNEL */

#if ENABLE_RTT_CHECK && !ENABLE_META_CHANNEL
	uint8_t *__pkt = pkt;
	__generate_rtt_echo_packet(pc, port_id, __pkt);
#endif

#if ENABLE_APP_HDR_BATCH
	struct rte_ether_hdr *ethh;
	struct rte_ipv4_hdr *iph;

	for (; pkt_len > 0; pkt_len -= mlen) {
		ethh = (struct rte_ether_hdr *)pkt;
		iph = (struct rte_ipv4_hdr *)(ethh + 1);
		mlen = rte_be_to_cpu_16(iph->total_length) + sizeof(struct rte_ether_hdr);

		if (iph->type_of_service == 0xf0) {
			_forward_app_payload(pc, port_id, pkt, mlen);
		} else {
			__process_cache_meta(pc, port_id, pkt);
		}

		pkt += mlen;
#if SHOW_STATISTICS
		g_stat[pc->lcore_id].numMeta++;
#endif
	}
#else /* ENABLE_APP_HDR_BATCH */

	for (; pkt_len > 0; pkt_len -= mlen) {
		mlen = __process_cache_meta(pc, port_id, pkt);
		pkt += mlen;
#if SHOW_STATISTICS
		g_stat[pc->lcore_id].numMeta++;
#endif
	}
#endif /* ENABLE_APP_HDR_BATCH */
}

static __rte_always_inline __rte_hot void
process_ingress_packet(pkt_ctrl *pc, uint16_t port_id, 
		uint8_t *pkt, uint16_t pkt_len)
{
	struct rte_ether_hdr *ethh = (struct rte_ether_hdr *)pkt;
	uint16_t ether_type = rte_be_to_cpu_16(ethh->ether_type);

	if (ether_type == RTE_ETHER_TYPE_IPV4) {
		struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)(ethh + 1);
#if SHOW_STATISTICS
		g_stat[pc->lcore_id].rx_bytes += pkt_len;
#endif
#if ENABLE_FRD_OFFLOAD
		if (iph->type_of_service > 0 && iph->type_of_service < 4) { // 1, 2, or 3
			frd_offload_process(pc->fo, pc->ht, pc->lcore_id, port_id, pkt, pkt_len);
			return;
		}
#endif
		if (unlikely(memcmp(&ethh->dst_addr, &src_addr[port_id], 
						sizeof(struct rte_ether_addr)) != 0)) {
			return;
		}

#if ENABLE_APP_HDR_BATCH
		UNUSED(iph);
#else
		if (iph->type_of_service == 0xf0) {
			_forward_app_payload(pc, port_id, pkt, pkt_len);
			return;
		}
#endif

#if !ENABLE_META_CHANNEL
		__process_cache_data(pc, port_id, pkt, pkt_len);
#endif

	} else if (ether_type == ETYPE_OFFLOAD) {
		__process_cache_item_offload(pc, port_id, pkt, pkt_len);
	} else if (ether_type == ETYPE_EVICTION) {
		__process_cache_item_eviction(pc, port_id, pkt, pkt_len);
	} 
}

static pkt_ctrl *
pkt_ctrl_setup(uint16_t lcore_id) {

	int i, j, nb_ports;
	pkt_ctrl *pc;
	struct dpdk_private_context *dpc;

	nb_ports = rte_eth_dev_count_avail();

	pc = calloc(1, sizeof(pkt_ctrl));
	if (!pc) {
		log_error("Cannot allocate memory for pkt_ctrl context "
				"lcore_id=%u rte_errno=%u (%s)\n",
				lcore_id, rte_errno, rte_strerror(rte_errno));
		exit(EXIT_FAILURE);
	}
	g_pkt_ctrl[lcore_id] = pc;
	
	dpc = calloc(1, sizeof(struct dpdk_private_context));
	if (!dpc) 
		rte_exit(EXIT_FAILURE, "Cannot allocate for dpdk_private_context "
				"coreid=%u, rte_errno=%u (%s)\n",
				lcore_id, rte_errno, rte_strerror(rte_errno));
	g_dpc[lcore_id] = dpc;

	pc->lcore_id = lcore_id;
	pc->ready = false;
	pc->dpc = dpc;

#if ENABLE_FRD_OFFLOAD
	pc->ht = fht_create(FHT_NUM_ENTRIES, NUM_FILE_BUFFERS / d_CONFIG.ncpus * 2); //
	pc->fo = frd_offload_create(PER_CORE_MAX_WAITS);
#endif

	dpc->pktmbuf_pool = pktmbuf_pool[lcore_id];
	dpc->shinfo_pool = shinfo_pool[lcore_id];

	for (j = 0; j < nb_ports; j++) {
		for (i = 0; i < MAX_PKTS_BURST; i++) {
			dpc->wmbufs[j].m_table[i] = rte_pktmbuf_alloc(dpc->pktmbuf_pool);
			if (dpc->wmbufs[j].m_table[i] == NULL)
				rte_exit(EXIT_FAILURE,
						"[CPU %d] Cannot allocate memory for "
						"port %d wmbuf[%d]\n",
						lcore_id, j, i);
		}
		dpc->wmbufs[j].len = 0;
	}

	wait_for_siblings(pc);

	return pc;
}

static void
pkt_ctrl_end(pkt_ctrl *pc)
{
	uint16_t port;

#if ENABLE_FRD_OFFLOAD
	fht_destroy(pc->ht);
	frd_offload_destroy(pc->fo);
#endif

	RTE_ETH_FOREACH_DEV(port) {
		if (pc->dpc->rmbufs[port].len != 0) {
			dpdk_free_pkts(pc->dpc->rmbufs[port].m_table, pc->dpc->rmbufs[port].len);
			pc->dpc->rmbufs[port].len = 0;
		}
	}
}

static int
main_loop(void *arg)
{
	int i;
	uint64_t us_cur;
	uint16_t port;
	uint16_t recv_cnt, sent_cnt;
	uint16_t lcore_id = rte_lcore_id();
	pkt_ctrl *pc = pkt_ctrl_setup(lcore_id);
	uint8_t *pktbuf;
	uint16_t len;

	run[lcore_id] = true;

#if ENABLE_REPLY_BATCH
	meta_reply_setup(lcore_id);
#endif
	port = 0; //
	//log_info("Run main loop lcore_id:%u\n", lcore_id);
	for(;;) {
		//RTE_ETH_FOREACH_DEV(port) {
			us_cur = GetCurUs();

			recv_cnt = dpdk_recv_pkts(lcore_id, port);

#if SHOW_STATISTICS
			g_stat[lcore_id].numPkts += recv_cnt;
#endif

#if DEBUG_LATENCY || DEBUG_BOTTLENECK
			if (recv_cnt > 0) {
				struct timeval tv_now;
				gettimeofday(&tv_now, NULL);
				log_latency("[RECV] recv_cnt=%u timestamp=%u, "
						"timestamp_now=%u, diff=%u\n",
						recv_cnt, timestamp, TIMEVAL_TO_TS(&tv_now), 
						TIMEVAL_TO_TS(&tv_now) - timestamp);
				INCR_RX_PKTS(recv_cnt);
			}
#endif

			for (i = 0; i < recv_cnt; i++) {
				pktbuf = dpdk_get_rptr(lcore_id, port, i, &len);
				if (pktbuf != NULL) {
					process_ingress_packet(pc, port, pktbuf, len);
				}
			}
#if !ENABLE_SQ_POLL
			//frd_offload_submit(pc->fo);
#endif
			
#if ENABLE_FRD_OFFLOAD
			frd_offload_process_cqe(pc->lcore_id, port, pc->fo, pc->ht);
#endif

			rate_limit_notify(pc->lcore_id, port, us_cur);
#ifdef _GOODPUT
			rate_limit_notify_goodput(pc->lcore_id, port, us_cur);
#endif
#ifdef _NOTIFYING_MBPS
			rate_limit_notify_mbps(pc->lcore_id, port, us_cur);
#endif

			sent_cnt = dpdk_send_pkts(lcore_id, port);

#if DEBUG_LATENCY || DEBUG_BOTTLENECK
			if (sent_cnt > 0) {
				struct timeval tv_now;
				gettimeofday(&tv_now, NULL);
				log_latency("[SEND] sent_cnt=%u timestamp=%u, "
						"timestamp_now=%u, diff=%u\n", 
						sent_cnt, timestamp, TIMEVAL_TO_TS(&tv_now),
						TIMEVAL_TO_TS(&tv_now) - timestamp);
				INCR_RUN_TIME(GetCurUs() - us_cur);
				INCR_TX_PKTS(sent_cnt);
			}
#endif

#if ENABLE_META_CHANNEL
			__process_cache_data(pc, port, NULL, 0);
#endif

#if ENABLE_REPLY_BATCH
			meta_reply_flush(lcore_id, port);
#endif

			INCR_TOTAL_TIMES(GetCurUs() - us_cur);
#if RX_IDLE_ENABLE
			dpdk_select(lcore_id, port);
#endif
#if DEBUG_ETH_STATS
			dpdk_dump_eth_stats(port, pc->lcore_id, us_cur);
#endif

#if SHOW_FRD_OFFLOAD_STAT
			frd_offload_show_stat(pc->lcore_id, pc->fo);
#endif
		//}

		if (!run[lcore_id])
			break;
	}
#if ENABLE_REPLY_BATCH
	meta_reply_teardown(lcore_id);
#endif

	pkt_ctrl_end(pc);

	return 0;
}

static void
dataplane_setup(void) {

	int lcore_id;
	rte_srand(time(NULL));

#if DEBUG
	debug_setup();
#endif

#if SHOW_STATISTICS
#if SHOW_CMD_LOG
	fp_cmd_log = fopen("cmd.log", "w");
	if (!fp_cmd_log) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}
#endif
	pthread_t showStatThread;
	if (pthread_create(&showStatThread, NULL, ShowStatistics, NULL) != 0) {
		perror("Fail to create thread");
		exit(EXIT_FAILURE);
	}
#endif

	signal(SIGINT, signal_handler);

	dpdk_setup();
	cht = chnk_ht_create();
#if ENABLE_META_CHANNEL
	_construct_channel();
#endif

	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			break;
		}
	}
}

static void 
dataplane_destroy(void)
{
	int i;

	log_info(" Teardown nic_cache dataplane\n");
	log_info(" ------------------------------- \n");

	chnk_ht_teardown(cht);
	dpdk_teardown();
#if DEBUG
	debug_teardown();
#endif

	usleep(30);

	for (i = 0; i < MAX_CPUS; i++) {
		if (!g_pkt_ctrl[i])
			break;
		rte_mempool_free(g_pkt_ctrl[i]->dpc->pktmbuf_pool);
		rte_mempool_free(g_pkt_ctrl[i]->dpc->shinfo_pool);
	}

#if DEBUG_BOTTLENECK
	PrintPacketProcessedByDPU();
#endif

#if ENABLE_META_CHANNEL
	_destruct_channel();
#endif

#if SHOW_CMD_LOG && SHOW_STATISTICS
	printf("num_offload:%4lu(RT:%4lu), num_evict:%4lu(RT:%4lu)\n",
			g_stat[0].numOffload, g_stat[0].numOffloadRT,
			g_stat[0].numEvict, g_stat[0].numEvictRT);
	fclose(fp_cmd_log);
#endif
}

static void
signal_handler(int signo) {
	int i;
	for (i = 0; i < MAX_CPUS; i++)
		run[i] = false;
#if SHOW_STATISTICS
	showStat = false;
#endif
}

int
main(int argc, char *argv[]) {

	config_parse("./dataplane.cfg");	

	printf("-------------------------------------------- \n");
	printf(" Configuration completes \n");
	printf(" total cache memory size : %4.2lf(GB)\n", 
			d_CONFIG.tot_cache_mem_sz / (1024 * 1024 * 1024));
	printf(" Max number of items able to accomodate : %lu\n", d_CONFIG.max_nb_items);
	printf(" Hash Power : %d\n", d_CONFIG.hash_power);
	printf(" Number of CPUs to be used : %d\n", d_CONFIG.ncpus);
	printf("-------------------------------------------- \n");

	dataplane_setup();
	dataplane_destroy();
	config_free();

	return 0;
}
