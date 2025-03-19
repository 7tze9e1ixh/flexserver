#include "rate_limit.h"
#include "dataplane.h"
#include "dpdk_io.h"
#include "config.h"

#define RATE_LIMIT_GBPS(b) (((b) << 3) * SEC_TO_MSEC(1) / RATE_LIMIT_NOTIFY_PERIOD)

struct nic_bandwidth_usage g_nbu[MAX_CPUS] = {0};
//struct dataplane_goodput g_mbps[MAX_CPUS] = {0};

static struct nic_bandwidth_usage g_nbu_prev[MAX_CPUS] = {0};

uint64_t g_us_notify_prev;
#ifdef _NOTIFYING_MBPS
uint64_t g_us_notify_mbps;
#endif

void
rate_limit_setup(uint16_t lcore_id) {
	if (lcore_id != 0)
		return;
	g_us_notify_prev = GetCurUs();
#ifdef _NOTIFYING_MBPS
	g_us_notify_mbps = GetCurUs();
#endif
}

inline static void
___get_global_bandwidth_usage(struct nic_bandwidth_usage *nbu_now) {

	int i;
	uint64_t sum_l1_cache = 0, sum_frd_offload = 0,
			 sum_l1_cache_prev = 0, sum_frd_offload_prev = 0;

	for (i = 0; i < d_CONFIG.ncpus; i++) {
		sum_l1_cache += g_nbu[i].l1_cache;
		sum_l1_cache_prev += g_nbu_prev[i].l1_cache;
		sum_frd_offload += g_nbu[i].frd_offload;
		sum_frd_offload_prev += g_nbu_prev[i].frd_offload;
	}
	rte_memcpy(g_nbu_prev, g_nbu, sizeof(struct nic_bandwidth_usage) * d_CONFIG.ncpus);

	nbu_now->l1_cache = RATE_LIMIT_GBPS(sum_l1_cache - sum_l1_cache_prev);
	nbu_now->frd_offload = RATE_LIMIT_GBPS(sum_frd_offload - sum_frd_offload_prev);
}

inline void
rate_limit_notify(uint16_t lcore_id, uint16_t port_id, uint64_t us_now) {
	if (lcore_id != 0)
		return;
	if (USEC_TO_MSEC(us_now - g_us_notify_prev) >= RATE_LIMIT_NOTIFY_PERIOD) {
		struct rte_mbuf *m;
		struct rte_ether_hdr *ethh;
		struct nic_bandwidth_usage *nt, nt_now;
		g_us_notify_prev = us_now;

		___get_global_bandwidth_usage(&nt_now);

		m = dpdk_get_wptr(lcore_id, port_id, sizeof(struct rte_ether_hdr) + 
				sizeof(struct nic_bandwidth_usage));
		ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		rte_memcpy(&ethh->src_addr, &src_addr[port_id], sizeof(struct rte_ether_addr));
		rte_memcpy(&ethh->dst_addr, &host_addr, sizeof(struct rte_ether_addr));
		ethh->ether_type = rte_cpu_to_be_16(RATE_LIMIT_NIC_THROUGHPUT_INFORM_TYPE);
		nt = (struct nic_bandwidth_usage *)(ethh + 1);
		nt->l1_cache = nt_now.l1_cache;
		nt->frd_offload = nt_now.frd_offload;
	}
}

#ifdef _NOTIFYING_MBPS
inline void
rate_limit_notify_mbps(uint16_t lcore_id, uint16_t port_id, uint64_t us_now) {

	if (lcore_id != 2)
		return;

	if (us_now - g_us_notify_mbps >= RATE_LIMIT_NOTIFY_MBPS_PERIOD) {
		int i;
		struct rte_mbuf *m;
		struct rte_ether_hdr *ethh;
		struct nic_bandwidth_usage *nt;
		uint64_t sum_t_cache_now = 0, sum_t_cache_prev = 0,
				 sum_t_frd_now = 0, sum_t_frd_prev = 0;
		double l1_cache_gbps, frd_offload_gbps;

		g_us_notify_mbps = us_now;

		for (i = 0; i < MAX_CPUS; i++) {

			sum_t_cache_now += g_mbps[i].t_cache_now;
			sum_t_cache_prev += g_mbps[i].t_cache_prev;

			sum_t_frd_now += g_mbps[i].t_frd_now;
			sum_t_frd_prev += g_mbps[i].t_frd_prev;

			g_mbps[i].t_frd_prev = g_mbps[i].t_frd_now;
			g_mbps[i].t_cache_prev = g_mbps[i].t_cache_now;
		}

		m = dpdk_get_wptr(lcore_id, port_id, 
				sizeof(struct rte_ether_hdr) + sizeof(struct nic_bandwidth_usage));

		ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		rte_memcpy(&ethh->s_addr, &src_addr[port_id], sizeof(struct rte_ether_addr));
		rte_memcpy(&ethh->d_addr, &host_addr, sizeof(struct rte_ether_addr));
		ethh->ether_type = rte_cpu_to_be_16(RATE_LIMIT_NIC_NOTIFYING_MBPS_TYPE);
		nt = (struct nic_bandwidth_usage *)(ethh + 1);

		l1_cache_gbps = (double)((sum_t_cache_now - sum_t_cache_prev) * 8) * 1e+6 \
			/ RATE_LIMIT_NOTIFY_MBPS_PERIOD / (1e9);

		nt->l1_cache = (uint64_t)l1_cache_gbps;
		nt->frd_offload = 0;
		//fprintf(stderr, "@@@@@@@, %lu\n", nt->l1_cache);
	}
}
#endif

#ifdef _GOODPUT
#define RATE_LIMIT_GOODPUT_NOTIFY_PERIOD 1	// sec
#define RATE_LIMIT_GOODPUT_NOTIFY_CPU	 1

uint64_t g_us_notify_goodput = 0;

inline void
rate_limit_notify_goodput(uint16_t lcore_id, uint16_t port_id, uint64_t us_now) {

	if (lcore_id != RATE_LIMIT_GOODPUT_NOTIFY_CPU)
		return;

	if (USEC_TO_MSEC(us_now - g_us_notify_goodput) < SEC_TO_MSEC(RATE_LIMIT_GOODPUT_NOTIFY_PERIOD)) 
		return;

	int i;
	uint64_t sum_t_cache_now = 0, sum_t_cache_prev = 0,
			 sum_t_frd_now = 0, sum_t_frd_prev = 0;
	struct nic_bandwidth_usage *nt;
	struct rte_ether_hdr *ethh;
	struct rte_mbuf *m;

	g_us_notify_goodput = us_now;

	for (i = 0; i < MAX_CPUS; i++) {
		sum_t_cache_now += g_goodput[i].t_cache_now;
		sum_t_cache_prev += g_goodput[i].t_cache_prev;
		sum_t_frd_now += g_goodput[i].t_frd_now;
		sum_t_frd_prev += g_goodput[i].t_frd_prev;

		g_goodput[i].t_cache_prev = g_goodput[i].t_cache_now;
		g_goodput[i].t_frd_prev = g_goodput[i].t_frd_now;
	}

	m = dpdk_get_wptr(lcore_id, port_id, sizeof(struct rte_ether_hdr) + 
			sizeof(struct nic_bandwidth_usage));
	ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	rte_memcpy(&ethh->s_addr, &src_addr[port_id], sizeof(struct rte_ether_addr));
	rte_memcpy(&ethh->d_addr, &host_addr, sizeof(struct rte_ether_addr));
	ethh->ether_type = rte_cpu_to_be_16(RATE_LIMIT_NIC_GOODPUT_INFORM_TYPE);
	nt = (struct nic_bandwidth_usage *)(ethh + 1);
	nt->l1_cache = (sum_t_cache_now - sum_t_cache_prev) << 3;
	nt->frd_offload = (sum_t_frd_now - sum_t_frd_prev) << 3;
}
#endif /* _GOODPUT */
