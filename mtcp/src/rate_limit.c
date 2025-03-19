#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <pthread.h>

#include <rte_ether.h>
#include <rte_common.h>

#include "rate_limit.h"
#include "nic_cache.h"
#include "util.h"
#include "eth_out.h"
#include "debug.h"

#define RUN_TRACE_THREAD FALSE
#define DBG_RATE_LIMIT FALSE
#if DBG_RATE_LIMIT
#define TRACE_RATE_LIMIT(f, ...) fprintf(stderr, "(%10s:%4d)" f, __func__, __LINE__, ##__VA_ARGS__)
#else
#define TRACE_RATE_LIMIT(f, ...) (void)0
#endif

struct nic_throughput g_nic_throughput;
struct nic_throughput g_nic_goodput;
struct nic_throughput g_nic_mbps;

struct rate_limit_cache {
	uint64_t us_start;
	uint64_t *tx_bytes_ring;
	uint32_t ring_size;
};

const double g_allowed_nic_cache_send_bandwidth = (double)(200LU * 1024 * 1024 * 1024) / 8;
struct rate_limit_cache *g_rate_limit_cache[MAX_CPUS] = {NULL};

inline static uint32_t
__rate_limit_cache_get_tx_ring_index(struct rate_limit_cache *rlc, uint64_t ts_us) {
	uint64_t elapsed;
	if (ts_us - rlc->us_start)
		elapsed = UINT64_MAX - rlc->us_start + 1 + ts_us;
	else 
		elapsed = ts_us - rlc->us_start;
	return elapsed / RATE_LIMIT_CACHE_RING_GRANURALITY;
}

inline static uint64_t
__rate_limit_cache_get_bytes(int cpu, uint64_t us_now) {

	struct rate_limit_cache *rlc;
	uint32_t ring_index;
	uint64_t bytes;

	rlc = g_rate_limit_cache[cpu];
	ring_index = __rate_limit_cache_get_tx_ring_index(rlc, us_now);

	if (ring_index >= rlc->ring_size) {
		bzero(rlc->tx_bytes_ring, sizeof(uint64_t) * rlc->ring_size);
		rlc->us_start = us_now;
		bytes = 0;
	} else {
		bytes = rlc->tx_bytes_ring[ring_index];
	}

	return bytes;
}

#if RUN_TRACE_THREAD
static void *
__rate_limit_cache_trace_thread(void *arg) {

	FILE *cache_trace_file;
	uint64_t us_now, sum;
	double gbps;
	int i;

	cache_trace_file = fopen("cache_rate_limit.csv", "w");
	if (!cache_trace_file) {
		TRACE_ERROR("Fail to fopen cache_rate_limit, %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	set_thread_core_affinity(11);
	while (1) {

		usleep(RATE_LIMIT_CACHE_RING_GRANURALITY);
		sum = 0;
		us_now = get_cur_us();
		for (i = 0; i < CONFIG.num_cores; i++) 
			sum += __rate_limit_cache_get_bytes(i, us_now);

		gbps = (double)(sum) / RATE_LIMIT_CACHE_RING_GRANURALITY * 8 / (1000);

		fprintf(cache_trace_file, "%4.2lf\n", gbps);
		fflush(cache_trace_file);
	}

	fclose(cache_trace_file);
	assert(0);

	return NULL;
}
#endif

void
rate_limit_cache_setup(mtcp_manager_t mtcp) {

	struct rate_limit_cache *rlc;
	int i;

	rlc = calloc(1, sizeof(struct rate_limit_cache));
	if (!rlc) {
		TRACE_ERROR("Fail to allocate memory for rate_limit_cache, %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	rlc->us_start = get_cur_us();
	rlc->tx_bytes_ring = calloc(RATE_LIMIT_CACHE_TX_RING_SIZE, sizeof(uint64_t));
	if (!rlc->tx_bytes_ring) {
		TRACE_ERROR("Fail to allocate memory for tx_bytes_ring, %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	rlc->ring_size = RATE_LIMIT_CACHE_TX_RING_SIZE;

	g_rate_limit_cache[mtcp->ctx->cpu] = rlc;

#if RUN_TRACE_THREAD
	int ret;
	pthread_t trace_thread;

	ret = pthread_create(&trace_thread, NULL, __rate_limit_cache_trace_thread, NULL);
	if (ret != 0) {
		TRACE_ERROR("Fail to create __rate_limit_cache_trace_thread, %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#endif

	while (1) {
		int cnt = 0;
		for (i = 0; i < CONFIG.num_cores; i++) {
			if (g_rate_limit_cache[i])
				cnt++;
		}
		if (cnt == CONFIG.num_cores)
			break;
		usleep(10);
	}
}

void
rate_limit_cache_destroy(mtcp_manager_t mtcp) {
	struct rate_limit_cache *rlc;
	rlc = g_rate_limit_cache[mtcp->ctx->cpu];
	free(rlc);
}

inline void
rate_limit_update(mtcp_manager_t mtcp, void *pkt_data) {
	struct rte_ether_hdr *ethh = pkt_data;
	struct nic_throughput *nt = (struct nic_throughput *)(ethh + 1);
	g_nic_throughput.t_cache = nt->t_cache;
	g_nic_throughput.t_frd = nt->t_frd;
}

inline void
rate_limit_cache_update_mbps(mtcp_manager_t mtcp, void *pkt_data) {
	struct rte_ether_hdr *ethh = pkt_data;
	struct nic_throughput *nt = (struct nic_throughput *)(ethh + 1);
	g_nic_mbps.t_cache = nt->t_cache;
	g_nic_mbps.t_frd = nt->t_frd;
}

inline bool
rate_limit_cache_can_send_now(mtcp_manager_t mtcp, uint32_t plen) {

#if RATE_LIMIT_CACHE_ENABLE_NOTIFY_MBPS
	/*
	if (g_nic_mbps.t_cache > 0)
		TRACE_INFO("@@@@@@@ t_cache:%lu\n", g_nic_mbps.t_cache);*/

	if (g_nic_mbps.t_cache >= 80) {
		//TRACE_INFO("t_cache:%lu\n", g_nic_mbps.t_cache);
		return false;
	}
	return true;
#else

#if RUN_TRACE_THREAD
	uint32_t ring_index;
	uint64_t us_now;
	struct rate_limit_cache *rlc;

	rlc = g_rate_limit_cache[mtcp->ctx->cpu];
	us_now = get_cur_us();
	ring_index = __rate_limit_cache_get_tx_ring_index(rlc, us_now);

	if (ring_index >= rlc->ring_size) {
		bzero(rlc->tx_bytes_ring, sizeof(uint64_t) * rlc->ring_size);
		rlc->us_start = us_now;
		rlc->tx_bytes_ring[0] += plen;
	} else {
		rlc->tx_bytes_ring[ring_index] += plen;
	}

	return true;
#else
	int32_t i;
	uint32_t ring_index;
	uint64_t us_now, sum;
	struct rate_limit_cache *rlc;
	double Bps;
	sum = plen;
	rlc = g_rate_limit_cache[mtcp->ctx->cpu];
	us_now = get_cur_us();
	ring_index = __rate_limit_cache_get_tx_ring_index(rlc, us_now);

	for (i = 0; i < CONFIG.num_cores; i++) 
		sum += __rate_limit_cache_get_bytes(i, us_now);

	Bps = (double)(sum * 1000000) / RATE_LIMIT_CACHE_RING_GRANURALITY;

	if (Bps >= g_allowed_nic_cache_send_bandwidth) {
		TRACE_RATE_LIMIT("Bps:%4.2lf, Gbps:%4.2lf\n", Bps, (double)Bps / 8 / (1e9));
		return false;
	}

	if (ring_index >= rlc->ring_size)
		rlc->tx_bytes_ring[0] += plen;
	else 
		rlc->tx_bytes_ring[ring_index] += plen;

	return true;
#endif /* RUN_TRACE_THREAD */
#endif /* RATE_LIMIT_CACHE_ENABLE_NOTIFY_MBPS */
}

#ifdef _GOODPUT
struct nic_throughput g_nic_goodput = {0};

void
rate_limit_get_goodput(mtcp_manager_t mtcp, void *pkt_data) {
	struct rte_ether_hdr *ethh = pkt_data;
	struct nic_throughput *nt = (struct nic_throughput *)(ethh + 1);
	g_nic_goodput.t_cache = nt->t_cache;
	g_nic_goodput.t_frd = nt->t_frd;
}
#endif /* _GOODPUT */

