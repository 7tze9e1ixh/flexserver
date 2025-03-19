#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#include <rte_memcpy.h>
#include <rte_branch_prediction.h>

#include "mtcp.h"
#include "nic_cache.h"
#include "debug.h"
#include "config.h"
#include "rate_limit.h"

#ifdef _GOODPUT
struct global_goodput g_goodput[MAX_CPUS] = {0};
#endif

uint32_t g_ns_block_duration;
extern mtcp_manager_t g_mtcp_manager[];

#if DEBUG_SINGLE_FLOW
uint64_t g_dbg_port = 0;
uint32_t g_dbg_ts = 0;
uint32_t g_numCompl;
#endif

#if SHOW_PKTLOSS
uint64_t nb_fast_retransmission[MAX_CPUS] = {0};
uint64_t nb_timeout_retransmission[MAX_CPUS] = {0};
uint64_t nb_tot_pkts[MAX_CPUS] = {0};
#endif

#if ENABLE_NIC_CACHE_FUNC_CALL
bool is_control_plane_queue_empty[MAX_CPUS] = {false};
#endif

#if SHOW_ETH_STATS
extern void dpdk_show_eth_stats(uint16_t portid);
extern void dpdk_show_eth_xstats(uint16_t portid);
#endif

#if ENABLE_NIC_CACHE_FUNC_CALL
#include "control_plane.h"
#include "config.h"
#else
#include "control_plane_client.h"
#endif

#if DEBUG_HOST_BOTTLENECK
uint64_t pkt_proc_time = 0;
uint64_t tot_time = 0;
static void *MonitorWorkingTime(void *arg);
static bool start;

static void *
MonitorWorkingTime(void *arg) {

	FILE *fp;
	uint64_t pkt_proc_time_prev, tot_time_prev;
	struct timespec ts_now;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	start = false;

	if (pthread_mutex_init(&mutex, NULL) < 0) {
		perror("Fail to initiate mutex");
		exit(EXIT_FAILURE);
	}

	if (pthread_cond_init(&cond, NULL) < 0) {
		perror("Fail to initiate conditional variable");
		exit(EXIT_FAILURE);
	}

	if (!(fp = fopen("cpu_utilization.data", "w"))) {
		perror("Fail to open cpu_utilization.data");
		exit(EXIT_FAILURE);
	}

	do {
		usleep(5000);
	} while(!start);

	(void)arg;

	pkt_proc_time_prev = tot_time_prev = 0;
	pkt_proc_time = tot_time = 0;

	fprintf(stderr, "Start MonitorWorkingTime loop...\n");
	for(;;) {
		uint64_t diff_pkt_proc_time, diff_tot_time;
		double r_i, r_w;
		pthread_mutex_lock(&mutex);
		clock_gettime(CLOCK_REALTIME, &ts_now);
		ts_now.tv_sec++;
		pthread_cond_timedwait(&cond, &mutex, &ts_now);

		diff_pkt_proc_time = (pkt_proc_time - pkt_proc_time_prev) / 1000;
		diff_tot_time = (tot_time - tot_time_prev) / 1000;

		r_w = (double)diff_pkt_proc_time / diff_tot_time;
		r_i = 1 - r_w;

		fprintf(fp, "r_w=%10.2lf, r_i=%10.2lf(%lu, %lu)\n", r_w, r_i, 
				diff_pkt_proc_time, diff_tot_time);
		fflush(fp);

		pthread_mutex_unlock(&mutex);
	}

	pthread_mutex_destroy(&mutex);
	pthread_cond_destroy(&cond);

	return NULL;
}
#endif

#define NIC_CACHE_MAX_LOG_LEN (256)

unsigned char dpu_mac_address[6];

#if ENABLE_NIC_CACHE_FUNC_CALL
static bool is_pvt_init[MAX_CPUS] = {false};
#else
static cp_clnt **cpc[MAX_CPUS] = {NULL};
static size_t g_nb_chs;
#endif

#if DEBUG_NIC_CACHE
static FILE *nc_fp = NULL;
#endif

#if DEBUG_DPU_RTT && ENABLE_ECHO
static FILE *dpu_rtt_fp = NULL;
#endif

void
nic_cache_global_init(size_t nb_chs)
{
	int i;
	FILE *dst_addr_fp;
	char line[1024];
	char *saveptr, *p;
	
	remove("log/nic_cache_dump.log");
#if DEBUG_NIC_CACHE && !PRINT_NIC_CACHE_LOG
	nc_fp = fopen("log/nic_cache_dump.log", "w");
	if (!nc_fp) {
		perror("Fail to open file for nic_cache_log.dump");
		exit(EXIT_FAILURE);
	}
#endif

#if ENABLE_NIC_CACHE_FUNC_CALL
	control_plane_setup();
	UNUSED(nb_chs);
#else
	control_plane_client_setup(nb_chs);
	g_nb_chs = nb_chs;
#endif

	dst_addr_fp = fopen("config/dpu_macaddr.conf", "r");
	if (!dst_addr_fp) {
		perror("Fail to open file which contains mac address");
		exit(EXIT_FAILURE);
	}

	if (fgets(line, 1024, dst_addr_fp) == NULL) {
		fprintf(stderr, "(%10s:%4d) Fail to parse DPU Mac Address\n", __func__, __LINE__);
		exit(EXIT_FAILURE);
	}

	p = strtok_r(line, ":", &saveptr);
	dpu_mac_address[0] = (unsigned char)strtoul(p, NULL, 16);
	for (i = 1; i < 6; i++) { 
		p = strtok_r(NULL, ":", &saveptr);
		dpu_mac_address[i] = (unsigned char)strtoul(p, NULL, 16);
	}

#if ENABLE_ECHO && DEBUG_DPU_RTT
	dpu_rtt_fp = fopen("log/dpu_rtt.data", "w");
	if (!dpu_rtt_fp) {
		fprintf(stderr, "(%10s:%4d) Fail to open dpu_rtt.log\n", __func__, __LINE__);
		exit(EXIT_FAILURE);
	}
#endif

#if DEBUG_HOST_BOTTLENECK
	pthread_t m_tid;
	if (pthread_create(&m_tid, NULL, MonitorWorkingTime, NULL) != 0) {
		perror("Fail to create MonitorWorkingTime");
		exit(EXIT_FAILURE);
	}
#endif
}

void 
nic_cache_private_init(int cpu)
{
#if ENABLE_NIC_CACHE_FUNC_CALL
	int i;
	bool ready = false;
	if (cpu == MASTER_CPU) {
		control_plane_heat_dataplane();
	}
	is_pvt_init[cpu] = true;
	/* Wait for other thread setup */
	while (!ready) {
		for (i = 0; i < CONFIG.num_cores; i++) {
			ready = true;
			if (!is_pvt_init[i]) {
				usleep(1000);
				ready = false;
				break;
			}
		}
	}
#else
	size_t i;
	cpc[cpu] = calloc(g_nb_chs, sizeof(cp_clnt *));
	if (!cpc[cpu]) {
		perror("Fail to allocate memory for control plane client");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < g_nb_chs; i++) {
		cpc[cpu][i] = control_plane_client_get_ch();
	}
#endif
}

void
nic_cache_private_teradown(int cpu)
{
#if !ENABLE_NIC_CACHE_FUNC_CALL
	free(cpc[cpu]);
#endif
}

void
nic_cache_global_teardown(void)
{
#if ENABLE_NIC_CACHE_FUNC_CALL
	control_plane_teardown();
#else
	control_plane_client_teardown();
#endif
#if DEBUG_NIC_CACHE && PRINT_NIC_CACHE_LOG
	fclose(nc_fp);
#endif

#if ENABLE_ECHO && DEBUG_DPU_RTT
	fclose(dpu_rtt_fp);
#endif
}

inline int
nic_cache_get_obj_hv(int cpu, int stream_id, char *url, size_t url_len, 
					uint64_t *hv, uint32_t *sz,
					void **block_map, int *numBlocks)
{
#if ENABLE_NIC_CACHE_FUNC_CALL
	int core_index = cpu % control_plane_get_nb_cpus();
	(void)stream_id;

/*	if (cpu == 1) core_index = 0; 
	else core_index = 1;*/

	return control_plane_get_obj_hv(core_index, url, url_len, hv, sz, block_map, numBlocks);
#else
	return control_plane_client_get_obj_hv(cpc[cpu][stream_id], url, url_len, hv, sz);
#endif
}

inline int
nic_cache_free_obj_by_hv(int cpu, int stream_id, uint64_t hv)
{
#if ENABLE_NIC_CACHE_FUNC_CALL
	int core_index = cpu % control_plane_get_nb_cpus();
	(void)stream_id;
	return control_plane_free_obj_by_hv(core_index, hv);
#else
	return control_plane_client_free_obj_by_hv(cpc[cpu][stream_id], hv);
#endif
}

/* if buf->msb_head == NULL, this code does not run */

void
nic_cache_dump(char *fn, int line, char *log, ...)
{
	va_list ap;
	char dump_buf[NIC_CACHE_MAX_LOG_LEN];

	va_start(ap, log);
	vsprintf(dump_buf, log, ap);
	va_end(ap);
#if PRINT_NIC_CACHE_LOG && DEBUG_NIC_CACHE
	fprintf(stderr, "(%10s:%4d) %s", fn, line, dump_buf);
//	fflush(stderr);
#elif DEBUG_NIC_CACHE
	fprintf(nc_fp, "(%10s:%4d) %s", fn, line, dump_buf);
//	fflush(nc_fp);
#endif
}

#if ENABLE_ECHO && DEBUG_DPU_RTT
void
nic_cache_dump_dpu_rtt(uint32_t dpu_rtt)
{
	fprintf(dpu_rtt_fp, "%u\n", dpu_rtt);
}
#endif

inline uint64_t 
GetCurUs(void) {
	struct timespec ts_now;
	clock_gettime(CLOCK_REALTIME, &ts_now);
	return (ts_now.tv_sec * 1000000 + ts_now.tv_nsec / 1000);
}

#if DEBUG_HOST_BOTTLENECK
void
nic_cache_start_monitoring(void) {
	start = true;
}
#endif

#if ENABLE_NIC_CACHE_FUNC_CALL
void
nic_cache_mtcp_master_thread_ready(void) {
	control_plane_mtcp_master_thread_ready();
}
#endif

#if SHOW_NIC_CACHE_STATISTICS

#define PERIOD 1LU
//#define TO_GBPS(b) ((double)(b) * 8 / ((1024LU * 1024LU * 1024LU) * PERIOD))
#define TO_GBPS(b) ((double)(b) * 8 / 1000000000LU) //((1000LU * 1000LU * 1000LU) * PERIOD)
#define BYTE_TO_GBPS(b) ((double)(b) / 1000000000LU)
#define DIFF(s, t) ((s) - (t))
struct nic_cache_stat  g_nic_cache_stat[MAX_CPUS] = {0};

static void
__wait_mtcp_threads(void) {
	int i, cnt;

	while (1) {
		cnt = 0;
		for (i = 0; i < CONFIG.num_cores; i++) {
			if (g_mtcp_manager[i])
				cnt++;
		}

		if (cnt == CONFIG.num_cores)
			break;
	}
}

#if DBG_PACING
static FILE *pacing_interval;
static FILE *pacing_number;
static FILE *pacing_interval_gap;

static void
__debug_pacing_setup(void) {

	pacing_interval = fopen("pacing_interval.csv", "w");
	if (!pacing_interval) {
		perror("fopen()");
		exit(EXIT_FAILURE);
	}

	pacing_number = fopen("pacing_number.csv", "w");
	if (!pacing_number) {
		perror("fopen()");
		exit(EXIT_FAILURE);
	}

	pacing_interval_gap = fopen("pacing_interval_gap.csv", "w");
	if (!pacing_interval_gap) {
		perror("fopen()");
		exit(EXIT_FAILURE);
	}
}

static void
__print_pacing_info(void) {

	int i, j;
	uint64_t sumInt, sumGaps;

	for (i = 0; i < PACING_INT_ARR_SIZE; i++) {
		sumInt = 0, sumGaps = 0;
		for (j = 0; j < CONFIG.num_cores; j++) {
			sumInt += (g_nic_cache_stat[j].pacing_interval_now[i] - 
					g_nic_cache_stat[j].pacing_interval_prev[i]);
			g_nic_cache_stat[j].pacing_interval_now[i] = g_nic_cache_stat[j].pacing_interval_prev[i];

			sumGaps += (g_nic_cache_stat[j].pacing_interval_gap_now[i] -
					g_nic_cache_stat[j].pacing_interval_gap_prev[i]);
			g_nic_cache_stat[j].pacing_interval_gap_now[i] = 
				g_nic_cache_stat[j].pacing_interval_gap_prev[i];
		}

		if (i == PACING_INT_ARR_SIZE - 1) {
			fprintf(pacing_interval, "%lu\n", sumInt);
			fprintf(pacing_interval_gap, "%lu\n", sumGaps);
			break;
		}
		fprintf(pacing_interval, "%lu,", sumInt);
		fprintf(pacing_interval_gap, "%lu,", sumGaps);
	}

	uint64_t sumPaced = 0, sumPacedSend = 0 ;
	for (j = 0; j < CONFIG.num_cores; j++) {
		sumPaced += (g_nic_cache_stat[j].numPaced_now - g_nic_cache_stat[j].numPaced_prev);
		sumPacedSend += (g_nic_cache_stat[j].numPacedSend_now - 
				g_nic_cache_stat[j].numPacedSend_prev);
		g_nic_cache_stat[j].numPaced_now = g_nic_cache_stat[j].numPaced_prev;
		g_nic_cache_stat[j].numPacedSend_now = g_nic_cache_stat[j].numPacedSend_prev;
	}

	fprintf(pacing_number, "%lu,%lu(%4.2lf)\n", 
			sumPacedSend, sumPaced, (double)sumPacedSend / sumPaced);

	fflush(pacing_interval);
	fflush(pacing_number);
	fflush(pacing_interval_gap);
}
#endif

#if DBG_STARVATION
static FILE *last_sent_ts_fp;
static FILE *starved_reason_fp;
static FILE *failToSend_fp;

static void
__starvation_setup(void) {
	last_sent_ts_fp = fopen("last_sent_ts.csv", "w");
	if (!last_sent_ts_fp) {
		perror("fopen()");
		exit(EXIT_FAILURE);
	}

	starved_reason_fp = fopen("starved_reason.csv", "w");
	if (!starved_reason_fp) {
		perror("fopen()");
		exit(EXIT_FAILURE);
	}

	failToSend_fp = fopen("fail_to_send.csv", "w");
	if (!failToSend_fp) {
		perror("fopen()");
		exit(EXIT_FAILURE);
	}
}

static void
__print_starvation_log(void) {

	int i, j;
	uint64_t sum;
	uint64_t sum_numStarvedReason[STARVED_REASON_NUMBER] = {0};
	uint64_t sum_numFailToSend[STARVED_REASON_NUMBER] = {0};

	for (i = 0; i < LAST_SENT_TS_SIZE - 1; i++) {
		sum = 0;
		for (j = 0; j < CONFIG.num_cores; j++) {
			sum += (g_nic_cache_stat[j].last_sent_ts_now[i] - 
				g_nic_cache_stat[j].last_sent_ts_prev[i]);
			g_nic_cache_stat[j].last_sent_ts_prev[i] = g_nic_cache_stat[j].last_sent_ts_now[i];
		}
		fprintf(last_sent_ts_fp, "%lu,", sum);
	}

	for (i = 0; i < STARVED_REASON_NUMBER; i++) {
		for (j = 0; j < CONFIG.num_cores; j++) {
			sum_numStarvedReason[i] += (g_nic_cache_stat[j].numStarvedReasons_now[i] -
					g_nic_cache_stat[j].numStarvedReasons_prev[i]);
			g_nic_cache_stat[j].numStarvedReasons_prev[i] = 
				g_nic_cache_stat[j].numStarvedReasons_now[i];

			sum_numFailToSend[i] += (g_nic_cache_stat[j].numFailToSendReason_now[i] - 
					g_nic_cache_stat[j].numFailToSendReason_prev[i]);
			g_nic_cache_stat[j].numFailToSendReason_prev[i] = 
				g_nic_cache_stat[j].numFailToSendReason_now[i]; 
		}
	}

	for (i = 0; i < STARVED_REASON_NUMBER; i++) {
		if (i == STARVED_REASON_NUMBER - 1) {
			fprintf(starved_reason_fp, "%lu\n", sum_numStarvedReason[i]);
			break;
		}
		fprintf(starved_reason_fp, "%lu,", sum_numStarvedReason[i]);
	}


	for (i = 0; i < STARVED_REASON_NUMBER; i++) {
		if (i == STARVED_REASON_NUMBER - 1) {
			fprintf(failToSend_fp, "%lu\n", sum_numFailToSend[i]);
			break;
		}
		fprintf(failToSend_fp, "%lu,", sum_numFailToSend[i]);
	}

	sum = 0;

	for (j = 0; j < CONFIG.num_cores; j++) {
		sum += g_nic_cache_stat[j].last_sent_ts_now[LAST_SENT_TS_SIZE - 1] - 
			g_nic_cache_stat[j].last_sent_ts_prev[LAST_SENT_TS_SIZE - 1];
	}

	fprintf(last_sent_ts_fp, "%lu\n", sum);
}
#endif

#if DBG_RATE_LIMIT_STATUS
inline static void
__print_rate_limit_info(void) {

	int i;
	uint64_t sum = 0;
	for (i = 0; i < CONFIG.num_cores; i++) {
		sum += g_nic_cache_stat[i].numFailToSend_now - g_nic_cache_stat[i].numFailToSend_prev;
		g_nic_cache_stat[i].numFailToSend_prev = g_nic_cache_stat[i].numFailToSend_now;
	}
	fprintf(stdout, "# Rate limited:%8lu\n", sum);
}
#endif

#if DBG_DISK_STACK_STATUS
inline static void
__print_disk_stack_status(void) {
	int i;
	uint64_t sum_totLat = 0, sum_numIOs = 0, sum_numReadBytes = 0,
			 sum_numIOPendings = 0, sum_numIssueReq=0, sum_submitLatency=0;

	for (i = 0; i < CONFIG.num_cores; i++) {
		sum_totLat += (g_nic_cache_stat[i].totalLatency_now - 
			g_nic_cache_stat[i].totalLatency_prev);
		g_nic_cache_stat[i].totalLatency_prev = g_nic_cache_stat[i].totalLatency_now;

		sum_numIOs += (g_nic_cache_stat[i].numIOs_now - g_nic_cache_stat[i].numIOs_prev);
		g_nic_cache_stat[i].numIOs_prev = g_nic_cache_stat[i].numIOs_now;

		sum_numReadBytes += (g_nic_cache_stat[i].numReadBytes_now - 
				g_nic_cache_stat[i].numReadBytes_prev);
		g_nic_cache_stat[i].numReadBytes_prev = g_nic_cache_stat[i].numReadBytes_now;

		sum_numIOPendings += (g_nic_cache_stat[i].numIOPendings_now -
				g_nic_cache_stat[i].numIOPendings_prev);
		g_nic_cache_stat[i].numIOPendings_prev = g_nic_cache_stat[i].numIOPendings_now;

		sum_numIssueReq += (g_nic_cache_stat[i].numIssueReq_now - 
				g_nic_cache_stat[i].numIssueReq_prev);
		g_nic_cache_stat[i].numIssueReq_now = g_nic_cache_stat[i].numIssueReq_prev;

		sum_submitLatency += (g_nic_cache_stat[i].total_submit_latency_now -
				g_nic_cache_stat[i].total_submit_latency_prev);
		g_nic_cache_stat[i].total_submit_latency_now = g_nic_cache_stat[i].total_submit_latency_prev;
	}

	fprintf(stdout, "Average IO Latency : %4.2lf, Disk Read Throughput : %4.2lf "
			"Average IOPending : %4.2lf, Average Submit Latency:%4.2lf\n",
			(double)sum_totLat / sum_numIOs, 
			(double)(sum_numReadBytes << 3) / 1000000000LU / PERIOD,
			(double)sum_numIOPendings / PERIOD,
			(double)sum_submitLatency / sum_numIssueReq);
}
#endif

#if DBG_TX_STATUS
static void
__log_tx_status(void) {

	int i;
	uint64_t sumTotLat = 0, sumTotTxPkts = 0, sumFrdPkts = 0,
			 sumMetaPkts = 0, sumFuncCalls = 0;

	for (i = 0; i < CONFIG.num_cores; i++) {
		sumTotLat  += (g_nic_cache_stat[i].sumTxLatency_now - 
				g_nic_cache_stat[i].sumTxLatency_prev);
		g_nic_cache_stat[i].sumTxLatency_prev = g_nic_cache_stat[i].sumTxLatency_now;

		sumTotTxPkts += (g_nic_cache_stat[i].numTxPkts_now - g_nic_cache_stat[i].numTxPkts_prev);
		g_nic_cache_stat[i].numTxPkts_prev = g_nic_cache_stat[i].numTxPkts_now;

		sumMetaPkts += (g_nic_cache_stat[i].numMetaPkts_now - g_nic_cache_stat[i].numMetaPkts_prev);
		g_nic_cache_stat[i].numMetaPkts_prev = g_nic_cache_stat[i].numMetaPkts_now;

		sumFuncCalls += (g_nic_cache_stat[i].numTxFuncCalls_now - g_nic_cache_stat[i].numTxFuncCalls_prev);
		g_nic_cache_stat[i].numTxFuncCalls_prev = g_nic_cache_stat[i].numTxFuncCalls_now;

		sumFrdPkts += (g_nic_cache_stat[i].numFrdPkts_now - g_nic_cache_stat[i].numFrdPkts_prev);
		g_nic_cache_stat[i].numFrdPkts_prev = g_nic_cache_stat[i].numFrdPkts_now;
	}

	fprintf(stdout, "Average Latency:%4.2lf, Meta Pkts:%4.2lf/sec, "
			"Host Pkts:%4.2lf/sec, Total Pkts:%4.2lf/sec\n",
			(double)sumTotLat / sumFuncCalls, 
			(double)sumMetaPkts / PERIOD,
			(double)sumFrdPkts / PERIOD,
			(double)sumTotTxPkts / PERIOD);
}
#endif

//#ifdef ENABLE_RTT_CHECK
static double
__show_avg_meta_rtt(double *host_path_rtt, double *arm_path_rtt) {

	int i;
	double avg_rtt;
	uint64_t sum_meta_now = 0, sum_rtt_now = 0,
			 sum_meta_prev = 0, sum_rtt_prev = 0,
			 sum_meta_to = 0, sum_meta_to_prev = 0,
			 sum_meta_flush = 0, sum_meta_flush_prev = 0,
			 sum_arm_path_rtt = 0, sum_arm_path_rtt_prev = 0,
			 sum_num_arm_path = 0, sum_num_arm_path_prev = 0,
			 sum_host_path_rtt = 0, sum_host_path_rtt_prev = 0,
			 sum_num_host_path = 0, sum_num_host_path_prev = 0;

	for (i = 0; i < CONFIG.num_cores; i++) {
		sum_meta_now += g_nic_cache_stat[i].num_meta;
		sum_rtt_now += g_nic_cache_stat[i].meta_rtt;
		sum_meta_prev += g_nic_cache_stat[i].num_meta_prev;
		sum_rtt_prev += g_nic_cache_stat[i].meta_rtt_prev;

		sum_meta_to += g_nic_cache_stat[i].meta_to; 
		sum_meta_to_prev += g_nic_cache_stat[i].meta_to_prev;

		sum_meta_flush += g_nic_cache_stat[i].meta_flush;
		sum_meta_flush_prev += g_nic_cache_stat[i].meta_flush_prev;

		sum_host_path_rtt += g_nic_cache_stat[i].host_path_rtt;
		sum_host_path_rtt_prev += g_nic_cache_stat[i].host_path_rtt_prev;

		sum_num_host_path += g_nic_cache_stat[i].num_host_path;
		sum_num_host_path_prev += g_nic_cache_stat[i].num_host_path_prev;

		sum_arm_path_rtt += g_nic_cache_stat[i].arm_path_rtt;
		sum_arm_path_rtt_prev += g_nic_cache_stat[i].arm_path_rtt_prev;

		sum_num_arm_path += g_nic_cache_stat[i].num_arm_path;
		sum_num_arm_path_prev += g_nic_cache_stat[i].num_arm_path_prev;
#if 0
		printf("[CPU%d] : meta_to:%4lu, meta_flush:%4lu\n", 
				i, g_nic_cache_stat[i].meta_to - g_nic_cache_stat[i].meta_to_prev,
				g_nic_cache_stat[i].meta_flush - g_nic_cache_stat[i].meta_flush_prev);
#endif

		g_nic_cache_stat[i].num_meta_prev = g_nic_cache_stat[i].num_meta;
		g_nic_cache_stat[i].meta_rtt_prev = g_nic_cache_stat[i].meta_rtt;

		g_nic_cache_stat[i].meta_to_prev = g_nic_cache_stat[i].meta_to;
		g_nic_cache_stat[i].meta_flush_prev = g_nic_cache_stat[i].meta_flush;

		g_nic_cache_stat[i].host_path_rtt_prev = g_nic_cache_stat[i].host_path_rtt;
		g_nic_cache_stat[i].arm_path_rtt_prev = g_nic_cache_stat[i].arm_path_rtt;

		g_nic_cache_stat[i].num_host_path = g_nic_cache_stat[i].num_host_path_prev;
		g_nic_cache_stat[i].num_arm_path = g_nic_cache_stat[i].num_arm_path_prev;
	}
	avg_rtt = (double)(sum_rtt_now - sum_rtt_prev) / (sum_meta_now - sum_meta_prev) / 1000;

	printf("Average meta rtt : %4.2lfms, meta_to:%4lu(%4.2lf), meta_flush:%4lu\n", 
			avg_rtt, sum_meta_to - sum_meta_to_prev,  
			(double)(sum_meta_to - sum_meta_to_prev) / (sum_meta_flush - sum_meta_flush_prev),
			sum_meta_flush - sum_meta_flush_prev);

	*host_path_rtt = (double)(sum_host_path_rtt - sum_host_path_rtt_prev) / (sum_num_host_path - sum_num_host_path_prev);
	*arm_path_rtt = (double)(sum_arm_path_rtt - sum_arm_path_rtt_prev) / (sum_num_arm_path - sum_num_arm_path_prev);

	printf("Average Host Path Rtt : %4.2lfms, Average ARM Path Rtt : %4.2lf\n", 
			*host_path_rtt, *arm_path_rtt);

	return avg_rtt;
}
//#endif

#include "frd_rate_limit.h"

#ifdef _GOODPUT
static FILE *fp_goodput = NULL;
//struct global_goodput g_goodput[MAX_CPUS] = {0};

static void 
__dump_goodput(void) {

	int i;
	uint64_t sum_t_general = 0,
			 sum_t_l2_cache = 0,
			 sum_t_nvmes = 0;

	for (i = 0; i < CONFIG.num_cores; i++) {
		sum_t_general += (g_goodput[i].t_general_now - g_goodput[i].t_general_prev);
		g_goodput[i].t_general_prev = g_goodput[i].t_general_now;

		sum_t_l2_cache += (g_goodput[i].t_l2_cache_now - g_goodput[i].t_l2_cache_prev);
		g_goodput[i].t_l2_cache_prev = g_goodput[i].t_l2_cache_now;

		sum_t_nvmes += (g_goodput[i].t_nvmes_now - g_goodput[i].t_nvmes_prev);
		g_goodput[i].t_nvmes_prev = g_goodput[i].t_nvmes_now;
	}

	fprintf(fp_goodput,
			"%8.2lf,%8.2lf,%8.2lf,%8.2lf,%8.2lf\n",
			BYTE_TO_GBPS(g_nic_goodput.t_cache), 
			BYTE_TO_GBPS(g_nic_goodput.t_frd),
			TO_GBPS(sum_t_general),
			TO_GBPS(sum_t_l2_cache),
			TO_GBPS(sum_t_nvmes));
	fflush(fp_goodput);
}
#endif

static void *
NICCacheShowStatistics(void *arg) {

	int i, j;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	struct timespec ts_now;
	uint16_t totalFlows;
	struct nic_cache_stat nic_cache_stat_prev[MAX_CPUS] = {0};
	double total_gbps, host_gbps, nic_gbps, l2cache_gbps, disk_read_gbps, nic_frd_gbps;
	double r_l1cache, r_l2cache, r_diskRead;
	uint64_t sum_nvmeReqs[NUM_NVME];
	uint64_t sum_nvmeReqs_prev[NUM_NVME] = {0};

	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);

	__wait_mtcp_threads();
	control_plane_wait_for_heat_dataplane();

#if DBG_STARVATION
	__starvation_setup();
#endif

#if DBG_PACING
	__debug_pacing_setup();
#endif

#ifdef _GOODPUT
	fp_goodput = fopen("goodput.csv", "w");
	if (!fp_goodput) {
		perror("Fail to open goodput.csv");
		exit(EXIT_FAILURE);
	}
	fprintf(fp_goodput, "%8s,%8s,%8s,%8s,%8s\n",
			"L1_CACHE","FRD_OFFLOAD", "GENERAL", "L2_CAHCE", "FRD");
#endif

	FILE *fp_flexserver;
	fp_flexserver = fopen("flexserver.csv", "w");
	if (!fp_flexserver) {
		perror("Fail to open goodput.csv");
		exit(EXIT_FAILURE);
	}

	while (1) {
		uint64_t sumTotTX = 0, sum_L1_reqs = 0, sum_L2_reqs = 0, sum_host_reqs = 0;
		double  sum_l2_cache_gbps = 0, sum_host_gbps = 0;
		double r_L1_total = 0;
		pthread_mutex_lock(&mutex);

		clock_gettime(CLOCK_REALTIME, &ts_now);
		ts_now.tv_sec += PERIOD;

		pthread_cond_timedwait(&cond, &mutex, &ts_now);
		//sumTXBytes = sumL1Hit = sumL2Hit = sumDiskRead = 0;
#if 1
		fprintf(stdout, "-----------------------------------------------------------"
				"-------------------------------------------------------------------"
				"----------------------\n");
#endif
		totalFlows = 0;
#if DBG_STARVATION
		__print_starvation_log();
#endif

#if DBG_PACING
		__print_pacing_info();
#endif
		bzero(sum_nvmeReqs, sizeof(uint64_t) * NUM_NVME);

		for (i = 0; i < CONFIG.num_cores; i++) {
			total_gbps = TO_GBPS(DIFF(g_nic_cache_stat[i].tx_bytes,
					nic_cache_stat_prev[i].tx_bytes));
			l2cache_gbps = TO_GBPS(DIFF(g_nic_cache_stat[i].tx_l2cache,
						nic_cache_stat_prev[i].tx_l2cache));
			disk_read_gbps = TO_GBPS(DIFF(g_nic_cache_stat[i].tx_diskRead,
						nic_cache_stat_prev[i].tx_diskRead));

			r_l1cache = (double)DIFF(g_nic_cache_stat[i].numL1Hits, nic_cache_stat_prev[i].numL1Hits) / 
				DIFF(g_nic_cache_stat[i].numReqs, nic_cache_stat_prev[i].numReqs);

			r_l2cache = (double)DIFF(g_nic_cache_stat[i].numL2Hits, nic_cache_stat_prev[i].numL2Hits) / 
				DIFF(g_nic_cache_stat[i].numReqs, nic_cache_stat_prev[i].numReqs);

			r_diskRead = (double)DIFF(g_nic_cache_stat[i].numDiskReads, nic_cache_stat_prev[i].numDiskReads) /
				DIFF(g_nic_cache_stat[i].numReqs, nic_cache_stat_prev[i].numReqs);

			sum_l2_cache_gbps += l2cache_gbps;
			sum_host_gbps += disk_read_gbps;

			sum_L1_reqs += DIFF(g_nic_cache_stat[i].numL1Hits, nic_cache_stat_prev[i].numL1Hits);
			sum_L2_reqs += DIFF(g_nic_cache_stat[i].numL2Hits, nic_cache_stat_prev[i].numL2Hits);
			sum_host_reqs += DIFF(g_nic_cache_stat[i].numReqs, nic_cache_stat_prev[i].numReqs);

#if !SHOW_PER_CORE_STATUS
			UNUSED(r_diskRead);
			UNUSED(r_l1cache);
			UNUSED(r_l2cache);
			UNUSED(disk_read_gbps);
			UNUSED(l2cache_gbps);
			UNUSED(total_gbps);
#else
			fprintf(stdout, "(CPU%d) RTO : %-6lu, "
					"DUP_ACK : %-6lu, "
					"FastRetransmission : %-6lu, "
					"TX : %-6.2lf(gbps), "
					"TX(L2Cache) : %-6.2lf(gbps), "
					"TX(DISK READ) : %6.2lf(gbps), "
					"TOT_REQS : %-6lu, "
					"L1_HIT : %-6lu(%6lu) (%-6.2lf), "
					"L2_HIT : %-6lu(%6lu) (%-6.2lf), "
					"DISK READ : %-6lu (%-6.2lf) "
					"# flows : %-6u \n",
					i,
					(g_nic_cache_stat[i].numRTOs - nic_cache_stat_prev[i].numRTOs) / PERIOD,
					(g_nic_cache_stat[i].numDUPAcks - nic_cache_stat_prev[i].numDUPAcks) / PERIOD,
					(g_nic_cache_stat[i].numFastRetransmissions - 
						 nic_cache_stat_prev[i].numFastRetransmissions) / PERIOD,
					total_gbps,
					l2cache_gbps,
					disk_read_gbps,
					(g_nic_cache_stat[i].numReqs - nic_cache_stat_prev[i].numReqs),
					(g_nic_cache_stat[i].numL1Hits - nic_cache_stat_prev[i].numL1Hits),
					g_nic_cache_stat[i].numL1Hits,
					r_l1cache,
					(g_nic_cache_stat[i].numL2Hits - nic_cache_stat_prev[i].numL2Hits),
					g_nic_cache_stat[i].numL2Hits,
					r_l2cache,
					(g_nic_cache_stat[i].numDiskReads - nic_cache_stat_prev[i].numDiskReads),
					r_diskRead,
					g_mtcp_manager[i]->flow_cnt);
#endif

			sumTotTX += DIFF(g_nic_cache_stat[i].tx_bytes, 
					nic_cache_stat_prev[i].tx_bytes);
			totalFlows += g_mtcp_manager[i]->flow_cnt;

			for (j = 0; j < NUM_NVME; j++)
				sum_nvmeReqs[j] += g_nic_cache_stat[i].num_nvmeReqs[j];
		}

#if SHOW_ETH_STATS
		for (i = 0; i < CONFIG.eths_num; i++) {
			dpdk_show_eth_stats(i);
		}
#endif

#ifdef _GOODPUT
		__dump_goodput();
#endif

//#ifdef ENABLE_RTT_CHECK
		double arm_path_rtt, host_path_rtt;
		__show_avg_meta_rtt(&host_path_rtt, &arm_path_rtt);
//#endif

#if SHOW_NUM_REQS_PER_NVME
		for (i = 0; i < NUM_NVME; i++) {
			fprintf(stdout, "nvme%d : %lu(%lu/%lusec)", 
					i, sum_nvmeReqs[i], sum_nvmeReqs[i] - sum_nvmeReqs_prev[i], PERIOD);
			sum_nvmeReqs_prev[i] = sum_nvmeReqs[i];
		}
		fprintf(stdout, "\n");
#else
		UNUSED(sum_nvmeReqs_prev);
#endif /* SHOW_NUM_REQS_PER_NVME */

#if DBG_RATE_LIMIT_STATUS
		__print_rate_limit_info();
#endif

#if DBG_DISK_STACK_STATUS
		__print_disk_stack_status();
#endif

#if DBG_TX_STATUS
		__log_tx_status();
#endif

		host_gbps = TO_GBPS(sumTotTX);
		nic_gbps = BYTE_TO_GBPS(g_nic_throughput.t_cache);
		nic_frd_gbps = BYTE_TO_GBPS(g_nic_throughput.t_frd);
		fprintf(stdout, "Host/Snic TX:%-6.2lf/%-6.2lf(gbps), Sum TX:%-6.2lf(gbps), total flows:%-6u, hr:%6.2lf\n", 
				host_gbps, nic_gbps, host_gbps + nic_gbps, totalFlows,
				r_L1_total / CONFIG.num_cores);

#if DUMP_FLEXSERVER
		fprintf(fp_flexserver, "%4.2lf,%4.2lf,%4.2lf,%4.2lf,"
				"%4.2lf, %4.2lf,"
				"%4.2lu,%4.2lu,%4.2lu\n",
				sum_host_gbps, nic_gbps, sum_l2_cache_gbps, nic_frd_gbps,
				host_path_rtt, arm_path_rtt,
				sum_L1_reqs, sum_L2_reqs, sum_host_reqs);
#endif

		memcpy(nic_cache_stat_prev, g_nic_cache_stat, 
				sizeof(struct nic_cache_stat) * MAX_CPUS);

		pthread_mutex_unlock(&mutex);
	}

	return NULL;

}

void 
nic_cache_show_statistics(void) {

	pthread_t showStatThread;

	if (pthread_create(&showStatThread, NULL, NICCacheShowStatistics, NULL) != 0) {
		perror("Fail to create thread");
		exit(EXIT_FAILURE);
	}
}

#endif
