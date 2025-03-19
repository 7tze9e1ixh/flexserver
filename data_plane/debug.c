#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>

#include <rte_branch_prediction.h>

#include "debug.h"
#include "log.h"
#include "config.h"

#define DEBUG_LOG_BUF_SIZE	(256)
#define DUMP_PKTMBUF_BUF_SZ (1024)

static FILE *log_fp = NULL;
const static char log_filename[] = "nic_cache.log";

#if DEBUG_ETH_STATS
struct rte_eth_stats g_stats;
#endif

#if COLLECT_PACKET_PROCESS_TIME
uint64_t g_ptime[COLLECTING_INTERVAL] = {0};
uint64_t g_pint[COLLECTING_INTERVAL] = {0};
uint64_t g_pbyte_kb[COLLECTING_INTERVAL] = {0};
uint64_t g_per_pkt_proc_time[COLLECTING_INTERVAL] = {0};
uint64_t g_btime[COLLECTING_INTERVAL] = {0};
uint64_t g_tx_pkt_sz[COLLECTING_INTERVAL] = {0};
#endif

#if DEBUG_BOTTLENECK
static uint64_t dpu_start_time = 0;
static uint64_t tot_time[MAX_CPUS] = {0};
static uint64_t run_time[MAX_CPUS] = {0};
static uint64_t tx_pkts[MAX_CPUS] = {0};
static uint64_t rx_pkts[MAX_CPUS] = {0};
#endif

#if DEBUG_PACKET_SYNTHESIZATION
static FILE *pktmbuf_dump_fp = NULL;
const static char pktmbuf_dump_filename[] = "pktmbuf_dump.log";
#endif

#if CAL_PKT_PROC_TIME
uint64_t tot_pkt_proc_time = 0;
uint64_t tot_pbytes = 0;
uint64_t tot_times = 0;
#endif

void 
debug_setup(void) {
	log_fp = fopen(log_filename, "w");
	if (!log_fp) {
		perror("Fail to open nic_cache.log file");
		exit(EXIT_FAILURE);
	}
#if DEBUG_ETH_STATS
	memset(&g_stats, 0, sizeof(struct rte_eth_stats));
#endif

#if DEBUG_PACKET_SYNTHESIZATION
	pktmbuf_dump_fp = fopen(pktmbuf_dump_filename, "w");
	if (!pktmbuf_dump_fp) {
		perror("Fail to open pktmbuf_dump.log");
		exit(EXIT_FAILURE);
	}
#endif

#if USE_LOG_BUF
	log_buf_global_init(d_CONFIG.ncpus);
#endif
	//rte_log_set_level_pattern(log_pattern[0], RTE_LOG_INFO);
	//rte_log_set_level_regexp(log_pattern[0], RTE_LOG_INFO);
#if DEBUG_BOTTLENECK
	dpu_start_time = GetCurUs();
#endif
}

void 
debug_teardown(void) {
	fclose(log_fp);
	fprintf(stderr, "Destroy Log Buf\n");
#if DEBUG
	int i;
	log_buf_global_destroy();
#endif
	fprintf(stderr, "Complete Destroy Log Buffer\n");

#if CAL_PKT_PROC_TIME
	double per_pkt_proc_time;
	double r_i, r_w;

	fprintf(stderr, "--- Packet Processing Information --- \n");
	fprintf(stderr, "tot_pbytes=%lu\n", tot_pbytes);
	fprintf(stderr, "tot_pkt_proc_time=%lu\n", tot_pkt_proc_time);
	per_pkt_proc_time = (double)tot_pkt_proc_time / ((double)tot_pbytes / TO_NET_MTU);
	fprintf(stderr, "Per Packet Processing Time = %10.4f(us)\n", per_pkt_proc_time);
	r_i = (double)tot_pkt_proc_time / tot_times;
	r_w = 1 - r_i;
	fprintf(stderr, "r_i=%10.4f, r_w=%10.4f\n", r_w, r_i);
#endif /* CAL_PKT_PROC_TIME */

#if DEBUG_ETH_STATS
	fprintf(stderr, "ETH STATS WHILE DATAPLAE RUN\n");
	fprintf(stderr, "ipackets = %lu\n", g_stats.ipackets);
	fprintf(stderr, "opackets = %lu\n", g_stats.opackets);
	fprintf(stderr, "ibytes = %lu\n", g_stats.ibytes);
	fprintf(stderr, "obytes = %lu\n", g_stats.obytes);
	fprintf(stderr, "imissed = %lu\n", g_stats.imissed);
	fprintf(stderr, "ierrors = %lu\n", g_stats.ierrors);
	fprintf(stderr, "oerrors = %lu\n", g_stats.oerrors);
	fprintf(stderr, "rx_nombuf = %lu\n", g_stats.rx_nombuf);
#endif

#if COLLECT_PACKET_PROCESS_TIME
#define PACKET_PROCESS_TIME_FILE_NAME "packet_process_time.csv"
#define PBYTES_KB_FILE_NAME "pbytes_kb.csv"
#define PINT_FILE_NAME "pint.csv"
#define PER_PKT_PTIME "ptime.csv"
#define BLOCKING_TIME "btime.csv"
#define PKT_SZ "pkt_sz.csv"

	FILE *fp = fopen(PACKET_PROCESS_TIME_FILE_NAME, "w");
	if (!fp) {
		log_error("Fail to open %s\n", PACKET_PROCESS_TIME_FILE_NAME);
		return;
	}

	for (i = 0; i < COLLECTING_INTERVAL; i++) {
		fprintf(fp, "%lu,", g_ptime[i]);
	}
	fclose(fp);

	fp = fopen(PBYTES_KB_FILE_NAME, "w");
	if (!fp) {
		log_error("Fail to open %s\n", PBYTES_KB_FILE_NAME);
		return;
	}
	for (i = 0; i < COLLECTING_INTERVAL; i++) {
		fprintf(fp, "%lu,", g_pbyte_kb[i]);
	}

	fclose(fp);

	fp = fopen(PINT_FILE_NAME, "w");
	if (!fp) {
		log_error("Fail to open %s\n", PINT_FILE_NAME);
		return;
	}
	for (i = 0; i < COLLECTING_INTERVAL; i++) {
		fprintf(fp, "%lu,", g_pint[i]);
	}
	fclose(fp);

	fp = fopen(PER_PKT_PTIME, "w");
	if (!fp) {
		log_error("Fail to open %s\n", PER_PKT_PTIME);
		return;
	}
	for (i = 0; i < COLLECTING_INTERVAL; i++) {
		fprintf(fp, "%lu,", g_per_pkt_proc_time[i]);
	}
	fclose(fp);

	fp = fopen(BLOCKING_TIME, "w");
	if (!fp) {
		log_error("Fail to open %s\n", BLOCKING_TIME);
		return;
	}
	for (i = 0; i < COLLECTING_INTERVAL; i++) {
		fprintf(fp, "%lu,", g_btime[i]);
	}

	fp = fopen(PKT_SZ, "w");
	if (!fp) {
		log_error("Fail to open %s\n", PKT_SZ);
		return;
	}

	for (i = 0; i < COLLECTING_INTERVAL; i++) {
		fprintf(fp, "%lu,", g_tx_pkt_sz[i]);
	}
#endif
}

void 
debug_log(char *f_nm, int line, char *log, ...) {

	char debug_log_buf[DEBUG_LOG_BUF_SIZE];
	size_t log_len = 0;
	int ret;
	va_list ap;
	struct tm *tm_now;
	time_t time_now = time(NULL);
	tm_now = localtime(&time_now);
	if (unlikely(strlen(log) + 1 > DEBUG_LOG_BUF_SIZE)) {
		log_error("Too wrong log %c\n", ' ');
		return;
	} 

	if (f_nm && line > 0) {
		ret = sprintf(debug_log_buf, "(%02d-%02d-%02d %10s:%4d) ", 
				tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec, f_nm, line);
		if (ret < 0)
			return;
		log_len += ret;
	}

	va_start(ap, log);
	ret = vsprintf(debug_log_buf + log_len, log, ap);
	va_end(ap);
	if (ret < 0) 
		return;
	log_len += ret;
#if USE_LOG_BUF
	log_buf_write(debug_log_buf, log_len + 1);
#else
	fprintf(log_fp, "(%02d-%02d-%02d %10s:%4d) %s",
				tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec, f_nm, line,
				debug_log_buf);
	fflush(log_fp);
#endif
}

void 
dump_pktmbuf(struct rte_mbuf *m, char *log, ...) {
	/*
#if DEBUG_PACKET_SYNTHESIZATION
	char dump_pktmbuf_temp_buf[DUMP_PKTMBUF_BUF_SZ];
	va_list ap;
	va_start(ap, log);
	vsprintf(dump_pktmbuf_temp_buf, log, ap);
	va_end(ap);

	fprintf(pktmbuf_dump_fp, 
			"---------------------------------------------------\n"
			"Dump rte_mbuf (%p)\n"
			"%s"
			"buf_addr=%p, refcnt=%u, nb_segs=%u, port=%u, ol_flags=%lu, pkt_len=%u, data_len=%u\n",
			m, dump_pktmbuf_temp_buf, 
			m->buf_addr, m->refcnt, m->nb_segs, m->port, m->ol_flags, m->pkt_len, m->data_len
	);
	fflush(pktmbuf_dump_fp);
#else */
	return;
//#endif
}

#if DEBUG_BOTTLENECK
inline void 
incr_tot_time(uint64_t t) {
	uint16_t lcore_id = rte_lcore_id();
	tot_time[lcore_id] += t;
}

inline void
incr_run_time(uint64_t t) {
	uint16_t lcore_id = rte_lcore_id();
	run_time[lcore_id] += t;
}

inline void
incr_rx_pkts(uint64_t n) {
	uint16_t lcore_id = rte_lcore_id();
	rx_pkts[lcore_id] += n;
}

inline void
incr_tx_pkts(uint64_t n) {
	uint16_t lcore_id = rte_lcore_id();
	tx_pkts[lcore_id] += n;
}

void
PrintPacketProcessedByDPU(void) {
	int i;
	uint64_t cur_us = GetCurUs();
	uint64_t t_diff = (cur_us - dpu_start_time) / (1000000);
	uint64_t sum_x = 0, sum_y = 0;
	float run_ratio, idle_ratio;

	for (i = 0; i < MAX_CPUS; i++) {
		sum_x += tot_time[i];
		sum_y += run_time[i];
	}

	fprintf(stderr, "TOT_TIME=%lu, IDLE_TIME=%lu\n", sum_x, sum_y);
	run_ratio = (float)sum_y / sum_x;
	idle_ratio = 1.0f - run_ratio;
	sum_y = sum_x = 0;

	for (i = 0; i < MAX_CPUS; i++) {
		sum_x += rx_pkts[i];
		sum_y += tx_pkts[i];
	}

	fprintf(stderr, "SENT_CNT=%lu, RECV_CNT=%lu\n", sum_y, sum_x);
	fprintf(stderr, "Result\n");
	fprintf(stderr, "-----------------------------------------------------------\n");
	fprintf(stderr, "RunTime Ratio = %2.f\t IdleTime Ratio = %2.f\n", run_ratio, idle_ratio);
	fprintf(stderr, "TX/s = %10.f\t RX/s = %10.f\n", (float)sum_x / t_diff, (float)sum_y / t_diff);
	fprintf(stderr, "-----------------------------------------------------------\n");
}
#endif
