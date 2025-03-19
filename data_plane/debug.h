#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <rte_log.h>
#include <rte_mbuf_core.h>
#include <rte_mempool.h>

#include "dataplane.h"
#include "dpdk_io.h"

void debug_setup(void);
void debug_teardown(void);
void debug_log(char *f_nm, int line, char *log, ...);

#define DEBUG                       (FALSE)
#define DEBUG_PAYLOAD_CONSISTENCY   (FALSE) /* Testing Offloaded Payload Consistency */
#define DEBUG_EVICTION              (FALSE) /* Testing Evict-All-Instruction at Host*/
#define DEBUG_OFFLOAD				(FALSE)
#define DEBUG_BLK					(FALSE)
#define DEBUG_CHNK_HT               (FALSE)
#define DEBUG_TCP_SEQ               (FALSE)
#define DEBUG_RSS                   (FALSE)
#define DEBUG_BOTTLENECK            (FALSE)
#define DEBUG_LATENCY               (FALSE)
#define DEBUG_META                  (FALSE)
#define DEBUG_PKTMBUF				(FALSE)
#define DEBUG_ETH_STATS				(FALSE)
#define DEBUG_M_PORT				(FALSE)
#define DEBUG_ETH_XSTATS			(FALSE)

#define DUMP_PACKET					(FALSE)
#define DUMP_APP_HDR				(FALSE)

#define PRINT_PERIOD				(1)
#define SHOW_STATUS					(FALSE)

#define SHOW_RSS FALSE

#define COLLECT_PACKET_PROCESS_TIME FALSE
#define CAL_PKT_PROC_TIME           FALSE


#if DEBUG_ETH_STATS
extern struct rte_eth_stats g_stats;
#endif

#if DEBUG_BOTTLENECK
void incr_tot_time(uint64_t t);
void incr_run_time(uint64_t t);
void incr_rx_pkts(uint64_t n);
void incr_tx_pkts(uint64_t n);
void PrintPacketProcessedByDPU(void);
#define INCR_TOT_TIME(t) incr_tot_time((t))
#define INCR_RUN_TIME(t) incr_run_time((t))
#define INCR_RX_PKTS(n) incr_rx_pkts((n))
#define INCR_TX_PKTS(n) incr_tx_pkts((n))
#else
#define INCR_TOT_TIME(t) (void)0
#define INCR_RUN_TIME(t) (void)0
#define INCR_RX_PKTS(n) (void)0
#define INCR_TX_PKTS(n) (void)0
#endif
void dump_pktmbuf(struct rte_mbuf *m, char *log, ...);

#define log_error(_f, ...) do {\
	RTE_LOG(ERR, \
			USER1,\
			_f, \
           ##__VA_ARGS__);\
} while(0)

#define	log_info(_f, ...) do {\
	fprintf(stderr, "(%10s:%4d) " _f, __func__, __LINE__, ##__VA_ARGS__);\
} while(0)

#define log_warning(_f, ...) do {\
	RTE_LOG(WARNING,  \
			USER1,\
			_f, \
            ##__VA_ARGS__);\
} while(0)

#if SHOW_BLK_STATUS
#define PRINT_BLK_STATUS(f, ...) do{\
	log_info(f, ##__VA_ARGS__);\
} while(0)
#else
#define PRINT_BLK_STATUS(f, ...) UNUSED(0)
#endif

#if DEBUG
#define log_cache(_f, ...) do {\
	debug_log(__FILE__, __LINE__, _f, ##__VA_ARGS__);\
} while(0)


#else
#define log_cache(_f, ...) (void)0
#endif

#if DEBUG_CHNK_HT
#define log_chnk_ht(_f, ...) do {\
	RTE_LOG(ERR, \
			USER1,\
			"(%10s:%4d) " _f, \
			__func__, __LINE__, ##__VA_ARGS__);\
} while(0)
#else
#define log_chnk_ht(_f, ...) (void)0
#endif

#if DEBUG_TCP_SEQ
#define log_tcp_seq(_f, ...) do {\
	debug_log(__FILE__, __LINE__, _f, ##__VA_ARGS__);\
} while(0)
#else
#define log_tcp_seq(_f, ...) (void)0
#endif

#if DUMP_APP_HDR
#define log_app_hdr(_f, ...) do{\
	debug_log(__FILE__, __LINE__, _f, ##__VA_ARGS__);\
}while(0)
#else
#define log_app_hdr(_f, ...) (void)0
#endif
#if DEBUG_RSS
#define log_rss(_f, ...) do{\
	debug_log(__FILE__, __LINE__, _f, ##__VA_ARGS__);\
}while(0)
#else
#define log_rss(_f, ...) (void)0
#endif

#if DEBUG_LATENCY
#define log_latency(_f, ...) do {\
	debug_log(__FILE__, __LINE__, _f, ##__VA_ARGS__);\
} while(0)
#else
#define log_latency(_f, ...) (void)0
#endif

#if DEBUG_META
#define log_meta(_f, ...) do {\
	debug_log(__FILE__, __LINE__, _f, ##__VA_ARGS__);\
} while(0)
#else
#define log_meta(_f, ...) (void)0
#endif

#if DEBUG_EVICTION
#define LOG_EVICTION(f, ...) do {\
	struct timespec ts_now;\
	GET_CUR_TS(&ts_now);\
	debug_log(__FILE__, __LINE__, "[EVICTION] (ts=%4lu) " f, CUR_MS(&ts_now), ##__VA_ARGS__);\
} while(0)
#else
#define LOG_EVICTION(f, ...) (void)0
#endif

#if DEBUG_OFFLOAD
#define LOG_OFFLOAD(f, ...) do {\
	struct timespec ts_now;\
	GET_CUR_TS(&ts_now);\
	debug_log(__FILE__, __LINE__, "[OFFLOAD] (ts=%4lu) " f, CUR_MS(&ts_now), ##__VA_ARGS__);\
} while(0)
#else
#define LOG_OFFLOAD(f, ...) (void)0
#endif

#if DEBUG_BLK
#define LOG_BLK(f, ...) do {\
	struct timespec ts_now;\
	GET_CUR_TS(&ts_now);\
	debug_log(__FILE__, __LINE__, "[BLK] (ts=%4lu) " f, CUR_MS(&ts_now), ##__VA_ARGS__);\
} while(0)
#else
#define LOG_BLK(f, ...) (void)0
#endif

#if DEBUG_PKTMBUF
#define LOG_PKTMBUF(f, ...) do{\
	debug_log(NULL, -1, f, ##__VA_ARGS__);\
} while(0)
#else
#define LOG_PKTMBUF(f, ...) UNUSED(0)
#endif

#if DEBUG_M_PORT
#define LOG_MPORT(f, ...) do{\
	debug_log(NULL, -1, f, ##__VA_ARGS__);\
}while(0)
#else
#define LOG_MPORT(f, ...) (void)0
#endif

#if DUMP_PACKET
#define DUMP_REPLY_PACKET(f, ...) do{\
	debug_log(NULL, -1, f, ##__VA_ARGS__);\
} while(0)
#else
#define DUMP_REPLY_PACKET(f, ...) UNUSED(0)
#endif

#if CAL_PKT_PROC_TIME
extern uint64_t tot_pkt_proc_time;
extern uint64_t tot_pbytes;
extern uint64_t tot_times;

#define INCR_PKT_PROC_TIME(t) do {\
		tot_pkt_proc_time += (t);\
} while(0)
#define INCR_TOTAL_TIMES(t) do {\
		tot_times += (t);\
} while(0)

#define INCR_PBYTES(b) tot_pbytes += (b)
#else
#define INCR_PKT_PROC_TIME(t) (void)0
#define INCR_PBYTES(b) (void)0
#define INCR_TOTAL_TIMES(t) (void)0
#endif

#if COLLECT_PACKET_PROCESS_TIME
#define COLLECTING_INTERVAL 1000
extern uint64_t g_ptime[]; // us
extern uint64_t g_pint[];
extern uint64_t g_pbyte_kb[];
extern uint64_t g_per_pkt_proc_time[];
extern uint64_t g_btime[];
extern uint64_t g_tx_pkt_sz[];
#define INCR_PTIME(t) (g_ptime[(t) % COLLECTING_INTERVAL]++)
#define INCR_PINT(t) (g_pint[(t) % COLLECTING_INTERVAL]++)
#define INCR_PBYTES_KB(b) do {\
	int __index = ((b) >> 10) % COLLECTING_INTERVAL;\
	g_pbyte_kb[__index]++;\
}while(0)
#define INCR_PER_PACKET_PROC_TIME(us, b) do{\
	double __ppt_us = (double)(us) / ((b) / TO_NET_MTU);\
	int __index = ((int)(__ppt_us * 10)) % COLLECTING_INTERVAL;\
	g_per_pkt_proc_time[__index]++;\
} while(0)
#define INCR_BTIME(us) do{\
	int __index = (us) % COLLECTING_INTERVAL;\
	g_btime[__index]++;\
} while(0)
#define INCR_PKT_SZ(b) do{\
	int __index = ((b) >> 10) % COLLECTING_INTERVAL;\
	g_tx_pkt_sz[__index]++;\
} while(0)
#else
#define INCR_PTIME(t) UNUSED(0)
#define INCR_PINT(t) UNUSED(0)
#define INCR_PBYTES_KB(b) UNUSED(0)
#define INCR_PER_PACKET_PROC_TIME(us, b) UNUSED(0)
#define INCR_BTIME(us) UNUSED(0)
#define INCR_PKT_SZ(b) UNUSED(0)
#endif

#endif /* __DEBUG_H__*/
