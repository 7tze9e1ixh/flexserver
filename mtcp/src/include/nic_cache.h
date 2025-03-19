#ifndef __NIC_CACHE_H__
#define __NIC_CACHE_H__

#include <stdint.h>
#include <sys/queue.h>
#include "tcp_send_buffer.h"

#if ENABLE_NIC_CACHE_FUNC_CALL
#include "control_plane.h"
#endif


#define DEBUG_NIC_CACHE 0
#define DEBUG_NIC_CACHE_TCP_SEQ 0
#define PRINT_NIC_CACHE_LOG 0
#define DEBUG_NIC_CACHE_RTO 0
#define DEBUG_NIC_CACHE_STREAM 0
#define DEBUG_ECHO_PKT 0
#define DEBUG_TCP_ACK 0
#define DEBUG_DPU_RTT 0
#define DEBUG_LOCK 0
#define DEBUG_HOST_BOTTLENECK 0
#define DEBUG_SINGLE_FLOW 0

#define SHOW_PKTLOSS 0
#define SHOW_RSS 0
#define SHOW_ETH_STATS 0
#define SHOW_DATAPLANE_PER_CORE_LOAD 0

#define SHOW_NIC_CACHE_STATISTICS 1
#define SHOW_PER_CORE_STATUS 1
#define SHOW_NUM_REQS_PER_NVME 0
#define DUMP_FLEXSERVER 1
//#define PRINT_SYSTEM_THROUGHPUT 1

#define SEND_DUMMPY_DATA 0
#define DISABLE_FRD_OFFLOAD 1
#define DBG_STARVATION 0
#define DBG_CLOSE_REASON 0
#define DBG_PACING 0

#define DBG_RATE_LIMIT_STATUS 0
#define DBG_DISK_STACK_STATUS 0

#define DBG_TX_STATUS 1

#define ENABLE_SCHED_THREAD 0
#define ENABLE_FIXED_CWND 0 

#define FIXED_CWND_SIZE (256U * 1024)

#if DEBUG_SINGLE_FLOW
extern uint64_t g_dbg_port;
extern uint32_t g_dbg_ts;
extern uint32_t g_numCompl;
#endif

extern uint32_t g_ns_block_duration;

#define NUM_NVME 10

#if DBG_STARVATION
#define LAST_SENT_TS_GRANURALITY 1		// 10us
#define LAST_SENT_TS_DURATION 1000		// 10ms
#define LAST_SENT_TS_SIZE	(LAST_SENT_TS_DURATION / LAST_SENT_TS_GRANURALITY)

#define	STARVED_REASON_RATE_LIMITED 0
#define STARVED_REASON_NOT_ENOUGH_WINDOW_SPACE 1
#define STARVED_REASON_NOT_ENOUGH_PKTBUF 2
#define STARVED_REASON_NOT_STARVED 3
#define STARVED_REASON_NUMBER 4
#endif

#if DBG_PACING
#define PACING_INT_GRANURALITY 1   // 10us
#define PACING_INT_DURATION 1000
#define PACING_INT_ARR_SIZE (PACING_INT_DURATION / PACING_INT_GRANURALITY)
#endif

#ifdef _GOODPUT
struct global_goodput {
	uint64_t t_general_now;
	uint64_t t_general_prev;
	uint64_t t_l2_cache_now;
	uint64_t t_l2_cache_prev;
	uint64_t t_nvmes_now;
	uint64_t t_nvmes_prev;
};

extern struct global_goodput g_goodput[];
#endif

struct nic_cache_stat {

	uint64_t numPkts;
	uint64_t numRTOs;
	uint64_t numFastRetransmissions;
	uint64_t numDUPAcks;
	uint64_t threeDUPAcks;
	uint64_t tx_bytes;
	uint64_t tx_l2cache;
	uint64_t tx_diskRead;
	uint64_t numReqs;
	uint64_t numL1Hits;
	uint64_t numL2Hits;
	uint64_t numDiskReads;
	uint64_t num_nvmeReqs[NUM_NVME];

	uint64_t meta_rtt;
	uint64_t meta_rtt_prev;
	uint64_t num_meta;
	uint64_t num_meta_prev;
	uint64_t meta_to;
	uint64_t meta_flush;
	uint64_t meta_to_prev;
	uint64_t meta_flush_prev;

#ifdef ENABLE_DUMMY_CMD
	uint64_t dummy_bytes;
#endif /* ENABLE_DUMMY_CMD  */

#if DBG_STARVATION
	uint64_t last_sent_ts_now[LAST_SENT_TS_SIZE];
	uint64_t last_sent_ts_prev[LAST_SENT_TS_SIZE];

	uint64_t numStarved;
	uint64_t numStarvedAgain;

	uint64_t numStarvedReasons_now[STARVED_REASON_NUMBER];
	uint64_t numStarvedReasons_prev[STARVED_REASON_NUMBER];
	uint64_t numFailToSendReason_now[STARVED_REASON_NUMBER];
	uint64_t numFailToSendReason_prev[STARVED_REASON_NUMBER];
#endif

#if DBG_PACING
	uint64_t pacing_interval_now[PACING_INT_ARR_SIZE];
	uint64_t pacing_interval_prev[PACING_INT_ARR_SIZE];
	uint64_t pacing_interval_gap_now[PACING_INT_ARR_SIZE];
	uint64_t pacing_interval_gap_prev[PACING_INT_ARR_SIZE];

	uint64_t numPacedSend_now;
	uint64_t numPacedSend_prev;
	uint64_t numPaced_now;
	uint64_t numPaced_prev;
#endif

#if DBG_RATE_LIMIT_STATUS
	uint64_t numFailToSend_now;
	uint64_t numFailToSend_prev;
#endif

#if DBG_DISK_STACK_STATUS
	uint64_t totalLatency_now;
	uint64_t totalLatency_prev;

	uint64_t numIOs_now;
	uint64_t numIOs_prev;

	uint64_t numReadBytes_now;
	uint64_t numReadBytes_prev;

	uint64_t total_submit_latency_now;
	uint64_t total_submit_latency_prev;

	uint64_t numIssueReq_now;
	uint64_t numIssueReq_prev;

	uint64_t numIOPendings_now;
	uint64_t numIOPendings_prev;
#endif

#if DBG_TX_STATUS
	uint64_t numTxPkts_now;
	uint64_t numTxPkts_prev;

	uint64_t sumTxLatency_now;
	uint64_t sumTxLatency_prev;

	uint64_t numTxFuncCalls_now;
	uint64_t numTxFuncCalls_prev;

	uint64_t numMetaPkts_now;
	uint64_t numMetaPkts_prev;
	
	uint64_t numFrdPkts_now;
	uint64_t numFrdPkts_prev;
#endif
	uint64_t arm_path_rtt;
	uint64_t host_path_rtt;
	uint64_t num_arm_path;
	uint64_t num_host_path;

	uint64_t arm_path_rtt_prev;
	uint64_t host_path_rtt_prev;
	uint64_t num_arm_path_prev;
	uint64_t num_host_path_prev;
};

extern unsigned char dpu_mac_address[];
extern struct nic_cache_stat g_nic_cache_stat[];

#if SHOW_PKTLOSS
extern uint64_t nb_fast_retransmission[];
extern uint64_t nb_timeout_retransmission[];
extern uint64_t nb_tot_pkts[];
#define INCR_NB_FAST_RETRANS(cpu) nb_fast_retransmission[cpu]++
#define INCR_NB_TIMEOUT_RETRANS(cpu) nb_timeout_retransmission[cpu]++
#define INCR_TOT_PKTS(cpu) nb_tot_pkts[cpu]++
#else
#define INCR_NB_FAST_RETRANS(cpu) (void)0
#define INCR_NB_TIMEOUT_RETRANS(cpu) (void)0
#define INCR_TOT_PKTS(cpu) (void)0
#endif

#if DEBUG_HOST_BOTTLENECK
extern uint64_t pkt_proc_time;
extern uint64_t tot_time;
#define INCR_TOT_TIMES(t) (tot_time += (t))
#define INCR_PKT_PROC_TIME(t) (pkt_proc_time += (t))
#define START_MONOTORING() nic_cache_start_monitoring()
#else
#define INCR_TOT_TIMES(t) (void)0
#define INCR_PKT_PROC_TIME(t) (void)0
#define START_MONOTORING() (void)0
#endif

#define ENABLE_ECHO 0

#if DBG_CLOSE_REASON
#define TRACE_CLOSE_REASON(f, ...)  fprintf(stderr, "[%10s:%4d] " f, __func__, __LINE__, ##__VA_ARGS__)
#else
#define TRACE_CLOSE_REASON(f, ...) (void)0
#endif

#if DBG_FRD
#define NIC_CACHE_LOG_FRD(f, ...) do{\
	fprintf(stderr, "(%10s:%4d) " f, ##__VA_ARGS__);\
} while(0)
#else
#define NIC_CACHE_LOG_FRD(f, ...) (void)0
#endif

#if DEBUG_NIC_CACHE
#define NIC_CACHE_DUMP(_l, ...) do {\
	nic_cache_dump(__FILE__, __LINE__, _l, ##__VA_ARGS__);\
} while(0)
#else
#define NIC_CACHE_DUMP(_f, ...) (void)0
#endif

#if DEBUG_NIC_CACHE_TCP_SEQ
#define NIC_CACHE_LOG_TCP_SEQ(_l, ...) do{\
	nic_cache_dump(__FILE__, __LINE__, _l, ##__VA_ARGS__);\
} while(0)
#else 
#define NIC_CACHE_LOG_TCP_SEQ(_l, ...) (void)0
#endif

#if DEBUG_NIC_CACHE_RTO
#define NIC_CACHE_LOG_RTO(_l, ...) do{\
	nic_cache_dump(__FILE__, __LINE__,  _l, ##__VA_ARGS__);\
} while(0)
#else
#define NIC_CACHE_LOG_RTO(_l, ...) (void)0
#endif

#if DEBUG_NIC_CACHE_STREAM
#define NIC_CACHE_LOG_STREAM(_l, ...) do{\
	nic_cache_dump(__FILE__, __LINE__, _l, ##__VA_ARGS__);\
} while(0)
#else
#define NIC_CACHE_LOG_STREAM(_l, ...)  (void)0
#endif

#if DEBUG_ECHO_PKT
#define NIC_CACHE_LOG_ECHO_PKT(_l, ...) do{\
	nic_cache_dump(__FILE__, __LINE__, _l, ##__VA_ARGS__);\
} while(0)
#else
#define NIC_CACHE_LOG_ECHO_PKT(_l, ...) (void)0
#endif

#if DEBUG_TCP_ACK
#define NIC_CACHE_LOG_TCP_ACK(_l, ...) do{\
	nic_cache_dump(__FILE__, __LINE__, _l, ##__VA_ARGS__);\
} while(0)
#else
#define NIC_CACHE_LOG_TCP_ACK(_l, ...) (void)0
#endif


#if DEBUG_LOCK
#define NIC_CACHE_LOG_LOCK(_l, ...) do{\
	nic_cache_dump(__FILE__, __LINE__, _l, ##__VA_ARGS__);\
} while(0)
#else
#define NIC_CACHE_LOG_LOCK(_l, ...) (void)0
#endif

#if DEBUG_SINGLE_FLOW
#define TRACE_SINGLE_FLOW(p, f, ...) do{\
	uint16_t __port = ntohs((p));\
	if (__port == g_dbg_port)\
		nic_cache_dump(__FILE__, __LINE__, f, ##__VA_ARGS__);\
} while(0)
#define SET_SINGLE_FLOW_TS(p, ts) do {\
	uint16_t __port = ntohs(p);\
	if (__port == g_dbg_port)\
		g_dbg_ts = (ts);\
} while(0)
#else
#define TRACE_SINGLE_FLOW(p, f, ...) (void)0
#endif

#define ENABLE_NIC_CACHE_FUNC_CALL 1
#define ENABLE_FAIR_QUEUE 1
#define LIMIT_MAX_META_PAYLOADLEN 0
#define LIMIT_NB_TX_PKT_BURST 0

#define BLK_TYPE_TRANS_META 1
#define BLK_TYPE_REAL_META 0
#define MAX_NB_BLK_AS_WORD 64
#define MAX_NB_BLKS 64 * 16
#define DEFAULT_NB_CHS_PER_CORE 10
#define NB_TO_BE_ECHOED 128
#define NB_TX_PKT_THRESH 512
#define MASTER_CPU 0
#define DATAPLANE_MAX_CPUS 16

typedef struct trans_meta_s trans_meta;
typedef struct real_meta_s real_meta;

typedef struct pkt_shp_s {
	//uint32_t tot_len;
	uint16_t nb_blks;
	uint16_t blk_type[MAX_NB_BLK_AS_WORD];
} pkt_shp;

typedef struct blk_info_s {
	void *opaque;
	uint32_t blk_type : 1,
			 blk_len : 31;
} blk_info;

typedef struct blk_info_bundle_s {
	blk_info info[MAX_NB_BLKS];
} blk_info_bundle;

struct trans_meta_s {
	uint64_t t_hv;
	uint64_t t_off;
	uint32_t t_len;
} __attribute__((packed));

struct real_meta_s {
	uint16_t r_len;
} __attribute__((packed));

struct echo_hdr {
	uint32_t e_seq;
	uint16_t e_len;
}__attribute__((packed));

struct to_be_echoed {
	uint32_t e_seq;
	uint16_t e_len;
#if DEBUG_DPU_RTT
	uint32_t sent_ts;
#endif
	TAILQ_ENTRY(to_be_echoed) tbe_link;
};

TAILQ_HEAD(tbe_head, to_be_echoed);

void nic_cache_global_init(size_t nb_chs);
void nic_cache_private_init(int cpu);
void nic_cache_private_teardown(int cpu);
void nic_cache_global_teardown(void);
int nic_cache_get_obj_hv(int cpu, int stream_id, char *url, size_t url_len, 
		uint64_t *hv, uint32_t *sz, void **block_map, int *numBlocks);
int nic_cache_free_obj_by_hv(int cpu, int stream_id, uint64_t hv);
/*
uint32_t nic_cache_get_pkt_shp_and_info(struct tcp_send_buffer *buf, pkt_shp *shp, 
		blk_info_bundle *bib, uint32_t seq, uint32_t payloadlen);*/
/*
void nic_cache_create_meta_pkt(struct tcp_send_buffer *buf, pkt_shp *shp, 
		blk_info_bundle *bib, uint8_t *pktbuf, uint32_t seq);*/
void nic_cache_dump(char *fn, int line, char *log, ...);
//bool IsInMSB(struct tcp_send_buffer *buf, uint32_t seq, meta_send_buffer *msb);
//bool IsInRSB(struct tcp_send_buffer *buf, uint32_t seq, meta_send_buffer *msb);
uint64_t GetCurUs(void);

#if ENABLE_NIC_CACHE_FUNC_CALL

extern bool is_control_plane_queue_empty[];

#define CONTROL_PLANE_ENQUEUE_REPLY(mtcp, pkt_data, cur_ts) do {\
	int _cpu = (mtcp)->ctx->cpu;\
	int _core_index = _cpu % control_plane_get_nb_cpus();\
	is_control_plane_queue_empty[_cpu] = true;\
	control_plane_enqueue_reply(_core_index, (pkt_data), (cur_ts));\
} while(0)

#define CONTROL_PLANE_FLUSH_MESSAGES(ctxt, ifidx) do {\
	int _cpu = (ctxt)->cpu;\
	int _core_index = _cpu % control_plane_get_nb_cpus();\
	int _portid = CONFIG.eths[(ifidx)].ifindex;\
	control_plane_flush_message(_core_index, _portid, _cpu);\
} while(0)

void nic_cache_mtcp_master_thread_ready(void);

#define SIGNAL_TO_CONTROL_PLANE(ctxt) do{\
	int _cpu = (ctxt)->cpu;\
	int _core_index = _cpu % control_plane_get_nb_cpus();\
	if (is_control_plane_queue_empty[_cpu]) {\
		control_plane_signal_to_replyq(_core_index);\
		is_control_plane_queue_empty[_cpu] = false;\
	}\
} while(0)

#else
#define CONTROL_PLANE_ENQUEUE_REPLY(cpu, pkt_data, ts) (void)0
#define CONTROL_PLANE_FLUSH_MESSAGES(ctxt, ifidx) (void)0
#define SIGNAL_TO_CONTROL_PLANE(ctxt) UNUSED(0)
#endif

#if DEBUG_DPU_RTT && ENABLE_ECHO
void nic_cache_dump_dpu_rtt(uint32_t dpu_rtt);
#endif

#if DEBUG_HOST_BOTTLENECK
void nic_cache_start_monitoring(void);
#endif

#if SHOW_NIC_CACHE_STATISTICS
void nic_cache_show_statistics(void);
#endif


#endif /* __NIC_CACHE_H__ */
