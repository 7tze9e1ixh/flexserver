#ifndef __CORE_H__
#define __CORE_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h> 
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dirent.h>
#include <xxhash.h>

#include <sys/queue.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>

#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_cfgfile.h>
#include <rte_memcpy.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>

#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_branch_prediction.h>

#include "item_mp.h"
#include "item_queue.h"
#include "rb_tree.h"

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef UNUSED
#define UNUSED(_x)	(void)(_x)
#endif

#define MAX_NB_CPUS 16
#define PKT_QUEUE_SIZE 8192
#define NB_MBUFS (16*1024)
#define PKTMBUF_SIZE 16384

#define DEBUG FALSE
#define OFFLOADING_EVICTION_TEST FALSE
#define RUN_CACHE_OPTIMIZATION TRUE
#define TEST_CONNECTX6_LIMITATION FALSE
#define ALWAYS_READ_FROM_DISK FALSE
#define SET_CORE_AFFINITY FALSE
#define NUM_L2_CACHE_OFFLOADS_SCALE 4
#define ENABLE_CMD_LOAD_BALANCING FALSE
//#define ENABLE_PERIODIC_OFFLOAD TRUE

#define HOST_HYPERBOLIC      TRUE // 
#define HOST_LFU	         FALSE 
#define HOST_LRU			 FALSE // 

#ifdef HOST_HYPERBOLIC
#define HYPERBOLIC_SAMPLE_SIZE	    (1000) //(100) // 
#define HYPERBOLIC_OMEGA			(0.1)
#define HYPERBOLIC_MAX_LOOP_COUNT	(3)
#endif

#define NIC_HYPERBOLIC		 TRUE
#define NIC_LFU				 FALSE
#define NIC_LRU				 FALSE

#define ETYPE_PAYLOAD_OFFLOAD   (0xf80d)
#define ETYPE_TRANSMISSION      (0xf80f)
#define ETYPE_EVICTION          (0xf811)

typedef struct private_context private_context;
typedef struct optim_cache_context optim_cache_context;
typedef struct offload_reply_queue offload_reply_queue;
typedef struct eviction_reply_queue eviction_reply_queue;
typedef struct tx_pkt_queue tx_pkt_queue;

struct tx_pkt_queue {
	size_t len;
	pthread_mutex_t mutex;
	//pthread_cond_t cond;
	//rte_spinlock_t sl;
	struct rte_mbuf *mq[PKT_QUEUE_SIZE];
};

struct rx_offload_meta_hdr {
	uint64_t hv;
	uint32_t sz;
	uint16_t seq;
	uint64_t off;
} __rte_packed;

struct offload_reply_queue {
	size_t len;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool proc;
	struct rx_offload_meta_hdr q[PKT_QUEUE_SIZE];
	uint64_t ts[PKT_QUEUE_SIZE];
};

struct eviction_reply_queue {
	size_t len;
	//rte_spinlock_t sl;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool proc;
	uint64_t e_hv[PKT_QUEUE_SIZE];
	uint64_t ts[PKT_QUEUE_SIZE];
};

struct rx_e_hv {
	uint64_t e_hv[PKT_QUEUE_SIZE];
	size_t len;
};

struct private_context {
	uint16_t core_index;
	uint16_t lcore_id;
	item_mp *itmp;
};

#define MAX_PATH_LEN 256
struct direct_read_header {
	uint64_t hv;
	uint64_t ts;
	char path[];
};

#include "l2cache/block.h"
#include <sys/uio.h>

#define MAX_IOV 32

struct optim_cache_context {
	uint16_t core_index;
	rb_tree *ec_wait;
	rb_tree *oc_wait;
	struct rte_mempool *pktmbuf_pool;
	tx_pkt_queue *tpq;
	offload_reply_queue *orq;
	eviction_reply_queue *erq;
	struct rx_e_hv *rehv;
	struct rx_e_hv *compl_ohv;
	item_queue *ocq;
	item_queue *koq; /* Queue for object kicked out from L1_CACHE*/
	block_pool *bp;
	struct iovec iov[MAX_IOV];
};

struct control_plane_stats {
	uint64_t num_offload_dups;
	uint64_t num_evict_dups;
	uint64_t num_offloads;
	uint64_t num_evicts;
	uint64_t num_offload_pkts;
	uint64_t num_evict_pkts;
	uint64_t sum_dup_lat;
	uint64_t sum_offload_lat;
	uint64_t sum_evict_lat;
	uint64_t sum_srch_lat;
	uint64_t num_srch;
	uint64_t sum_mtx_lat;
	uint64_t num_mtx;
};

extern struct control_plane_stats g_stats;

#define GET_NB_BLK(sz) sz % DATAPLANE_BLOCK_SIZE ? \
	(sz / DATAPLANE_BLOCK_SIZE) + 1 : \
	(sz / DATAPLANE_BLOCK_SIZE)

#define DATAPLANE_BLOCK_SIZE (256 * 1024) //(128U * 1024)
#define CONTROL_PLANE_BLOCK_SIZE DATAPLANE_BLOCK_SIZE

#define TO_DECIMAL(s) strtol((s), NULL, 10)
#define TO_HEXADECIMAL(s) strtol((s), NULL, 16)
#define TO_REAL_NUMBER(s) strtod((s), NULL)
#define TO_GB(b) (b)*(1024 * 1024 * 1024)

#define SEC_TO_USEC(s) ((s) * 1000000)
#define NSEC_TO_USEC(ns) ((ns) / 1000)
#define SEC_TO_MSEC(s) ((s) * 1000)
#define NSEC_TO_MSEC(ns) ((ns) / 1000000)
#define MSEC_TO_USEC(ms) ((ms) * 1000)
#define MSEC_TO_NSEC(ms) ((ms) * 1000000)
#define USEC_TO_SEC(us) ((us) / 1000000)

#define MAX_OFFLOADING_BACKOFF_TIME 10 // sec
#define OFFLOADING_BACKOFF_TIME 20

#define MAX_EVICTION_BACKOFF_TIME 10 // sec
#define EVICTION_BACKOFF_TIME 20

#define GET_CUR_US(us) do {\
	struct timespec ts_now;\
	clock_gettime(CLOCK_REALTIME, &ts_now);\
	(us) = SEC_TO_USEC(ts_now.tv_sec) + NSEC_TO_USEC(ts_now.tv_nsec);\
} while(0)

inline static uint64_t
__us_now() {
	struct timespec ts_now;
	clock_gettime(CLOCK_REALTIME, &ts_now);
	return SEC_TO_USEC(ts_now.tv_sec) + NSEC_TO_USEC(ts_now.tv_nsec);
}

#define GET_CUR_MS(ms) do {\
	struct timespec ts_now;\
	clock_gettime(CLOCK_REALTIME, &ts_now);\
	(ms) = SEC_TO_MSEC(ts_now.tv_sec) + NSEC_TO_MSEC(ts_now.tv_nsec);\
} while(0)

extern uint32_t g_jhash_initval;
extern uint32_t g_crc_hash_initval;

#define CAL_HV(k, l) ((((uint64_t)rte_hash_crc((k), (l), g_crc_hash_initval) << 32) | \
		(uint64_t)rte_jhash((k), (l), g_jhash_initval)) ^ XXH3_64bits((k), (l)))

#if OFFLOADING_EVICTION_TEST
#define TEST_SEC_SLEEP 2	// BackOff time is 3 seconds 
#define TEST_BACKOFF_SLEEP() sleep(TEST_SEC_SLEEP)
#define MAX_TEST_COUNT 3
#endif

extern bool g_active_l1_cache;
extern bool g_active_l2_cache;


#endif /* __CORE_H__ */
