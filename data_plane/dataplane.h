#ifndef __DATAPLANE_H_
#define __DATAPLANE_H_

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

#include <rte_mempool.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

/* Common macro*/
#ifndef UNUSED
#define UNUSED(_x)	(void)(_x)
#endif

#define ETYPE_OFFLOAD			(0xf80d)
#define ETYPE_TRANSMISSION      (0xf80f)
#define ETYPE_EVICTION          (0xf811)

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0 
#endif

#define LOG_BUF_SIZE (20 * 1024 * 1024)
#define USE_LOG_BUF TRUE
#define PACKET_LOG FALSE

#define HZ_						1000
#define TIME_TICK				(1000000/HZ_)
#define TIMEVAL_TO_TS(t)		(uint32_t)((t)->tv_sec * HZ_ + ((t)->tv_usec / TIME_TICK))
#define TIMEVAL_TO_US(t)		(uint32_t)((t)->tv_sec * 1000000 + ((t)->tv_usec))
#define RX_IDLE FALSE
#if RX_IDLE
#define RX_IDLE_THRESH 32
#define RX_IDLE_TIMEOUT 1
#endif

#define LIMIT_TXQ_RATE FALSE
#define ENABLE_JUMBO_FRAME FALSE

#define IS_TRUE(flag) ((flag) ? "yes" : "no")

#include "dpdk_io.h"

#if ENABLE_JUMBO_FRAME
#define MTU (JUMBO_FRAME_MAX_SIZE - RTE_ETHER_HDR_LEN)
#else
#define MTU (TO_NET_MTU)
#endif

#define JUMBO_WITHOUT_HEADER_LEN (MTU - 40)
#define MAX_TSO_PACKET_SIZE (uint16_t)(32 * 1024)

#define ENABLE_DIRECT_DATA_READ TRUE
#define SHOW_STATISTICS FALSE
#define SHOW_ONLY_GOODPUT TRUE
#define SHOW_CMD_LOG FALSE
#define SHOW_ETH_STATS FALSE

#define ENABLE_SQ_POLL TRUE

struct dataplane_stat {
	uint64_t numEvict;
	uint64_t numEvictRT;

	uint64_t numOffload;
	uint64_t numOffloadRT;

	uint64_t totBytes;
	uint64_t disk_sent_bytes;
	uint64_t numMeta;
	uint64_t numPkts;
	uint64_t numFrdMeta;

	uint64_t numFrdSend;

	uint64_t numFrdSetup;
	uint64_t numFrdSetupHdr;
	uint64_t numRTOFrdSetup;

	uint64_t numFrdTeardown;
	uint64_t numFrdTeardownHdr;
	uint64_t numRTOFrdTeardown;

	uint64_t numReply;
	uint64_t numReplyHdr;

	uint64_t numFrdComplPkt;
	uint64_t numFrdComplHdr;

	uint64_t numFrdFreePkt;
	uint64_t numFrdFreeHdr;
	
	uint64_t rx_bytes;

	uint64_t numAppHdr;
	uint64_t appHdrBytes;

	uint64_t us_tx_burst;
	uint64_t num_tx_burst;

};

struct dataplane_goodput {
	uint64_t t_cache_now;
	uint64_t t_cache_prev;

	uint64_t t_frd_now;
	uint64_t t_frd_prev;
};

#ifdef _GOODPUT
extern struct dataplane_goodput g_goodput[];
#endif

#ifdef _NOTIFYING_MBPS
extern struct dataplane_goodput g_mbps[];
#endif

struct eviction_meta {
	uint64_t e_hv;
	uint64_t ts;
} __rte_packed;

struct trans_meta {
	uint64_t t_hv;
	uint64_t t_off;
	uint32_t t_len;
} __rte_packed;

struct direct_read_header {
	uint64_t hv;
	uint64_t ts;
	char path[];
};

struct frd_offload_hdr {
	uint32_t toSend;
	uint64_t offset;
	uint32_t id;
	uint16_t path_len;
	char path[];
};

extern struct dataplane_stat g_stat[];

#define GET_TCP_HDR_LEN(tcph) (((tcph)->data_off & 0xf0) >> 2)
#define GET_CUR_TS(_ts) clock_gettime(CLOCK_MONOTONIC_COARSE, _ts)
#define SEC_TO_MSEC(_s) ((_s) * 1000)
#define MSEC_TO_SEC(_ms) (_ms) / 1000
#define MSEC_TO_NSEC(ms) ((ms) * 1000000)
#define NSEC_TO_MSEC(_ns) (_ns) / 1000000
#define USEC_TO_NSEC(us) ((us) * 1000)
#define USEC_TO_MSEC(us) ((us) / 1000)
#define USEC_TO_SEC(us) ((us) / 1000000)
#define CUR_MS(_ts) SEC_TO_MSEC((_ts)->tv_sec) + NSEC_TO_MSEC((_ts)->tv_nsec / 1000000)

#define MAX_FILE_LEN (2U * 1024 * 1024) // 2MB
#define CACHE_BLOCK_SIZE (256 * 1024) // (128U * 1024) 
#define MAX_IOV (MAX_FILE_LEN / CACHE_BLOCK_SIZE)
#define OFFLOAD_CHUNK_SIZE (16 * 1024) // (8 * 1024) 
#define CHUNK_PER_BLOCK (CACHE_BLOCK_SIZE / OFFLOAD_CHUNK_SIZE)

extern uint64_t GetCurUs(void);

#define NUM_FILE_BUFFERS 16384 //19600
#define FHT_NUM_ENTRIES 512

#define ENABLE_META_CHANNEL FALSE
#define ENABLE_RTT_CHECK FALSE
#define ENABLE_APP_HDR_BATCH FALSE

#endif /* __DATAPLANE_H_ */
