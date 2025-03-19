#ifndef __FRD_OFFLOAD_H__
#define __FRD_OFFLOAD_H__

#include <liburing.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <stdint.h>
#include <stdio.h>

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ether.h>

#include "dpdk_io.h"
#include "dataplane.h"
#include "fht.h"
#include "fb.h"

#define FRD_OFFLOAD_DISK_READ 0x01
#define FRD_OFFLOAD_TRANSMISSION 0x02
#define FRD_OFFLOAD_FREE_FILE_BUF 0x03

#define FRD_OFFLOAD_ON_PROCEEDING 0x10
#define FRD_OFFLOAD_COMPLETE 0x20
#define FRD_OFFLOAD_ALREADY_FREED 0x30

#define PER_CORE_MAX_WAITS 8192 //4096 //2048

#define MAX_NPH_LEN 256

#define SHOW_FRD_OFFLOAD_STAT FALSE

#define FRD_OFFLOAD_ENABLE_QUEUE_DEPTH_COORDINATION TRUE
#define FRD_OFFLOAD_MAX_IOPENDINGS 256 //128

enum mbuf_wait_state {
	MBUF_WAIT_STATE_INACTIVE,
	MBUF_WAIT_STATE_ON_PROCEEDING,
	MBUF_WAIT_STATE_ACTIVE,
};

typedef struct mbuf_wait {
	enum mbuf_wait_state state;
	uint8_t nph[MAX_NPH_LEN];
	uint16_t nph_len;
	struct fb *b;
	int32_t fildes;
	uint32_t id;
	uint64_t data_len;
	struct iovec iovecs[FB_MAX_ALIGNED_MEMCHUNKS];
	//frd_iovecs *iovs;
	TAILQ_ENTRY(mbuf_wait) mbuf_wait_link;
#if SHOW_FRD_OFFLOAD_STAT
	uint64_t ts;
#endif
} mbuf_wait;

typedef struct frd_offload {
	unsigned long maxNumWaits;
	unsigned long numWaits;
	//TAILQ_HEAD(, mbuf_wait) wait_list;
	mbuf_wait *mw_ptr;
	TAILQ_HEAD(, mbuf_wait) free_list;
	struct io_uring uring;
	uint64_t tx_bytes;
	uint32_t numSQEs;
	struct fb_pool *fbp;
	
#if SHOW_FRD_OFFLOAD_STAT
	uint64_t sumLatNow;
	uint64_t sumLatPrev;
	uint64_t numIOsNow;
	uint64_t numIOsPrev;
	uint64_t ts_prev;
#endif

#if FRD_OFFLOAD_ENABLE_QUEUE_DEPTH_COORDINATION
	TAILQ_HEAD(, mbuf_wait) wait_list;
	uint16_t numIOPendings;
	uint16_t numIOWaitings;
#endif
} frd_offload;

frd_offload *
frd_offload_create(unsigned long maxNumWaits);

void 
frd_offload_destroy(frd_offload *fo);

void
frd_offload_process_cqe(uint16_t lcore_id, uint16_t port_id, frd_offload *fo, fht *ht);

extern void
frd_offload_process_setup(frd_offload *fo, fht *ht,
						  uint16_t lcore_id, uint16_t port_id,
						  uint8_t *pkt, uint16_t pkt_len);

extern void
frd_offload_process_transmission(frd_offload *fo, fht *ht,
		                         uint16_t lcore_id, uint16_t port_id,
								 uint8_t *pkt, uint16_t pkt_len);

extern void
frd_offload_free_file_buffer(frd_offload *fo, fht *ht,
		                     uint16_t lcore_id, uint16_t port_id,
							 uint8_t *pkt, uint16_t pkt_len);

inline static void
frd_offload_process(frd_offload *fo, fht *ht, 
		            uint16_t lcore_id, uint16_t port_id,
		            uint8_t *pkt, uint16_t pkt_len) {

	struct rte_ether_hdr *ethh;
	struct rte_ipv4_hdr *iph;

	ethh = (struct rte_ether_hdr *)pkt;
	iph = (struct rte_ipv4_hdr *)(ethh + 1);

	switch (iph->type_of_service & 0x0f) {
	case FRD_OFFLOAD_DISK_READ :
		frd_offload_process_setup(fo, ht, lcore_id, port_id, pkt, pkt_len);
		break;
	case FRD_OFFLOAD_TRANSMISSION :
		frd_offload_process_transmission(fo, ht, lcore_id, port_id, pkt, pkt_len);
		break;
	case FRD_OFFLOAD_FREE_FILE_BUF :
		frd_offload_free_file_buffer(fo, ht, lcore_id, port_id, pkt, pkt_len);
		break;
	default :
		//fprintf(stderr, "frd_offload_process: wrong tos(app hdr) %d\n", iph->type_of_service);//
	}
}

#if SHOW_FRD_OFFLOAD_STAT
inline static void
frd_offload_show_stat(uint16_t lcore_id, frd_offload *fo) {
	uint64_t ts_cur = GetCurUs();
	if (ts_cur - fo->ts_prev < 1000000)
		return;
	fprintf(stdout, "LCORE%u, avg latency(us):%4.2lf\n", lcore_id, 
			(double)(fo->sumLatNow - fo->sumLatPrev) / (fo->numIOsNow - fo->numIOsPrev));
	fo->ts_prev = ts_cur;
	fo->numIOsPrev = fo->numIOsNow;
	fo->sumLatNow = fo->sumLatPrev;
}
#endif

#endif /* __FRD_OFFLOAD_H__ */
