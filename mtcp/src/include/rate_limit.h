#ifndef __RATE_LIMIT_H__
#define __RATE_LIMIT_H__

#include <stdint.h>
#include "mtcp.h"
#include "nic_cache.h"

#define NIC_THROUGHPUT_INFORM_TYPE 0xf810
#define RATE_LIMIT_CACHE_NOTIFYING_MBPS_TYPE 0xf808
#define RATE_LIMIT_CACHE_ENABLE_NOTIFY_MBPS FALSE

#define RATE_LIMIT_CACHE_TX_RING_SIZE (1024 * 512)
#define RATE_LIMIT_CACHE_RING_GRANURALITY 1000 // us

struct nic_throughput {
	uint64_t t_cache;
	uint64_t t_frd;
};

extern struct nic_throughput g_nic_throughput;
extern struct nic_throughput g_nic_mbps;

#ifdef _GOODPUT
extern struct nic_throughput g_nic_goodput;
#endif

void
rate_limit_cache_setup(mtcp_manager_t mtcp);

extern void
rate_limit_update(mtcp_manager_t mtcp, void *pkt_data);

extern void
rate_limit_cache_update_mbps(mtcp_manager_t mtcp, void *pkt_data);

extern bool
rate_limit_cache_can_send_now(mtcp_manager_t mtcp, uint32_t plen);

void
rate_limit_cache_destroy(mtcp_manager_t mtcp);

#ifdef _GOODPUT
extern void
rate_limit_get_goodput(mtcp_manager_t mtcp, void *pkt_data);
#endif

#endif
