#ifndef __RATE_LIMIT_H__
#define __RATE_LIMIT_H__

#include <stdint.h>

#define RATE_LIMIT_NIC_NOTIFYING_MBPS_TYPE 0xf808
#define RATE_LIMIT_NIC_GOODPUT_INFORM_TYPE 0xf809
#define RATE_LIMIT_NIC_THROUGHPUT_INFORM_TYPE 0xf810

#define RATE_LIMIT_NOTIFY_PERIOD 1000 // ms
#define RATE_LIMIT_NOTIFY_MBPS_PERIOD 1000 // us

struct nic_bandwidth_usage {
	unsigned long l1_cache;
	unsigned long frd_offload;
};

extern struct nic_bandwidth_usage g_mbps_now[];
extern struct nic_bandwidth_usage g_nbu[];
extern uint64_t g_us_notify_prev;

extern void
rate_limit_notify(uint16_t lcore_id, uint16_t port_id, uint64_t us_now);

#ifdef _NOTIFYING_MBPS
extern void
rate_limit_notify_mbps(uint16_t lcore_id, uint16_t port_id, uint64_t us_now);
#endif

#ifdef _GOODPUT
extern void
rate_limit_notify_goodput(uint16_t lcore_id, uint16_t port_id, uint64_t us_now);
#endif

#endif /* __RATE_LIMIT_H__ */
