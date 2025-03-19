#include <string.h>

#include "ps.h"
#include "ip_in.h"
#include "eth_in.h"
#include "arp.h"
#include "debug.h"
#include "nic_cache.h"
#include "rate_limit.h"

#define ETYPE_PAYLOAD_OFFLOAD		0xf80d
#define ETYPE_EVICTION				0xf811
#define NIC_GOODPUT_INFORM_TYPE		0xf809
#define NIC_THROUGHPUT_INFORM_TYPE	0xf810
/*----------------------------------------------------------------------------*/
int
ProcessPacket(mtcp_manager_t mtcp, const int ifidx, 
		uint32_t cur_ts, unsigned char *pkt_data, int len)
{
	struct ethhdr *ethh = (struct ethhdr *)pkt_data;
	u_short ip_proto = ntohs(ethh->h_proto);
	int ret;

#if 0
	TRACE_INFO("src_addr=%x:%x:%x:%x:%x:%x\n", 
			ethh->h_source[0], ethh->h_source[1], ethh->h_source[2],
			ethh->h_source[3], ethh->h_source[4], ethh->h_source[5]);
	TRACE_INFO("dst_addr=%x:%x:%x:%x:%x:%x, len=%d\n",
			ethh->h_dest[0], ethh->h_dest[1], ethh->h_dest[2],
			ethh->h_dest[3], ethh->h_dest[4], ethh->h_dest[5], len);
#endif

#ifdef PKTDUMP
	DumpPacket(mtcp, (char *)pkt_data, len, "IN", ifidx);
#endif

#ifdef NETSTAT
	mtcp->nstat.rx_packets[ifidx]++;
	mtcp->nstat.rx_bytes[ifidx] += len + 24;
#endif /* NETSTAT */

	if (ip_proto == ETH_P_IP) {
		/* process ipv4 packet */
		ret = ProcessIPv4Packet(mtcp, cur_ts, ifidx, pkt_data, len);
	} else if (ip_proto == ETH_P_ARP) {
		ProcessARPPacket(mtcp, cur_ts, ifidx, pkt_data, len);
		return TRUE;
	} 
#if ENABLE_NIC_CACHE && ENABLE_NIC_CACHE_FUNC_CALL
	else if (ip_proto == ETYPE_PAYLOAD_OFFLOAD || ip_proto == ETYPE_EVICTION) {
		CONTROL_PLANE_ENQUEUE_REPLY(mtcp, pkt_data, cur_ts);
		return TRUE;
	} 
#endif
	else if (ip_proto == NIC_THROUGHPUT_INFORM_TYPE) {
		rate_limit_update(mtcp, pkt_data);
#ifdef _GOODPUT
	} else if (ip_proto == NIC_GOODPUT_INFORM_TYPE) {
		rate_limit_get_goodput(mtcp, pkt_data);
#endif
#if RATE_LIMIT_CACHE_ENABLE_NOTIFY_MBPS
	} else if (ip_proto == RATE_LIMIT_CACHE_NOTIFYING_MBPS_TYPE) {
		rate_limit_cache_update_mbps(mtcp, pkt_data);
#endif  /* RATE_LIMIT_CACHE_ENABLE_NOTIFY_MBPS */
	} else {
		mtcp->iom->release_pkt(mtcp->ctx, ifidx, pkt_data, len);
		return TRUE;
	}

#ifdef NETSTAT
	if (ret < 0) {
		mtcp->nstat.rx_errors[ifidx]++;
	}
#endif

	return ret;
}
