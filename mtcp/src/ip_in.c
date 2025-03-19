#include <string.h>
#include <netinet/ip.h>

#include "ip_in.h"
#include "tcp_in.h"
#include "mtcp_api.h"
#include "ps.h"
#include "debug.h"
#include "icmp.h"

#if ENABLE_NIC_CACHE
#include "nic_cache.h"
#endif

#include "frd_offload_ctrl.h"

#define ETH_P_IP_FRAG   0xF800
#define ETH_P_IPV6_FRAG 0xF6DD

#define IPH_ECHO_FLAGS 0x40

#ifdef ENABLE_RTT_CHECK
#include "meta_offload.h"

extern void
meta_offload_process_rtt_packet(meta_offload *mo, struct iphdr *iph);
#endif

/*----------------------------------------------------------------------------*/
inline int 
ProcessIPv4Packet(mtcp_manager_t mtcp, uint32_t cur_ts, 
				  const int ifidx, unsigned char* pkt_data, int len)
{
	/* check and process IPv4 packets */
	struct iphdr* iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
	int ip_len = ntohs(iph->tot_len);
	int rc = -1;

#if ENABLE_NIC_CACHE && ENABLE_ECHO
	if (iph->tos == 4) 
		return ProcessEchoPacket(mtcp, cur_ts, iph);
#endif

#ifdef ENABLE_RTT_CHECK
	if (iph->tos == 0xfb) {
		meta_offload_process_rtt_packet(mtcp->mo, iph);
		return TRUE;
	}
#endif

	if (iph->tos > 0) 
		return foc_proc_reply(mtcp, iph, cur_ts, len);

	/* drop the packet shorter than ip header */
	if (ip_len < sizeof(struct iphdr))
		return ERROR;

#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
#if ENABLE_MULTI_TX_QUEUE
        rc = mtcp->iom->dev_ioctl(mtcp->ctx, ifidx, PKT_RX_IP_CSUM, iph, 0);
#else
        rc = mtcp->iom->dev_ioctl(mtcp->ctx, ifidx, PKT_RX_IP_CSUM, iph);
#endif
	if (rc == -1 && ip_fast_csum(iph, iph->ihl))
		return ERROR;
#else
	UNUSED(rc);
	if (ip_fast_csum(iph, iph->ihl))
		return ERROR;
#endif

#if !PROMISCUOUS_MODE
	/* if not promiscuous mode, drop if the destination is not myself */
	if (iph->daddr != CONFIG.eths[ifidx].ip_addr)
		return TRUE;
#endif

	// see if the version is correct
	if (iph->version != 0x4 ) {
		mtcp->iom->release_pkt(mtcp->ctx, ifidx, pkt_data, len);
		return FALSE;
	}
	
	switch (iph->protocol) {
		case IPPROTO_TCP:
			return ProcessTCPPacket(mtcp, cur_ts, ifidx, iph, ip_len);
		case IPPROTO_ICMP:
			return ProcessICMPPacket(mtcp, iph, ip_len);
		default:
			/* currently drop other protocols */
			return FALSE;
	}
	return FALSE;
}
/*----------------------------------------------------------------------------*/
