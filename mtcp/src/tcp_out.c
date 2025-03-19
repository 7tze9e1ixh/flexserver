#include <unistd.h>
#include <rte_ethdev.h>
#include "tcp_out.h"
#include "tcp_util.h"
#include "mtcp.h"
#include "ip_out.h"
#include "tcp_in.h"
#include "tcp_stream.h"
#include "eventpoll.h"
#include "timer.h"
#include "debug.h"
#include "rate_limit.h"
#include "frd_offload_ctrl.h"
#include "cache_buffer.h"
#include "frd_rate_limit.h"
#include "util.h"
#include "general_data_buffer.h"
#if RATE_LIMIT_ENABLED || PACING_ENABLED
#include "pacing.h"
#endif

#if ENABLE_NIC_CACHE
#include "nic_cache.h"
#endif

#if ZERO_COPY
#include "zero_copy.h"
#endif

#include "flex_buffer.h"
#include "meta_offload.h"

#define TCP_CALCULATE_CHECKSUM      TRUE
#define ACK_PIGGYBACK				TRUE
#define TRY_SEND_BEFORE_QUEUE		FALSE

#define TCP_MAX_WINDOW 65535

#if ENABLE_NIC_CACHE && LIMIT_MAX_META_PAYLOADLEN
static uint16_t GetMaxTSOPacketSize(uint16_t hdrlen);
#endif

/*----------------------------------------------------------------------------*/
static inline uint16_t
CalculateOptionLength(uint8_t flags)
{
	uint16_t optlen = 0;

	if (flags & TCP_FLAG_SYN) {
		optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
		optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
#endif /* TCP_OPT_SACK_ENABLED */

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_SACK_ENABLED */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		optlen += TCP_OPT_WSCALE_LEN + 1;

	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_FLAG_SACK) {
			optlen += TCP_OPT_SACK_LEN + 2;
		}
#endif
	}

	assert(optlen % 4 == 0);

	return optlen;
}
/*----------------------------------------------------------------------------*/
static inline void
GenerateTCPTimestamp(tcp_stream *cur_stream, uint8_t *tcpopt, uint32_t cur_ts)
{
	uint32_t *ts = (uint32_t *)(tcpopt + 2);

	tcpopt[0] = TCP_OPT_TIMESTAMP;
	tcpopt[1] = TCP_OPT_TIMESTAMP_LEN;
	ts[0] = htonl(cur_ts);
	ts[1] = htonl(cur_stream->rcvvar->ts_recent);
}
/*----------------------------------------------------------------------------*/
static inline void
GenerateTCPOptions(tcp_stream *cur_stream, uint32_t cur_ts, 
		uint8_t flags, uint8_t *tcpopt, uint16_t optlen)
{
	int i = 0;

	if (flags & TCP_FLAG_SYN) {
		uint16_t mss;

		/* MSS option */
		mss = cur_stream->sndvar->mss;
		tcpopt[i++] = TCP_OPT_MSS;
		tcpopt[i++] = TCP_OPT_MSS_LEN;
		tcpopt[i++] = mss >> 8;
		tcpopt[i++] = mss % 256;

		/* SACK permit */
#if TCP_OPT_SACK_ENABLED
#if !TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
		tcpopt[i++] = TCP_OPT_SACK_PERMIT;
		tcpopt[i++] = TCP_OPT_SACK_PERMIT_LEN;
		TRACE_SACK("Local SACK permited.\n");
#endif /* TCP_OPT_SACK_ENABLED */

		/* Timestamp */
#if TCP_OPT_TIMESTAMP_ENABLED
#if !TCP_OPT_SACK_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_SACK_ENABLED */
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		/* Window scale */
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_WSCALE;
		tcpopt[i++] = TCP_OPT_WSCALE_LEN;
		tcpopt[i++] = cur_stream->sndvar->wscale_mine;

	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_OPT_SACK) {
			// i += GenerateSACKOption(cur_stream, tcpopt + i);
		}
#endif
	}

	assert (i == optlen);
}
/*----------------------------------------------------------------------------*/
__attribute__((hot)) inline int
SendTCPPacketStandalone(struct mtcp_manager *mtcp, 
		uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, 
		uint32_t seq, uint32_t ack_seq, uint16_t window, uint8_t flags, 
		uint8_t *payload, uint16_t payloadlen, 
		uint32_t cur_ts, uint32_t echo_ts)
{
	struct tcphdr *tcph;
	uint8_t *tcpopt;
	uint32_t *ts;
	uint16_t optlen;
	int rc = -1;

	optlen = CalculateOptionLength(flags);
	if (payloadlen + optlen > TCP_DEFAULT_MSS) {
		TRACE_ERROR("Payload size exceeds MSS.\n");
		assert(0);
		return ERROR;
	}

	tcph = (struct tcphdr *)IPOutputStandalone(mtcp, IPPROTO_TCP, 0, 
			saddr, daddr, TCP_HEADER_LEN + optlen + payloadlen);
	if (tcph == NULL) {
		return ERROR;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = sport;
	tcph->dest = dport;

	if (flags & TCP_FLAG_SYN)
		tcph->syn = TRUE;
	if (flags & TCP_FLAG_FIN)
		tcph->fin = TRUE;
	if (flags & TCP_FLAG_RST)
		tcph->rst = TRUE;
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	tcph->seq = htonl(seq);
	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(ack_seq);
	}

	tcph->window = htons(MIN(window, TCP_MAX_WINDOW));

	tcpopt = (uint8_t *)tcph + TCP_HEADER_LEN;
	ts = (uint32_t *)(tcpopt + 4);

	tcpopt[0] = TCP_OPT_NOP;
	tcpopt[1] = TCP_OPT_NOP;
	tcpopt[2] = TCP_OPT_TIMESTAMP;
	tcpopt[3] = TCP_OPT_TIMESTAMP_LEN;
	ts[0] = htonl(cur_ts);
	ts[1] = htonl(echo_ts);

	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	if (payloadlen > 0) {
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
#if defined(NETSTAT) && defined(ENABLELRO)
		mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
	}
		
#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
	uint8_t is_external;
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, GetOutputInterface(daddr, &is_external),
					  PKT_TX_TCPIP_CSUM, NULL);
	UNUSED(is_external);
#endif
	if (rc == -1)
		tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
					      TCP_HEADER_LEN + optlen + payloadlen,
					      saddr, daddr);
#endif

	if (tcph->syn || tcph->fin) {
		payloadlen++;
	}

	INCR_TOT_PKTS(mtcp->ctx->cpu);

	return payloadlen;
}
/*----------------------------------------------------------------------------*/
extern int32_t dpdk_set_mbuf_hw_offload(struct rte_mbuf *m, int cmd);

/*----------------------------------------------------------------------------*/
__attribute__((hot)) static inline  int
SendGeneralData(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t flags, flex_buffer *flex_buf, uint16_t payloadlen)
{
	struct tcphdr *tcph;
	uint16_t optlen;
	uint8_t wscale = 0;
	uint32_t window32 = 0;
	int rc = -1;
	struct rte_mbuf *m = NULL;
#if ENABLE_META_TX_QUEUE
	flex_buffer *flex_buf_next = TAILQ_NEXT(flex_buf, flex_buffer_link);
#endif

	optlen = CalculateOptionLength(flags);
#if 0
	if (payloadlen + optlen > cur_stream->sndvar->mss) {
		TRACE_ERROR("Payload size exceeds MSS\n");
		return ERROR;
	}
#endif

	payloadlen = MIN(payloadlen,
			flex_buffer_get_remaining_length(flex_buf, cur_stream->snd_nxt));

	//TRACE_INFO("payloadlen:%u\n", payloadlen);

#if 0
	if (payloadlen != flex_buf->data_len) {
		TRACE_INFO("flex_buffer_get_remaining_length() error\n");
	}
#endif

#if ENABLE_META_TX_QUEUE
	if (flex_buf_next && flex_buf_next->type == L1_CACHE_BUFFER) {
#if ENABLE_APP_HDR_BATCH
		tcph = (struct tcphdr *)meta_offload_generate_ipv4_packet(mtcp->mo, cur_stream,
				TCP_HEADER_LEN + optlen + payloadlen, 
				META_OFFLOAD_APP_HDR, cur_ts);
#else
		tcph = (struct tcphdr *)IPOutputExt(mtcp, cur_stream,
				TCP_HEADER_LEN + optlen + payloadlen, (void **)&m);
		assert(m != NULL);
#endif
	} else {
		tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream, 
			TCP_HEADER_LEN + optlen + payloadlen);
		mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out, GET_MBUF, &m);
	}
#else
	tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream, 
			TCP_HEADER_LEN + optlen + payloadlen);
	mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out, GET_MBUF, &m);
#endif /* ENABLE_META_TX_QUEUE */

#if SHOW_NIC_CACHE_STATISTICS
	g_nic_cache_stat[mtcp->ctx->cpu].tx_bytes += payloadlen;
#endif /* SHOW_NIC_CACHE_STATISTICS */

	if (tcph == NULL) {
		return -2;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
		if (cur_stream->snd_nxt != cur_stream->sndvar->iss) {
			TRACE_DBG("Stream %d: weird SYN sequence. "
					"snd_nxt: %u, iss: %u\n", cur_stream->id, 
					cur_stream->snd_nxt, cur_stream->sndvar->iss);
		}
#if 0
		TRACE_FIN("Stream %d: Sending SYN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
#endif
	}
	if (flags & TCP_FLAG_RST) {
		TRACE_FIN("Stream %d: Sending RST.\n", cur_stream->id);
		tcph->rst = TRUE;
	}
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	if (flags & TCP_FLAG_WACK) {
		tcph->seq = htonl(cur_stream->snd_nxt - 1);
		TRACE_CLWND("%u Sending ACK to get new window advertisement. "
				"seq: %u, peer_wnd: %u, snd_nxt - snd_una: %u\n", 
				cur_stream->id,
				cur_stream->snd_nxt - 1, cur_stream->sndvar->peer_wnd, 
				cur_stream->snd_nxt - cur_stream->sndvar->snd_una);
	} else if (flags & TCP_FLAG_FIN) {
		tcph->fin = TRUE;
		
		if (cur_stream->sndvar->fss == 0) {
			TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
					cur_stream->id, cur_stream->closed);
		}
		tcph->seq = htonl(cur_stream->sndvar->fss);
		cur_stream->sndvar->is_fin_sent = TRUE;
		TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
	} else {
		tcph->seq = htonl(cur_stream->snd_nxt);
	}

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(cur_stream->rcv_nxt);
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		UpdateTimeoutList(mtcp, cur_stream);
	}

	if (flags & TCP_FLAG_SYN) {
		wscale = 0;
	} else {
		wscale = cur_stream->sndvar->wscale_mine;
	}

	window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
	tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
	/* if the advertised window is 0, we need to advertise again later */
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}

	GenerateTCPOptions(cur_stream, cur_ts, flags, 
			(uint8_t *)tcph + TCP_HEADER_LEN, optlen);
	
	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
#if ENABLE_APP_HDR_BATCH
	if (flex_buf_next && flex_buf_next->type == L1_CACHE_BUFFER) {
		general_data_buffer *gdb = flex_buf->opaque;
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, gdb->data, payloadlen);
	} else {
		zero_copy_set(mtcp, m, cur_stream->snd_nxt, flex_buf, payloadlen);
	}
#else
	zero_copy_set(mtcp, m, cur_stream->snd_nxt, flex_buf, payloadlen);
#endif /* ENABLE_APP_HDR_BATCH */

#if SHOW_NIC_CACHE_STATISTICS
	//TRACE_INFO("diskRead += %d", payloadlen);
	g_nic_cache_stat[mtcp->ctx->cpu].tx_diskRead += payloadlen;
#endif /* SHOW_NIC_CACHE_STATISTICS */

#if defined(NETSTAT) && defined(ENABLELRO)
	mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL) {
#if ENABLE_APP_HDR_BATCH
		if (flex_buf_next && flex_buf_next->type != L1_CACHE_BUFFER) 
#endif /* ENABLE_APP_HDR_BATCH */
		rc = dpdk_set_mbuf_hw_offload(m, PKT_TX_TCPIP_CSUM);
	}
#endif
	if (rc == -1) {
		tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
					      TCP_HEADER_LEN + optlen + payloadlen, 
					      cur_stream->saddr, cur_stream->daddr);
	}
#endif
	
	cur_stream->snd_nxt += payloadlen;

	if (tcph->syn || tcph->fin) {
		cur_stream->snd_nxt++;
		payloadlen++;
	}

	if (payloadlen > 0) {
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
					payloadlen, cur_stream->snd_nxt);
		}

		/* update retransmission timer if have payload */
		cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		TRACE_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n", 
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);

		AddtoRTOList(mtcp, cur_stream);
	}

#if ENABLE_META_TX_QUEUE
#if !ENABLE_APP_HDR_BATCH
	uint16_t nif_out = cur_stream->sndvar->nif_out;
	uint16_t qid = GET_META_TX_QID(mtcp->ctx->cpu);

#if ENABLE_MULTI_VFS
	nif_out = 1;
	qid = mtcp->ctx->cpu;
#endif
	if (flex_buf_next && flex_buf_next->type == L1_CACHE_BUFFER) {
		/* TRACE_INFO("cpu:%u, qid:%u\n",
				mtcp->ctx->cpu, GET_META_TX_QID(mtcp->ctx->cpu));*/
		do {
			rc = rte_eth_tx_burst(nif_out, qid, (struct rte_mbuf **)&m, 1);
		} while (rc != 1);
	}
#endif /* ENABLE_APP_HDR_BATCH */
#endif /* ENABLE_META_TX_QUEUE */
		
	return payloadlen;
}
/*----------------------------------------------------------------------------*/
__attribute__((hot)) inline static int
SendFileBufferData(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t flags, flex_buffer *flex_buf, uint16_t payloadlen)
{
	struct tcphdr *tcph;
	uint16_t optlen;
	uint8_t wscale = 0;
	uint32_t window32 = 0;
	int rc = -1;

	optlen = CalculateOptionLength(flags);

	payloadlen = MIN((uint32_t)payloadlen, 
			flex_buffer_get_remaining_length(flex_buf, cur_stream->snd_nxt));

	tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream, 
			TCP_HEADER_LEN + optlen + payloadlen);

#if SHOW_NIC_CACHE_STATISTICS
	g_nic_cache_stat[mtcp->ctx->cpu].tx_bytes += payloadlen;
#endif /* SHOW_NIC_CACHE_STATISTICS */

	if (tcph == NULL) {
		return -2;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
		if (cur_stream->snd_nxt != cur_stream->sndvar->iss) {
			TRACE_DBG("Stream %d: weird SYN sequence. "
					"snd_nxt: %u, iss: %u\n", cur_stream->id, 
					cur_stream->snd_nxt, cur_stream->sndvar->iss);
		}
#if 0
		TRACE_FIN("Stream %d: Sending SYN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
#endif
	}
	if (flags & TCP_FLAG_RST) {
		TRACE_FIN("Stream %d: Sending RST.\n", cur_stream->id);
		tcph->rst = TRUE;
	}
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	if (flags & TCP_FLAG_WACK) {
		tcph->seq = htonl(cur_stream->snd_nxt - 1);
		TRACE_CLWND("%u Sending ACK to get new window advertisement. "
				"seq: %u, peer_wnd: %u, snd_nxt - snd_una: %u\n", 
				cur_stream->id,
				cur_stream->snd_nxt - 1, cur_stream->sndvar->peer_wnd, 
				cur_stream->snd_nxt - cur_stream->sndvar->snd_una);
	} else if (flags & TCP_FLAG_FIN) {
		tcph->fin = TRUE;
		
		if (cur_stream->sndvar->fss == 0) {
			TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
					cur_stream->id, cur_stream->closed);
		}
		tcph->seq = htonl(cur_stream->sndvar->fss);
		cur_stream->sndvar->is_fin_sent = TRUE;
		TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
	} else {
		tcph->seq = htonl(cur_stream->snd_nxt);
	}

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(cur_stream->rcv_nxt);
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		UpdateTimeoutList(mtcp, cur_stream);
	}

	if (flags & TCP_FLAG_SYN) {
		wscale = 0;
	} else {
		wscale = cur_stream->sndvar->wscale_mine;
	}

	window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
	tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
	/* if the advertised window is 0, we need to advertise again later */
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}

	GenerateTCPOptions(cur_stream, cur_ts, flags, 
			(uint8_t *)tcph + TCP_HEADER_LEN, optlen);
	
	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	if (payloadlen > 0) {
		struct rte_mbuf *m;
#if USE_OLD_RATE_LIMIT
		//rl_incr_tx_bytes(mtcp, payloadlen);
#endif
		mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out, GET_MBUF, &m);
		zero_copy_set(mtcp, m, cur_stream->snd_nxt, flex_buf, payloadlen);

#if SHOW_NIC_CACHE_STATISTICS
		g_nic_cache_stat[mtcp->ctx->cpu].tx_diskRead += payloadlen;
#endif /* SHOW_NIC_CACHE_STATISTICS */

#if defined(NETSTAT) && defined(ENABLELRO)
		mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
		//mtcp->tx_bytes += payloadlen;
	}

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
					  PKT_TX_TCPIP_CSUM, NULL);
#endif
	if (rc == -1)
		tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
					      TCP_HEADER_LEN + optlen + payloadlen, 
					      cur_stream->saddr, cur_stream->daddr);
#endif
	
	cur_stream->snd_nxt += payloadlen;

	if (tcph->syn || tcph->fin) {
		cur_stream->snd_nxt++;
		payloadlen++;
	}

	if (payloadlen > 0) {
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
					payloadlen, cur_stream->snd_nxt);
		}

		/* update retransmission timer if have payload */
		cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		TRACE_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n", 
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);

		AddtoRTOList(mtcp, cur_stream);
	}

#ifdef ENABLE_DUMMY_CMD
	meta_offload_generate_dummy_packet(mtcp->mo, cur_stream, tcph, TCP_HEADER_LEN + optlen, cur_ts);
#endif
		
	return payloadlen;
}
/*----------------------------------------------------------------------------*/
__attribute__((hot)) inline int
SendTCPPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen)
{
	struct tcphdr *tcph;
	uint16_t optlen;
	uint8_t wscale = 0;
	uint32_t window32 = 0;
	int rc = -1;

	optlen = CalculateOptionLength(flags);
#if 0
	if (payloadlen + optlen > cur_stream->sndvar->mss) {
		TRACE_ERROR("Payload size exceeds MSS\n");
		return ERROR;
	}
#endif
	tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream, 
			TCP_HEADER_LEN + optlen + payloadlen);
#if SHOW_NIC_CACHE_STATISTICS
	g_nic_cache_stat[mtcp->ctx->cpu].tx_bytes += payloadlen;
#endif /* SHOW_NIC_CACHE_STATISTICS */

	if (tcph == NULL) {
		return -2;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
		if (cur_stream->snd_nxt != cur_stream->sndvar->iss) {
			TRACE_DBG("Stream %d: weird SYN sequence. "
					"snd_nxt: %u, iss: %u\n", cur_stream->id, 
					cur_stream->snd_nxt, cur_stream->sndvar->iss);
		}
#if 0
		TRACE_FIN("Stream %d: Sending SYN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
#endif
	}
	if (flags & TCP_FLAG_RST) {
		TRACE_FIN("Stream %d: Sending RST.\n", cur_stream->id);
		tcph->rst = TRUE;
	}
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	if (flags & TCP_FLAG_WACK) {
		tcph->seq = htonl(cur_stream->snd_nxt - 1);
		TRACE_CLWND("%u Sending ACK to get new window advertisement. "
				"seq: %u, peer_wnd: %u, snd_nxt - snd_una: %u\n", 
				cur_stream->id,
				cur_stream->snd_nxt - 1, cur_stream->sndvar->peer_wnd, 
				cur_stream->snd_nxt - cur_stream->sndvar->snd_una);
	} else if (flags & TCP_FLAG_FIN) {
		tcph->fin = TRUE;
		
		if (cur_stream->sndvar->fss == 0) {
			TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
					cur_stream->id, cur_stream->closed);
		}
		tcph->seq = htonl(cur_stream->sndvar->fss);
		cur_stream->sndvar->is_fin_sent = TRUE;
		TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
	} else {
		tcph->seq = htonl(cur_stream->snd_nxt);
	}
/*
	if (payloadlen > 0) {
		NIC_CACHE_LOG_TCP_SEQ("[REAL] stream(%p), port=%u, tcp.seq=%u(%u), "
				"payloadlen=%u, rto=%u, cur_ts=%u\n",
			cur_stream, ntohs(cur_stream->dport), cur_stream->snd_nxt,
			cur_stream->snd_nxt - cur_stream->sndvar->sndbuf->init_seq,
			payloadlen, cur_stream->sndvar->rto, cur_ts);
	}*/

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(cur_stream->rcv_nxt);
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		UpdateTimeoutList(mtcp, cur_stream);
	}

	if (flags & TCP_FLAG_SYN) {
		wscale = 0;
	} else {
		wscale = cur_stream->sndvar->wscale_mine;
	}

	window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
	tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
	/* if the advertised window is 0, we need to advertise again later */
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}

	GenerateTCPOptions(cur_stream, cur_ts, flags, 
			(uint8_t *)tcph + TCP_HEADER_LEN, optlen);
	
	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	if (payloadlen > 0) {
		//TRACE_INFO("payloadlen:%u\n", payloadlen);
#if USE_OLD_RATE_LIMIT
		//rl_incr_tx_bytes(mtcp, payloadlen);
#endif
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);


#if defined(NETSTAT) && defined(ENABLELRO)
		mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
		//mtcp->tx_bytes += payloadlen;
	}

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
					  PKT_TX_TCPIP_CSUM, NULL);
#endif
	if (rc == -1)
		tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
					      TCP_HEADER_LEN + optlen + payloadlen, 
					      cur_stream->saddr, cur_stream->daddr);
#endif
	
	cur_stream->snd_nxt += payloadlen;

	if (tcph->syn || tcph->fin) {
		cur_stream->snd_nxt++;
		payloadlen++;
	}

	if (payloadlen > 0) {
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
					payloadlen, cur_stream->snd_nxt);
		}

		/* update retransmission timer if have payload */
		cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		TRACE_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n", 
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);
		/*
		NIC_CACHE_LOG_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n",
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);*/
		AddtoRTOList(mtcp, cur_stream);
	}
		
	return payloadlen;
}
/*----------------------------------------------------------------------------*/
#if ENABLE_NIC_CACHE
inline static int
SendControlPlaneCachedPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t flags, flex_buffer *flex_buf, uint16_t payloadlen)
{
	struct tcphdr *tcph;
	uint16_t optlen;
	uint8_t wscale = 0;
	uint32_t window32 = 0;
	int rc = -1;

	optlen = CalculateOptionLength(flags);
	assert(payloadlen >= 0);
#if 0
	if (payloadlen + optlen > cur_stream->sndvar->mss) {
		TRACE_ERROR("Payload size exceeds MSS\n");
		return ERROR;
	}
#endif
	tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream, 
			TCP_HEADER_LEN + optlen + payloadlen);

	if (tcph == NULL) {
		return -2;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
		if (cur_stream->snd_nxt != cur_stream->sndvar->iss) {
			TRACE_DBG("Stream %d: weird SYN sequence. "
					"snd_nxt: %u, iss: %u\n", cur_stream->id, 
					cur_stream->snd_nxt, cur_stream->sndvar->iss);
		}
#if 0
		TRACE_FIN("Stream %d: Sending SYN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
#endif
	}
	if (flags & TCP_FLAG_RST) {
		TRACE_FIN("Stream %d: Sending RST.\n", cur_stream->id);
		tcph->rst = TRUE;
	}
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	if (flags & TCP_FLAG_WACK) {
		tcph->seq = htonl(cur_stream->snd_nxt - 1);
		TRACE_CLWND("%u Sending ACK to get new window advertisement. "
				"seq: %u, peer_wnd: %u, snd_nxt - snd_una: %u\n", 
				cur_stream->id,
				cur_stream->snd_nxt - 1, cur_stream->sndvar->peer_wnd, 
				cur_stream->snd_nxt - cur_stream->sndvar->snd_una);
	} else if (flags & TCP_FLAG_FIN) {
		tcph->fin = TRUE;
		
		if (cur_stream->sndvar->fss == 0) {
			TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
					cur_stream->id, cur_stream->closed);
		}
		tcph->seq = htonl(cur_stream->sndvar->fss);
		cur_stream->sndvar->is_fin_sent = TRUE;
		TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
	} else {
		tcph->seq = htonl(cur_stream->snd_nxt);
	}
/*
	if (payloadlen > 0) {
		NIC_CACHE_LOG_TCP_SEQ("[REAL] stream(%p), port=%u, tcp.seq=%u(%u), "
				"payloadlen=%u, rto=%u, cur_ts=%u\n",
			cur_stream, ntohs(cur_stream->dport), cur_stream->snd_nxt,
			cur_stream->snd_nxt - cur_stream->sndvar->sndbuf->init_seq,
			payloadlen, cur_stream->sndvar->rto, cur_ts);
	}*/

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(cur_stream->rcv_nxt);
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		UpdateTimeoutList(mtcp, cur_stream);
	}

	if (flags & TCP_FLAG_SYN) {
		wscale = 0;
	} else {
		wscale = cur_stream->sndvar->wscale_mine;
	}

	window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
	tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
	/* if the advertised window is 0, we need to advertise again later */
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}

	GenerateTCPOptions(cur_stream, cur_ts, flags, 
			(uint8_t *)tcph + TCP_HEADER_LEN, optlen);
	
	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	if (payloadlen > 0) {
		struct rte_mbuf *m;

		mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out, GET_MBUF, &m);
		zero_copy_set(mtcp, m, cur_stream->snd_nxt, flex_buf, payloadlen);

#if SHOW_NIC_CACHE_STATISTICS
		g_nic_cache_stat[mtcp->ctx->cpu].tx_bytes += payloadlen;
		g_nic_cache_stat[mtcp->ctx->cpu].tx_l2cache += payloadlen;
#endif /* SHOW_NIC_CACHE_STATISTICS */


#if defined(NETSTAT) && defined(ENABLELRO)
		mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
	}

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
					  PKT_TX_TCPIP_CSUM, NULL);
#endif
	if (rc == -1)
		tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
					      TCP_HEADER_LEN + optlen + payloadlen, 
					      cur_stream->saddr, cur_stream->daddr);
#endif
	
	cur_stream->snd_nxt += payloadlen;

	if (tcph->syn || tcph->fin) {
		cur_stream->snd_nxt++;
		payloadlen++;
	}

	if (payloadlen > 0) {
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
					payloadlen, cur_stream->snd_nxt);
		}

		/* update retransmission timer if have payload */
		cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		TRACE_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n", 
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);
		/*
		NIC_CACHE_LOG_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n",
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);*/
		AddtoRTOList(mtcp, cur_stream);
	}

	return payloadlen;
}

inline static int
SendFrdOffloadPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t flags, flex_buffer *flex_buf, uint32_t payloadlen)
{
	struct tcphdr *tcph;
	uint16_t optlen;
	uint8_t wscale = 0;
	uint32_t window32 = 0;
	struct frd_offload_hdr *foh;
	
	INCR_TOT_PKTS(mtcp->ctx->cpu);

	optlen = CalculateOptionLength(flags);

#if ENABLE_META_BATCH
	tcph = (struct tcphdr *)meta_offload_generate_ipv4_packet(mtcp->mo,
			cur_stream,
			TCP_HEADER_LEN + optlen + sizeof(struct frd_offload_hdr),
			META_OFFLOAD_FRD_SEND,
			cur_ts);
#else
	tcph = (struct tcphdr *)IPFrdOffload(mtcp, cur_stream, 
			TCP_HEADER_LEN + optlen + sizeof(struct frd_offload_hdr));
#endif

	if (tcph == NULL) {
		return -2;
	}

	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
		if (cur_stream->snd_nxt != cur_stream->sndvar->iss) {
			TRACE_DBG("Stream %d: weird SYN sequence. "
					"snd_nxt: %u, iss: %u\n", cur_stream->id, 
					cur_stream->snd_nxt, cur_stream->sndvar->iss);
		}
	}
	if (flags & TCP_FLAG_RST) {
		TRACE_FIN("Stream %d: Sending RST.\n", cur_stream->id);
		tcph->rst = TRUE;
	}
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	if (flags & TCP_FLAG_WACK) {
		tcph->seq = htonl(cur_stream->snd_nxt - 1);
		TRACE_CLWND("%u Sending ACK to get new window advertisement. "
				"seq: %u, peer_wnd: %u, snd_nxt - snd_una: %u\n", 
				cur_stream->id,
				cur_stream->snd_nxt - 1, cur_stream->sndvar->peer_wnd, 
				cur_stream->snd_nxt - cur_stream->sndvar->snd_una);
	} else if (flags & TCP_FLAG_FIN) {
		tcph->fin = TRUE;
		
		if (cur_stream->sndvar->fss == 0) {
			TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
					cur_stream->id, cur_stream->closed);
		}
		tcph->seq = htonl(cur_stream->sndvar->fss);
		cur_stream->sndvar->is_fin_sent = TRUE;
		TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
	} else {
		tcph->seq = htonl(cur_stream->snd_nxt);
	}

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(cur_stream->rcv_nxt);
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		UpdateTimeoutList(mtcp, cur_stream);
	}

	if (flags & TCP_FLAG_SYN) {
		wscale = 0;
	} else {
		wscale = cur_stream->sndvar->wscale_mine;
	}

	window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
	tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
	/* if the advertised window is 0, we need to advertise again later */
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}

	GenerateTCPOptions(cur_stream, cur_ts, flags, 
			(uint8_t *)tcph + TCP_HEADER_LEN, optlen);
	
	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	if (payloadlen > 0) {
		uint64_t offset;
		uint32_t seq = cur_stream->snd_nxt;
		struct foc_tx_state *fts = flex_buf->opaque;

		offset = flex_buffer_get_offset(flex_buf, seq);

		foh = (struct frd_offload_hdr *)((uint8_t *)tcph + TCP_HEADER_LEN + optlen);
		foh->toSend = payloadlen;
		foh->offset = offset;
		foh->id = fts->id;
#if defined(NETSTAT) && defined(ENABLELRO)
		mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
	}

	cur_stream->snd_nxt += payloadlen;

	if (tcph->syn || tcph->fin) {
		cur_stream->snd_nxt++;
		payloadlen++;
	}

	if (payloadlen > 0) {
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
					payloadlen, cur_stream->snd_nxt);
		}
#if !ENABLE_ECHO
		cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		TRACE_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n",
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);

		NIC_CACHE_LOG_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n",
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);
		AddtoRTOList(mtcp, cur_stream);
#endif
	}

	return payloadlen;
}

inline static int
SendTransmissionMetaPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t flags, flex_buffer *flex_buf, uint32_t payloadlen)
{
	struct tcphdr *tcph;
	uint16_t optlen;
	uint8_t wscale;
	uint32_t window32;
	trans_meta *tmh;
	
	INCR_TOT_PKTS(mtcp->ctx->cpu);

	optlen = CalculateOptionLength(flags);

#if ENABLE_META_BATCH
	tcph = (struct tcphdr *)meta_offload_generate_ipv4_packet(mtcp->mo, 
			cur_stream, 
			TCP_HEADER_LEN + optlen + sizeof(trans_meta),
			META_OFFLOAD_CACHE,
			cur_ts);
#else
	tcph = (struct tcphdr *)IPTransmissionOffload(mtcp, cur_stream, 
			TCP_HEADER_LEN + optlen + sizeof(trans_meta));
#endif

	if (tcph == NULL) {
		return -2;
	}

	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
		if (cur_stream->snd_nxt != cur_stream->sndvar->iss) {
			TRACE_DBG("Stream %d: weird SYN sequence. "
					"snd_nxt: %u, iss: %u\n", cur_stream->id, 
					cur_stream->snd_nxt, cur_stream->sndvar->iss);
		}
	}
	if (flags & TCP_FLAG_RST) {
		TRACE_FIN("Stream %d: Sending RST.\n", cur_stream->id);
		tcph->rst = TRUE;
	}
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	if (flags & TCP_FLAG_WACK) {
		tcph->seq = htonl(cur_stream->snd_nxt - 1);
		TRACE_CLWND("%u Sending ACK to get new window advertisement. "
				"seq: %u, peer_wnd: %u, snd_nxt - snd_una: %u\n", 
				cur_stream->id,
				cur_stream->snd_nxt - 1, cur_stream->sndvar->peer_wnd, 
				cur_stream->snd_nxt - cur_stream->sndvar->snd_una);
	} else if (flags & TCP_FLAG_FIN) {
		tcph->fin = TRUE;
		
		if (cur_stream->sndvar->fss == 0) {
			TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
					cur_stream->id, cur_stream->closed);
		}
		tcph->seq = htonl(cur_stream->sndvar->fss);
		cur_stream->sndvar->is_fin_sent = TRUE;
		TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
	} else {
		tcph->seq = htonl(cur_stream->snd_nxt);
	}

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(cur_stream->rcv_nxt);
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		UpdateTimeoutList(mtcp, cur_stream);
	}

	if (flags & TCP_FLAG_SYN) {
		wscale = 0;
	} else {
		wscale = cur_stream->sndvar->wscale_mine;
	}

	window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
	tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
	/* if the advertised window is 0, we need to advertise again later */
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}

	GenerateTCPOptions(cur_stream, cur_ts, flags, 
			(uint8_t *)tcph + TCP_HEADER_LEN, optlen);
	
	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	
	if (payloadlen > 0) {
		cache_buffer *cb = flex_buf->opaque;
		tmh = (trans_meta *)((uint8_t *)tcph + TCP_HEADER_LEN + optlen);
		tmh->t_hv = cb->hv;
		tmh->t_off = flex_buffer_get_offset(flex_buf, cur_stream->snd_nxt);
		tmh->t_len = payloadlen;

		/* TRACE_INFO("hv=%lu, off=%lu, len=%u, source:%u, dest:%u\n", 
				tmh->t_hv, tmh->t_off, tmh->t_len, tcph->source, tcph->dest);*/

#if defined(NETSTAT) && defined(ENABLELRO)
		mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
	}

	cur_stream->snd_nxt += payloadlen;

	if (tcph->syn || tcph->fin) {
		cur_stream->snd_nxt++;
		payloadlen++;
	}

	if (payloadlen > 0) {
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
					payloadlen, cur_stream->snd_nxt);
		}
#if !ENABLE_ECHO
		cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		TRACE_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n",
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);

		NIC_CACHE_LOG_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n",
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);
		AddtoRTOList(mtcp, cur_stream);
#endif
	}

#if ENABLE_ECHO
	if (cur_stream->on_rto_idx >= 0) {
		RemoveFromRTOList(mtcp, cur_stream);
	}
#endif

	return payloadlen;
}
#endif
/*----------------------------------------------------------------------------*/
#if ENABLE_NIC_CACHE
inline static uint16_t 
GetMaxTSOPacketSize(uint16_t hdrlen)
{
	return MAX_TSO_PKT_SIZE - hdrlen;
}
#endif
/*----------------------------------------------------------------------------*/
#define RATE_LIMIT_ENABLE_SND_WND_LIMIT FALSE
#define RATE_LIMIT_MAX_SND_SIZE_SCALE 64

inline static int
FlushTCPSendingBuffer(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	uint32_t pkt_len;
	uint32_t len;
	uint32_t seq;
	int remaining_window;
	int sndlen;
	int packets = 0;
	int ret;
	uint8_t wack_sent = 0;
#if ENABLE_FLEX_BUFFER
	flex_buffer *flex_buf;
#endif

#if RATE_LIMIT_ENABLE_SND_WND_LIMIT
	uint32_t max_sndlen = (0xffff -
		- CalculateOptionLength(TCP_FLAG_ACK) 
		- TOTAL_TCP_HEADER_LEN) * RATE_LIMIT_MAX_SND_SIZE_SCALE;
#endif
	
	if (!sndvar->sndbuf) {
		TRACE_ERROR("Stream %d: No send buffer available.\n", cur_stream->id);
		assert(0);
		return 0;
	}

#if ZERO_COPY	
	ret = SBUF_TRYLOCK(&sndvar->write_lock);
	if (ret == EBUSY) {
		// return -1;
		goto out;
	}

	assert(ret == 0);
#else
	SBUF_LOCK(&sndvar->write_lock);
#endif

#if ENABLE_NIC_CACHE
	if (sndvar->sndbuf->total_buf_size == 0) {
#else
	if (sndvar->sndbuf->len == 0) {
#endif
		packets = 0;
		goto out;
	}

	while (1) {
#if USE_CCP
		if (sndvar->missing_seq) {
			seq = sndvar->missing_seq;
		} else {
#endif
			seq = cur_stream->snd_nxt;
#if USE_CCP
		}
#endif

#if ENABLE_NIC_CACHE
		len = sndvar->sndbuf->total_buf_size - (seq - sndvar->sndbuf->head_seq);
#else
		len = sndvar->sndbuf->len - (seq - sndvar->sndbuf->head_seq);
#endif

#if ENABLE_OLD_RATE_LIMIT
		if (rl_is_tx_capa(mtcp) < 0) {
			packets = -3;
			goto out;
		}
#endif /* ENABLE_OLD_RATE_LIMIT*/

#if USE_CCP
		 /// Without this, mm continually drops packets (not sure why, bursting?) -> mtcp sees lots of losses -> throughput dies
		  if(cur_stream->wait_for_acks &&
		   TCP_SEQ_GT(cur_stream->snd_nxt, cur_stream->rcvvar->last_ack_seq)) {
			goto out;
		}
#endif
		/* sanity check */
		if (TCP_SEQ_LT(seq, sndvar->sndbuf->head_seq)) {
			TRACE_ERROR("Stream %d: Invalid sequence to send. "
						"state: %s, seq: %u, head_seq: %u.\n",
						cur_stream->id, TCPStateToString(cur_stream),
						seq, sndvar->sndbuf->head_seq);
			assert(0);
			break;
		}
		if (TCP_SEQ_LT(seq, sndvar->snd_una)) {
			TRACE_ERROR("Stream %d: Invalid sequence to send. "
						"state: %s, seq: %u, snd_una: %u.\n",
						cur_stream->id, TCPStateToString(cur_stream),
						seq, sndvar->snd_una);
			assert(0);
			break;
		}
#if ENABLE_NIC_CACHE
		if (sndvar->sndbuf->total_buf_size < (seq - sndvar->sndbuf->head_seq)) {
			TRACE_ERROR("Stream %d: len < 0\n",
						cur_stream->id);
			assert(0);
			break;
		}
#else
		if (sndvar->sndbuf->len < (seq - sndvar->sndbuf->head_seq)) {
			TRACE_ERROR("Stream %d: len < 0\n",
						cur_stream->id);
			assert(0);
			break;
		}
#endif

		/* if there is no buffered data */
		if (len == 0)
			break;
		
#if TCP_OPT_SACK_ENABLED
		if (SeqIsSacked(cur_stream, seq)) {
			TRACE_DBG("!! SKIPPING %u\n", seq - sndvar->iss);
			cur_stream->snd_nxt += len;
			continue;
		}
#endif

		remaining_window = MIN(sndvar->cwnd, sndvar->peer_wnd)
			               - (seq - sndvar->snd_una);
		/* if there is no space in the window */
		if (remaining_window <= 0 ||
		    (remaining_window < sndvar->mss && seq - sndvar->snd_una > 0)) {
			/* if peer window is full, send ACK and let its peer advertises new one */
			if (sndvar->peer_wnd <= sndvar->cwnd) {
#if 0
				TRACE_CLWND("Full peer window. "
							"peer_wnd: %u, (snd_nxt-snd_una): %u\n",
							sndvar->peer_wnd, seq - sndvar->snd_una);
#endif
				if (!wack_sent && TS_TO_MSEC(cur_ts - sndvar->ts_lastack_sent) > 500)
					EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_WACK);
				else
					wack_sent = 1;
			}
			packets = -3;
			goto out;
		}
		
		/* payload size limited by TCP MSS */
		/* payload size limited by remaining window space */
		len = MIN(len, remaining_window);
#if ENABLE_FLEX_BUFFER
		flex_buf = flex_buffer_find_in_range(sndvar->sndbuf, seq);
		if (flex_buf->type == L1_CACHE_BUFFER || flex_buf->type == FRD_OFFLOAD_BUFFER) {
			pkt_len = len;
		} else {
			pkt_len = MIN(len, GetMaxTSOPacketSize(TOTAL_TCP_HEADER_LEN + 
						CalculateOptionLength(TCP_FLAG_ACK)));
		}
#else /* ENABLE_FLEX_BUFFER */

#if ENABLE_NIC_CACHE
		if (!sndvar->sndbuf->msb_head) {
#if ENABLE_MTCP_TSO
			pkt_len = MIN(len, GetMaxTSOPacketSize(TOTAL_TCP_HEADER_LEN +
						CalculateOptionLength(TCP_FLAG_ACK)));
#else /* ENABLE_MTCP_TSO */
			pkt_len = MIN(len, sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK));
#endif /* ENABLE_MTCP_TSO */
		} else {
#if LIMIT_MAX_META_PAYLOADLEN
			pkt_len = MIN(len, GetMaxTSOPacketSize(TOTAL_TCP_HEADER_LEN + 
						CalculateOptionLength(TCP_FLAG_ACK)));
#else /* LIMIT_MAX_META_PAYLOADLEN */
			if (sndvar->sndbuf->msb_head->numBlocks > 0) {
				pkt_len = MIN(len, 
						GetMaxTSOPacketSize(TOTAL_TCP_HEADER_LEN +
							CalculateOptionLength(TCP_FLAG_ACK)));
			} else  {
				pkt_len = len;
			}
#endif /* LIMIT_MAX_META_PAYLOADLEN */
		}
#else  /* ENABLE_NIC_CACHE */
		pkt_len = MIN(len, sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK));
#endif  /* ENABLE_NIC_CACHE */
#endif /* ENABLE_FLEX_BUFFER */

#if RATE_LIMIT_ENABLE_SND_WND_LIMIT
		if (flex_buf->type == GENERAL_DATA_BUFFER || 
				flex_buf->type == L2_CACHE_BUFFER ||
				flex_buf->type == FILE_BUFFER || 
				flex_buf->type == L1_CACHE_BUFFER) {
			pkt_len = MIN(pkt_len, max_sndlen);
		}
#endif

#if RATE_LIMIT_ENABLED
		// update rate
		if (cur_stream->rcvvar->srtt) {
			cur_stream->bucket->rate = (uint32_t)( //mbps
                BYTES_TO_BITS((double)sndvar->cwnd) / SECONDS_TO_USECS(UNSHIFT_SRTT(cur_stream->rcvvar->srtt))
            );
		}
		if (cur_stream->bucket->rate != 0 && (SufficientTokens(cur_stream->bucket, pkt_len*8) < 0)) {
			packets = -3;
			goto out;
		}
#endif
    
#if PACING_ENABLED
        if (!CanSendNow(cur_stream->pacer)) {
            packets = -3;
            goto out;
        }
#endif

#if ENABLE_FLEX_BUFFER
		//TRACE_INFO("seq:%u, cur_stream:%p\n", cur_stream->snd_nxt, cur_stream);
		switch(flex_buf->type) {
			case GENERAL_DATA_BUFFER :
				sndlen = SendGeneralData(mtcp, cur_stream, cur_ts,
						TCP_FLAG_ACK, flex_buf, pkt_len);
				if (sndlen > 0)
					mtcp->tx_bytes += sndlen;

				break;
			case L1_CACHE_BUFFER :
				sndlen = SendTransmissionMetaPacket(mtcp, cur_stream, cur_ts, 
						TCP_FLAG_ACK, flex_buf, pkt_len);
#if DBG_TX_STATUS
				g_nic_cache_stat[mtcp->ctx->cpu].numMetaPkts_now++;
#endif
				break;
			case L2_CACHE_BUFFER :
				sndlen = SendControlPlaneCachedPacket(mtcp, cur_stream, cur_ts, 
						TCP_FLAG_ACK, flex_buf, pkt_len);
				if (sndlen > 0)
					mtcp->tx_bytes += sndlen;

				break;
			case FRD_OFFLOAD_BUFFER :
				sndlen = SendFrdOffloadPacket(mtcp, cur_stream, cur_ts, 
						TCP_FLAG_ACK, flex_buf, pkt_len);
				break;
			case FILE_BUFFER :
				sndlen = SendFileBufferData(mtcp, cur_stream, cur_ts,
						TCP_FLAG_ACK, flex_buf, pkt_len);
#if DBG_TX_STATUS
				g_nic_cache_stat[mtcp->ctx->cpu].numFrdPkts_now++;
#endif
				if (sndlen > 0)
					mtcp->tx_bytes += sndlen;

				break;
		}

		if (sndlen < 0) {
			packets = -3;
			goto out;
		}
		mtcp->iom->send_pkts(mtcp->ctx, cur_stream->sndvar->nif_out);

#if FRD_RATE_LIMIT_DBG_STATUS
		frd_rate_limit_incr_tx_bytes(mtcp, sndlen);
#endif

#if RATE_LIMIT_ENABLE_SND_WND_LIMIT
		max_sndlen -= sndlen;
		if (max_sndlen == 0) {
			packets = -3;
			goto out;
		}
#endif

#else /* ENABLE_FLEX_BUFFER */	
		uint8_t *data;
		data = sndvar->sndbuf->head + (seq - sndvar->sndbuf->head_seq);
		
		if (sndvar->sndbuf->msb_head) {
			if (sndvar->sndbuf->msb_head->numBlocks == -1) {
				sndlen = SendTransmissionMetaPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, pkt_len);
			} else {
				sndlen = SendControlPlaneCachedPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, data, pkt_len);
			}
			//TRACE_INFO("sndlen=%u\n", sndlen);
			if (sndlen < 0) {
				packets = -3;
				goto out;
			}
			//TRACE_INFO("packets=%d, sndlen=%u\n", packets, sndlen);
		} else {
			if (sndvar->sndbuf->fts) {
				struct foc_tx_state *fts = sndvar->sndbuf->fts;
				uint32_t rlen = 0;
				if (sndvar->sndbuf->len > 0 && cur_stream->snd_nxt == sndvar->sndbuf->head_seq) {
					/*
					TRACE_INFO("len:%u, seq:%u, head_seq:%u\n", 
							sndvar->sndbuf->len, sndvar->sndbuf->head_seq, fts->head_seq);*/
					rlen = sndvar->sndbuf->len;

					if (cur_stream->snd_nxt + rlen != fts->head_seq) {
						TRACE_INFO("Fail!\n");
						exit(EXIT_FAILURE);
					}

					if ((sndlen = SendTCPPacket(mtcp, cur_stream, cur_ts, 
												TCP_FLAG_ACK, data, sndvar->sndbuf->len)) < 0) {
						/* there is no available tx buf */
						packets = -3;
						goto out;
					}
				}

				if ((sndlen = SendFrdOffloadPacket(mtcp, cur_stream, cur_ts,
								TCP_FLAG_ACK, pkt_len - rlen)) < 0) {
					packets = -3;
					goto out;
				}
			} else {
				if ((sndlen = SendTCPPacket(mtcp, cur_stream, cur_ts, 
											TCP_FLAG_ACK, data, pkt_len)) < 0) {
					/* there is no available tx buf */
					packets = -3;
					goto out;
				}
			}
		}
#endif

#if USE_CCP
		if (sndvar->missing_seq) {
			sndvar->missing_seq = 0;
		}
#endif
		packets++;
	}

out:
	SBUF_UNLOCK(&sndvar->write_lock);	
	return packets;	
}
/*----------------------------------------------------------------------------*/
static inline int 
SendControlPacket(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	int ret = 0;
	
	if (cur_stream->state == TCP_ST_SYN_SENT) {
		/* Send SYN here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_SYN, NULL, 0);

	} else if (cur_stream->state == TCP_ST_SYN_RCVD) {
		/* Send SYN/ACK here */
		cur_stream->snd_nxt = sndvar->iss;
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
				TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_ESTABLISHED) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_CLOSE_WAIT) {
		/* Send ACK for the FIN here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_LAST_ACK) {
		/* if it is on ack_list, send it after sending ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			/* Send FIN/ACK here */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
		}
	} else if (cur_stream->state == TCP_ST_FIN_WAIT_1) {
		/* if it is on ack_list, send it after sending ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			/* Send FIN/ACK here */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
		}

	} else if (cur_stream->state == TCP_ST_FIN_WAIT_2) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_CLOSING) {
		if (sndvar->is_fin_sent) {
			/* if the sequence is for FIN, send FIN */
			if (cur_stream->snd_nxt == sndvar->fss) {
				ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
						TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
			} else {
				ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
						TCP_FLAG_ACK, NULL, 0);
			}
		} else {
			/* if FIN is not sent, send fin with ack */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
		}

	} else if (cur_stream->state == TCP_ST_TIME_WAIT) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_CLOSED) {
		/* Send RST here */
		TRACE_DBG("Stream %d: Try sending RST (TCP_ST_CLOSED)\n", 
				cur_stream->id);
		/* first flush the data and ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_RST, NULL, 0);
			if (ret >= 0) {
				DestroyTCPStream(mtcp, cur_stream);
			}
		}
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPControlList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int cnt = 0;
	int ret;

	thresh = MIN(thresh, sender->control_list_cnt);

	/* Send TCP control messages */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->control_list);
	last = TAILQ_LAST(&sender->control_list, control_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside control loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->control_link);

		TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
		sender->control_list_cnt--;

		if (cur_stream->sndvar->on_control_list) {
			cur_stream->sndvar->on_control_list = FALSE;
			//TRACE_DBG("Stream %u: Sending control packet\n", cur_stream->id);
			ret = SendControlPacket(mtcp, cur_stream, cur_ts);
			if (ret == -2) {
				TAILQ_INSERT_HEAD(&sender->control_list, 
						cur_stream, sndvar->control_link);
				cur_stream->sndvar->on_control_list = TRUE;
				sender->control_list_cnt++;
				/* since there is no available write buffer, break */
				break;
			} else if (ret < 0) {
				/* try again after handling other streams */
				TAILQ_INSERT_TAIL(&sender->control_list,
						  cur_stream, sndvar->control_link);
				cur_stream->sndvar->on_control_list = TRUE;
				sender->control_list_cnt++;
			}
		} else {
			TRACE_ERROR("Stream %d: not on control list.\n", cur_stream->id);
		}

		if (cur_stream == last) 
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPDataList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int cnt = 0;
	int ret;

#if ENABLE_FLOW_SCHED
	struct send_pq *pq = sender->send_pq;
	cur_stream = RB_MIN(send_pq, pq);
	last = RB_MAX(send_pq, pq);
	UNUSED(next);
#else
	cur_stream = TAILQ_FIRST(&sender->send_list);
	last = TAILQ_LAST(&sender->send_list, send_head);
#endif
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside send loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
#if ENABLE_FLOW_SCHED
		RB_REMOVE(send_pq, pq, cur_stream);
#else
		next = TAILQ_NEXT(cur_stream, sndvar->send_link);
		TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);
#endif
		if (cur_stream->sndvar->on_send_list) {
			ret = 0;

			/* Send data here */
			/* Only can send data when ESTABLISHED or CLOSE_WAIT */
			if (cur_stream->state == TCP_ST_ESTABLISHED) {
				if (cur_stream->sndvar->on_control_list) {
					/* delay sending data after until on_control_list becomes off */
					//TRACE_DBG("Stream %u: delay sending data.\n", cur_stream->id);
					ret = -1;
				} else {
					ret = FlushTCPSendingBuffer(mtcp, cur_stream, cur_ts);
					//TRACE_INFO("cwnd=%u\n", cur_stream->sndvar->cwnd);
				}
			} else if (cur_stream->state == TCP_ST_CLOSE_WAIT || 
					cur_stream->state == TCP_ST_FIN_WAIT_1 || 
					cur_stream->state == TCP_ST_LAST_ACK) {
				ret = FlushTCPSendingBuffer(mtcp, cur_stream, cur_ts);
			} else {
				TRACE_DBG("Stream %d: on_send_list at state %s\n", 
						cur_stream->id, TCPStateToString(cur_stream));
#if DUMP_STREAM
				DumpStream(mtcp, cur_stream);
#endif
			}
#if 0
			if (ret == -4) {
				/* Rate Limited */
#if ENABLE_FLOW_SCHED
				RB_INSERT(send_pq, pq, cur_stream);
#else
				TAILQ_INSERT_HEAD(&sender->send_list, cur_stream, sndvar->send_link);
#endif
				break;
			} 
#endif

			if (ret < 0) {
#if ENABLE_FLOW_SCHED
				RB_INSERT(send_pq, pq, cur_stream);
#else
				TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
#endif
				/* since there is no available write buffer, break */
				break;

			} else {
				SQ_LOCK(&mtcp->ctx->sendq_lock);
				cur_stream->sndvar->on_send_list = FALSE;
				sender->send_list_cnt--;
				SQ_UNLOCK(&mtcp->ctx->sendq_lock);

#if ACK_PIGGYBACK
				if (cur_stream->sndvar->ack_cnt > 0) {
					if (cur_stream->sndvar->ack_cnt > ret) {
						cur_stream->sndvar->ack_cnt -= ret;
					} else {
						cur_stream->sndvar->ack_cnt = 0;
					}
				}
#endif
#if 1
				if (cur_stream->control_list_waiting) {
					if (!cur_stream->sndvar->on_ack_list) {
						cur_stream->control_list_waiting = FALSE;
						AddtoControlList(mtcp, cur_stream, cur_ts);
					}
				}
#endif
			}
		} else {
			TRACE_ERROR("Stream %d: not on send list.\n", cur_stream->id);
#ifdef DUMP_STREAM
			DumpStream(mtcp, cur_stream);
#endif
		}

		if (cur_stream == last) 
			break;
#if ENABLE_FLOW_SCHED
		cur_stream = RB_MIN(send_pq, pq);
#else
		cur_stream = next;
#endif
	}
/*
	NIC_CACHE_LOG_TCP_SEQ("[TX_Q_SIZE:Before Sent] q_sz=%u\n",
			mtcp->iom->dev_ioctl(mtcp->ctx, 0, GET_TX_QUEUE_LEN, NULL));*/

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPACKList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int to_ack;
	int cnt = 0;
	int ret;

	/* Send aggregated acks */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->ack_list);
	last = TAILQ_LAST(&sender->ack_list, ack_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside ack loop. cnt: %u\n", cnt);
		next = TAILQ_NEXT(cur_stream, sndvar->ack_link);

		if (cur_stream->sndvar->on_ack_list) {
			/* this list is only to ack the data packets */
			/* if the ack is not data ack, then it will not process here */
			to_ack = FALSE;
			if (cur_stream->state == TCP_ST_ESTABLISHED || 
					cur_stream->state == TCP_ST_CLOSE_WAIT || 
					cur_stream->state == TCP_ST_FIN_WAIT_1 || 
					cur_stream->state == TCP_ST_FIN_WAIT_2 || 
					cur_stream->state == TCP_ST_TIME_WAIT) {
				/* TIMEWAIT is possible since the ack is queued 
				   at FIN_WAIT_2 */
				if (cur_stream->rcvvar->rcvbuf) {
					if (TCP_SEQ_LEQ(cur_stream->rcv_nxt, 
								cur_stream->rcvvar->rcvbuf->head_seq + 
								cur_stream->rcvvar->rcvbuf->merged_len)) {
						to_ack = TRUE;
					}
				}
			} else {
				TRACE_DBG("Stream %u (%s): "
						"Try sending ack at not proper state. "
						"seq: %u, ack_seq: %u, on_control_list: %u\n", 
						cur_stream->id, TCPStateToString(cur_stream), 
						cur_stream->snd_nxt, cur_stream->rcv_nxt, 
						cur_stream->sndvar->on_control_list);
#ifdef DUMP_STREAM
				DumpStream(mtcp, cur_stream);
#endif
			}

			if (to_ack) {
				/* send the queued ack packets */
				while (cur_stream->sndvar->ack_cnt > 0) {
					ret = SendTCPPacket(mtcp, cur_stream, 
							cur_ts, TCP_FLAG_ACK, NULL, 0);
					if (ret < 0) {
						/* since there is no available write buffer, break */
						break;
					}
					cur_stream->sndvar->ack_cnt--;
				}

				/* if is_wack is set, send packet to get window advertisement */
				if (cur_stream->sndvar->is_wack) {
					cur_stream->sndvar->is_wack = FALSE;
					ret = SendTCPPacket(mtcp, cur_stream, 
							cur_ts, TCP_FLAG_ACK | TCP_FLAG_WACK, NULL, 0);
					if (ret < 0) {
						/* since there is no available write buffer, break */
						cur_stream->sndvar->is_wack = TRUE;
					}
				}

				if (!(cur_stream->sndvar->ack_cnt || cur_stream->sndvar->is_wack)) {
					cur_stream->sndvar->on_ack_list = FALSE;
					TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
					sender->ack_list_cnt--;
				}
			} else {
				cur_stream->sndvar->on_ack_list = FALSE;
				cur_stream->sndvar->ack_cnt = 0;
				cur_stream->sndvar->is_wack = 0;
				TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
				sender->ack_list_cnt--;
			}

			if (cur_stream->control_list_waiting) {
				if (!cur_stream->sndvar->on_send_list) {
					cur_stream->control_list_waiting = FALSE;
					AddtoControlList(mtcp, cur_stream, cur_ts);
				}
			}
		} else {
			TRACE_ERROR("Stream %d: not on ack list.\n", cur_stream->id);
			TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
			sender->ack_list_cnt--;
#ifdef DUMP_STREAM
			thread_printf(mtcp, mtcp->log_fp, 
					"Stream %u: not on ack list.\n", cur_stream->id);
			DumpStream(mtcp, cur_stream);
#endif
		}

		if (cur_stream == last)
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline struct mtcp_sender *
GetSender(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	if (cur_stream->sndvar->nif_out < 0) {
		return mtcp->g_sender;
	}

	int eidx = CONFIG.nif_to_eidx[cur_stream->sndvar->nif_out];
	if (eidx < 0 || eidx >= CONFIG.eths_num) {
		TRACE_ERROR("(NEVER HAPPEN) Failed to find appropriate sender.\n");
		return NULL;
	}

	return mtcp->n_sender[eidx];
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
#if TRY_SEND_BEFORE_QUEUE
	int ret;
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	ret = SendControlPacket(mtcp, cur_stream, cur_ts);
	if (ret < 0) {
#endif
		if (!cur_stream->sndvar->on_control_list) {
			struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
			assert(sender != NULL);

			cur_stream->sndvar->on_control_list = TRUE;
			TAILQ_INSERT_TAIL(&sender->control_list, cur_stream, sndvar->control_link);
			sender->control_list_cnt++;
			//TRACE_DBG("Stream %u: added to control list (cnt: %d)\n", 
			//		cur_stream->id, sender->control_list_cnt);
		}
#if TRY_SEND_BEFORE_QUEUE
	} else {
		if (cur_stream->sndvar->on_control_list) {
			cur_stream->sndvar->on_control_list = FALSE;
			TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
			sender->control_list_cnt--;
		}
	}
#endif
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
#if ENABLE_FLOW_SCHED
	struct send_pq *pq = sender->send_pq;
#endif
	assert(sender != NULL);

	if(!cur_stream->sndvar->sndbuf) {
		TRACE_ERROR("[%d] Stream %d: No send buffer available.\n", 
				mtcp->ctx->cpu,
				cur_stream->id);
		assert(0);
		return;
	}

	if (!cur_stream->sndvar->on_send_list) {
		cur_stream->sndvar->on_send_list = TRUE;
#if ENABLE_FLOW_SCHED
		RB_INSERT(send_pq, pq, cur_stream);
#else
		TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
#endif
		sender->send_list_cnt++;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoACKList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (!cur_stream->sndvar->on_ack_list) {
		cur_stream->sndvar->on_ack_list = TRUE;
		TAILQ_INSERT_TAIL(&sender->ack_list, cur_stream, sndvar->ack_link);
		sender->ack_list_cnt++;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (cur_stream->sndvar->on_control_list) {
		cur_stream->sndvar->on_control_list = FALSE;
		TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
		sender->control_list_cnt--;
		//TRACE_DBG("Stream %u: Removed from control list (cnt: %d)\n", 
		//		cur_stream->id, sender->control_list_cnt);
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);
#if ENABLE_FLOW_SCHED
	struct send_pq *pq = sender->send_pq;
#endif

	if (cur_stream->sndvar->on_send_list) {
		cur_stream->sndvar->on_send_list = FALSE;
#if ENABLE_FLOW_SCHED
		RB_REMOVE(send_pq, pq, cur_stream);
#else
		TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);
#endif
		sender->send_list_cnt--;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromACKList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (cur_stream->sndvar->on_ack_list) {
		cur_stream->sndvar->on_ack_list = FALSE;
		TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
		sender->ack_list_cnt--;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
EnqueueACK(mtcp_manager_t mtcp, 
		tcp_stream *cur_stream, uint32_t cur_ts, uint8_t opt)
{
	if (!(cur_stream->state == TCP_ST_ESTABLISHED || 
			cur_stream->state == TCP_ST_CLOSE_WAIT || 
			cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2)) {
		TRACE_DBG("Stream %u: Enqueueing ack at state %s\n", 
				cur_stream->id, TCPStateToString(cur_stream));
	}

	if (opt == ACK_OPT_NOW) {
		if (cur_stream->sndvar->ack_cnt < cur_stream->sndvar->ack_cnt + 1) {
			cur_stream->sndvar->ack_cnt++;
		}
	} else if (opt == ACK_OPT_AGGREGATE) {
		if (cur_stream->sndvar->ack_cnt == 0) {
			cur_stream->sndvar->ack_cnt = 1;
		}
	} else if (opt == ACK_OPT_WACK) {
		cur_stream->sndvar->is_wack = TRUE;
	}
	AddtoACKList(mtcp, cur_stream);
}
/*----------------------------------------------------------------------------*/
inline void 
DumpControlList(mtcp_manager_t mtcp, struct mtcp_sender *sender)
{
	tcp_stream *stream;

	TRACE_DBG("Dumping control list (count: %d):\n", sender->control_list_cnt);
	TAILQ_FOREACH(stream, &sender->control_list, sndvar->control_link) {
		TRACE_DBG("Stream id: %u in control list\n", stream->id);
	}
}
