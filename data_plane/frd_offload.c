#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/param.h>

#include <rte_branch_prediction.h>
#include <rte_memcpy.h>

#include "frd_offload.h"
#include "meta_reply.h"
#include "config.h"
#include "debug.h"
#include "rate_limit.h"

#define DBG_FRD_OFFLOAD 0
#if DBG_FRD_OFFLOAD
#define TRACE_FRD_OFFLOAD(f, ...) fprintf(stderr, "(%10s:%4d) " f, __func__, __LINE__, ##__VA_ARGS__)
#else
#define TRACE_FRD_OFFLOAD(f, ...) (void)0
#endif

#define NUM_LIBURING_ENTRIES (4 * 1024) //(16 * 1024)

#if SHOW_STATISTICS
_Atomic uint32_t g_numFrdOffloads = 0;
#endif

inline static void 
__to_big_endian(struct tcp_four_tuple *tft) {
	tft->srcAddr = rte_be_to_cpu_32(tft->srcAddr);
	tft->dstAddr = rte_be_to_cpu_32(tft->dstAddr);
	tft->sport = rte_be_to_cpu_16(tft->sport);
	tft->dport = rte_be_to_cpu_16(tft->dport);
}

frd_offload *
frd_offload_create(unsigned long maxNumWaits) {

	frd_offload *fo;
	int ret;
	unsigned long i;

	fo = calloc(1, sizeof(frd_offload));
	if (!fo) 
		goto err_calloc;

	fo->mw_ptr = calloc(maxNumWaits, sizeof(mbuf_wait));
	if (!fo->mw_ptr)
		goto err_calloc;

	fo->maxNumWaits = maxNumWaits;

	//TAILQ_INIT(&fo->wait_list);
	TAILQ_INIT(&fo->free_list);
#if FRD_OFFLOAD_ENABLE_QUEUE_DEPTH_COORDINATION
	TAILQ_INIT(&fo->wait_list);
#endif

	for (i = 0; i < maxNumWaits; i++) 
		TAILQ_INSERT_TAIL(&fo->free_list, &fo->mw_ptr[i], mbuf_wait_link);
#if ENABLE_SQ_POLL
	struct io_uring_params params;
	uint16_t lcore_id = rte_lcore_id();
	bzero(&params, sizeof(struct io_uring_params));
	params.flags = (IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF);
	params.sq_thread_cpu = lcore_id + MAX_CPUS / 2;
	ret = io_uring_queue_init_params(NUM_LIBURING_ENTRIES, &fo->uring, &params);
#else
	ret = io_uring_queue_init(NUM_LIBURING_ENTRIES, &fo->uring, 0);
#endif
	if (ret != 0) {
		log_error("io_uring_queue_init(), %s\n", strerror(-ret));
		exit(EXIT_FAILURE);
	}

	fo->fbp = fb_pool_create(NUM_FILE_BUFFERS / d_CONFIG.ncpus);

	return fo;

err_calloc :
	perror("calloc()");
	exit(EXIT_FAILURE);
}

inline static void
__generate_frd_offload_reply(uint16_t lcore_id, uint16_t port_id,
		uint8_t *nph, enum mbuf_wait_state st, uint32_t fb_id) 
{
	struct rte_mbuf *m;
	struct rte_ether_hdr *ethh;//, *in_ethh;
	struct rte_ipv4_hdr *iph;
	struct rte_tcp_hdr *tcph;
	struct frd_offload_hdr *foh;
	rte_be16_t tempPort;
	rte_be32_t tempIPAddr;

#if SHOW_STATISTICS && !ENABLE_REPLY_BATCH
	g_stat[lcore_id].numReply++;
#endif

#if ENABLE_REPLY_BATCH
	m = meta_reply_get_wptr(lcore_id, port_id, 
			sizeof(struct rte_ether_hdr) +
			sizeof(struct rte_ipv4_hdr) +
			sizeof(struct rte_tcp_hdr) + 
			sizeof(struct frd_offload_hdr));
#else
	m = dpdk_get_wptr(lcore_id, port_id, 
			sizeof(struct rte_ether_hdr) +
			sizeof(struct rte_ipv4_hdr) +
			sizeof(struct rte_tcp_hdr) + 
			sizeof(struct frd_offload_hdr));
#endif

	//in_ethh = (struct rte_ether_hdr *)nph;
	ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	iph = (struct rte_ipv4_hdr *)(ethh + 1);
	tcph = (struct rte_tcp_hdr *)(iph + 1);
	foh = (struct frd_offload_hdr *)(tcph + 1);

	rte_memcpy(iph, nph + sizeof(struct rte_ether_hdr), 
			sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));
	rte_memcpy(&ethh->src_addr, &src_addr[port_id], sizeof(struct rte_ether_addr));
	rte_memcpy(&ethh->dst_addr, &host_addr, sizeof(struct rte_ether_addr));
	ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	if (st == MBUF_WAIT_STATE_INACTIVE) {
		iph->type_of_service = FRD_OFFLOAD_ALREADY_FREED;
#if SHOW_STATISTICS
		g_stat[lcore_id].numFrdComplHdr++;
#endif
	} else if (st == MBUF_WAIT_STATE_ON_PROCEEDING) {
		iph->type_of_service = FRD_OFFLOAD_ON_PROCEEDING;
#if SHOW_STATISTICS
		g_stat[lcore_id].numFrdComplHdr++;
#endif
	} else if (st == MBUF_WAIT_STATE_ACTIVE) {
		iph->type_of_service = FRD_OFFLOAD_COMPLETE;
#if SHOW_STATISTICS
		g_stat[lcore_id].numFrdFreeHdr++;
#endif
	} else {
		log_error("Wrong option\n");
		exit(EXIT_FAILURE);
	}

	tempIPAddr = iph->src_addr;
	iph->src_addr = iph->dst_addr;
	iph->dst_addr = tempIPAddr;
	iph->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + 
		sizeof(struct rte_tcp_hdr) + sizeof(struct frd_offload_hdr));
	iph->hdr_checksum = 0;

	tempPort = tcph->src_port;
	tcph->src_port = tcph->dst_port;
	tcph->dst_port = tempPort;
	tcph->cksum = 0;

	foh->id = fb_id;

	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = sizeof(struct rte_ipv4_hdr);
	m->l4_len = GET_TCP_HDR_LEN(tcph);
	m->ol_flags = RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
}

#if FRD_OFFLOAD_ENABLE_QUEUE_DEPTH_COORDINATION
inline static void 
__frd_offload_process_wait_list(frd_offload *fo) {

	uint16_t i;
	mbuf_wait *mw;
	struct io_uring_sqe *sqe = NULL;

	while(fo->numIOPendings <= FRD_OFFLOAD_MAX_IOPENDINGS && fo->numIOWaitings > 0) {

		mw = TAILQ_FIRST(&fo->wait_list);
		TAILQ_REMOVE(&fo->wait_list, mw, mbuf_wait_link);

		sqe = io_uring_get_sqe(&fo->uring);
		if (!sqe) {
			log_error("io_uring_sqe(), not enough entries\n");
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < mw->b->numChunks; i++) {
			mw->iovecs[i].iov_base = mw->b->am[i]->addr;
			mw->iovecs[i].iov_len = FB_SIZE;
		}

		io_uring_prep_readv(sqe, mw->fildes, mw->iovecs, mw->b->numChunks, 0);
		io_uring_sqe_set_data(sqe, mw);

		fo->numIOPendings++;
		fo->numIOWaitings--;
	}
	
	io_uring_submit(&fo->uring);
}
#endif

inline static uint16_t 
__frd_offload_issue_sqe(frd_offload *fo, fht *ht, uint16_t lcore_id, uint16_t port_id,
		struct rte_ether_hdr *ethh, struct rte_ipv4_hdr *iph, struct rte_tcp_hdr *tcph) {

	mbuf_wait *mw;
	int32_t i;
	struct io_uring_sqe *sqe = NULL;
	struct frd_offload_hdr *foh;
	struct tcp_four_tuple tft = {
		.srcAddr = iph->src_addr,
		.dstAddr = iph->dst_addr,
		.sport = tcph->src_port,
		.dport = tcph->dst_port,
	};

	foh = (struct frd_offload_hdr *)(tcph + 1);
	__to_big_endian(&tft);
#if FRD_OFFLOAD_ENABLE_QUEUE_DEPTH_COORDINATION
	__frd_offload_process_wait_list(fo);
#endif

	mw = fht_get(ht, &tft, foh->id);
	if (mw) {
		__generate_frd_offload_reply(lcore_id, port_id, (uint8_t *)ethh, mw->state, foh->id);
#if SHOW_STATISTICS
		g_stat[lcore_id].numRTOFrdSetup++;
#endif
		goto out;
	}

	mw = TAILQ_FIRST(&fo->free_list);
	if (!mw) {
		log_error("Increase # of mbuf_wait\n");
		exit(EXIT_FAILURE);
	}

	TAILQ_REMOVE(&fo->free_list, mw, mbuf_wait_link);

	mw->fildes = open(foh->path, O_RDONLY | O_DIRECT);
	if (mw->fildes < 0) {
		log_error("open(), %s, %s, foh:%p\n", foh->path, strerror(errno), foh);
		exit(EXIT_FAILURE);
	}

	mw->nph_len = sizeof(struct rte_ether_hdr) + 
		sizeof(struct rte_ipv4_hdr) +
		sizeof(struct rte_tcp_hdr);
	mw->data_len = lseek(mw->fildes, 0, SEEK_END);
	rte_memcpy(mw->nph, ethh, mw->nph_len);

	mw->b = fb_alloc(fo->fbp, mw->data_len);

	mw->state = MBUF_WAIT_STATE_ON_PROCEEDING;
	mw->id = foh->id;

	fht_insert_data(ht, &tft, mw, foh->id);
	/*if (foh->id < 10)
		fprintf(stderr, "insert mw, core: %d, id: %d\n", lcore_id, foh->id); //
*/
#if SHOW_STATISTICS
	const uint32_t value = 1;
	__atomic_add_fetch(&g_numFrdOffloads, value, __ATOMIC_RELAXED);
#endif

#if FRD_OFFLOAD_ENABLE_QUEUE_DEPTH_COORDINATION
	if (fo->numIOPendings >= FRD_OFFLOAD_MAX_IOPENDINGS) {
		TAILQ_INSERT_TAIL(&fo->wait_list, mw, mbuf_wait_link);
		fo->numIOWaitings++;
		goto out;
	}

	fo->numIOPendings++;
#endif

	sqe = io_uring_get_sqe(&fo->uring);
	if (!sqe) {
		log_error("io_uring_sqe(), not enough entries\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < mw->b->numChunks; i++) {
		mw->iovecs[i].iov_base = mw->b->am[i]->addr;
		mw->iovecs[i].iov_len = FB_SIZE;
	}

	io_uring_prep_readv(sqe, mw->fildes, mw->iovecs, mw->b->numChunks, 0);
	io_uring_sqe_set_data(sqe, mw);
	io_uring_submit(&fo->uring);

out:
	return (uint16_t)(sizeof(struct rte_ether_hdr) + 
						  sizeof(struct rte_ipv4_hdr) + 
						  sizeof(struct rte_tcp_hdr) +
						  sizeof(struct frd_offload_hdr) + foh->path_len + 1);
}

/* case FRD_OFFLOAD_DISK_READ */
inline void
frd_offload_process_setup(frd_offload *fo, fht *ht, 
						  uint16_t lcore_id, uint16_t port_id, 
						  uint8_t *pkt, uint16_t pkt_len)
{
	struct rte_ether_hdr *ethh;
	struct rte_tcp_hdr *tcph;
	struct rte_ipv4_hdr *iph;
	uint16_t hlen = 0;

	for (; pkt_len > 0; pkt_len -= hlen) {
		ethh = (struct rte_ether_hdr *)pkt;
		iph = (struct rte_ipv4_hdr *)(ethh + 1);
		tcph = (struct rte_tcp_hdr *)(iph + 1);
		hlen = __frd_offload_issue_sqe(fo, ht, lcore_id, port_id, ethh, iph, tcph);
		pkt += hlen;
#if SHOW_STATISTICS
		g_stat[lcore_id].numFrdSetupHdr++;
#endif
	}
#if SHOW_STATISTICS
	g_stat[lcore_id].numFrdSetup++;
#endif
}

void
frd_offload_process_cqe(uint16_t lcore_id, uint16_t port_id, frd_offload *fo, fht *ht) {

	int32_t ret;
	struct io_uring_cqe *cqe = NULL;
	struct mbuf_wait *mw;

	struct rte_ether_hdr *ethh;

	while(1) {
		ret = io_uring_peek_cqe(&fo->uring, &cqe);
		if (ret == -EAGAIN)
			break;
		if (ret != 0) {
			log_error("io_uring_peek_cqe() error, %s\n", strerror(ret));
			exit(EXIT_FAILURE);
		}

		if (cqe->res <= 0) {
			log_error("%s\n", strerror(-cqe->res));
			exit(EXIT_FAILURE);
		}

		TRACE_FRD_OFFLOAD("res:%d\n", cqe->res);

		mw = io_uring_cqe_get_data(cqe);
		mw->state = MBUF_WAIT_STATE_ACTIVE;
		close(mw->fildes);
		ethh = (struct rte_ether_hdr *)mw->nph;

		io_uring_cqe_seen(&fo->uring, cqe);
		__generate_frd_offload_reply(lcore_id, port_id, (uint8_t *)ethh, 
				MBUF_WAIT_STATE_ACTIVE, mw->id);
#if FRD_OFFLOAD_ENABLE_QUEUE_DEPTH_COORDINATION
		fo->numIOPendings--;
#endif
	}
}

extern void 
ext_buf_free_callback_fn(void *addr __rte_unused, void *opaque);

inline static void
__generate_frd_offload_packet(uint16_t lcore_id, uint16_t port_id,
		uint8_t *nph, uint16_t nph_len, uint32_t seq,
		mbuf_wait *mw, uint16_t toSend, uint64_t offset) 
{
	struct rte_mbuf *m = NULL, *payloadm = NULL, *prev = NULL;
	struct rte_ether_hdr *ethh = NULL, *in_ethh = NULL;
	struct rte_ipv4_hdr *iph = NULL;
	struct rte_tcp_hdr *tcph = NULL;
	struct shinfo_ctx *shinfo_ctx = NULL;
	struct dpdk_private_context *dpc = g_dpc[lcore_id];
	uint16_t num_mbufs, i, startIndex, data_len;
	uint64_t prefix_len;
	rte_iova_t iova;
	void *addr;

	in_ethh = (struct rte_ether_hdr *)nph;
	m = dpdk_get_wptr(lcore_id, port_id, nph_len);
	ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	iph = (struct rte_ipv4_hdr *)(ethh + 1);
	tcph = (struct rte_tcp_hdr *)(iph + 1);

	rte_memcpy(&ethh->src_addr, &src_addr[port_id], sizeof(struct rte_ether_addr));
	rte_memcpy(&ethh->dst_addr, &in_ethh->src_addr, sizeof(struct rte_ether_addr));
	ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	rte_memcpy(iph, nph + sizeof(struct rte_ether_hdr), nph_len - sizeof(struct rte_ether_hdr));

	iph->total_length = rte_cpu_to_be_16(nph_len + toSend - sizeof(struct rte_ether_hdr));
	iph->type_of_service = 0;
	iph->hdr_checksum = 0;
	tcph->cksum = 0;
	tcph->sent_seq = rte_cpu_to_be_32(seq);

	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = sizeof(struct rte_ipv4_hdr);
	m->l4_len = GET_TCP_HDR_LEN(tcph);
	m->tso_segsz = MTU - (m->l3_len + m->l4_len);
	m->ol_flags = RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_TCP_SEG;

	prefix_len = offset % FB_SIZE;
	num_mbufs = (uint32_t)toSend + prefix_len > FB_SIZE ? 2 : 1;
	startIndex = offset / FB_SIZE;
	prev = m;

	for (i = startIndex; i < startIndex + num_mbufs; i++) {
		data_len = RTE_MIN(FB_SIZE - prefix_len, (uint64_t)toSend);
		assert(data_len <= 0xffff);

		payloadm = rte_pktmbuf_alloc(dpc->pktmbuf_pool);
		if (unlikely(!payloadm)) {
			log_error("Fail to get payloadm, increase # of payloadm\n");
			exit(EXIT_FAILURE);
		}

		if (unlikely((rte_mempool_get(dpc->shinfo_pool, (void **)&shinfo_ctx)) < 0)) {
			log_error("Fail to get shinfo_ctx, increase # of shinfo\n");
			exit(EXIT_FAILURE);
		}

		payloadm->nb_segs = 1;
		payloadm->next = NULL;
		prev->next = payloadm;

		shinfo_ctx->shinfo.free_cb = ext_buf_free_callback_fn;
		shinfo_ctx->shinfo.fcb_opaque = shinfo_ctx;
		shinfo_ctx->core_id = lcore_id;

		iova = mw->b->am[i]->iova + prefix_len;
		addr = mw->b->am[i]->addr + prefix_len;

		rte_mbuf_ext_refcnt_set(&shinfo_ctx->shinfo, 1);

		rte_pktmbuf_attach_extbuf(payloadm, addr, iova, data_len, &shinfo_ctx->shinfo);
		rte_pktmbuf_reset_headroom(payloadm);
		rte_pktmbuf_adj(payloadm, data_len);

		payloadm->data_len = data_len;
		payloadm->pkt_len = 0;
		payloadm->data_off = 0;

		if (unlikely(payloadm->ol_flags != RTE_MBUF_F_EXTERNAL)) {
			log_error("Fail to attach external buffer\n");
			exit(EXIT_FAILURE);
		}

		m->nb_segs++;
		m->pkt_len += (uint16_t)data_len;
		offset = 0;
		toSend -= data_len;
		prev = payloadm;
		prefix_len = 0;
	}
#ifdef _GOODPUT
	g_goodput[lcore_id].t_frd_now += toSend;
#endif

#ifdef _NOTIFYING_MBPS
	g_mbps[lcore_id].t_frd_now += toSend;
#endif
}

__rte_always_inline __rte_hot static uint16_t
__frd_offload_process_meta(uint16_t lcore_id, uint16_t port_id, frd_offload *fo, fht *ht,
		struct rte_ether_hdr *in_ethh, struct rte_ipv4_hdr *in_iph, struct rte_tcp_hdr *in_tcph)
{
	uint16_t nph_len, max_tso_pkt_len;
	struct mbuf_wait *mw;
	int32_t i, toGen;
	uint32_t seq, toSend, remain;
	struct frd_offload_hdr *foh;
	struct tcp_four_tuple tft = {
		.srcAddr = in_iph->src_addr,
		.dstAddr = in_iph->dst_addr,
		.sport = in_tcph->src_port,
		.dport = in_tcph->dst_port,
	};

	foh = (struct frd_offload_hdr *)((uint8_t *)in_tcph + GET_TCP_HDR_LEN(in_tcph));
	__to_big_endian(&tft);

	mw = fht_get(ht, &tft, foh->id);

	TRACE_FRD_OFFLOAD("id:%u, offset:%lu, toSend:%u\n", foh->id, foh->offset, foh->toSend);

	nph_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + GET_TCP_HDR_LEN(in_tcph);

	if (!mw) {
		/* TODO */
		__generate_frd_offload_reply(lcore_id, port_id, (void *)in_ethh, MBUF_WAIT_STATE_INACTIVE, foh->id);
		if (foh->id < 10)
			fprintf(stderr, "!!!!!!!!!!!!############## no mbuf_wait, lcore_id: %d, foh->id: %d\n\n\n", lcore_id, foh->id);
		goto out;
	}

	seq = rte_be_to_cpu_32(in_tcph->sent_seq);
	//nph_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + GET_TCP_HDR_LEN(in_tcph);
	max_tso_pkt_len = MAX_TSO_PACKET_SIZE - nph_len;
	toGen = howmany(foh->toSend, max_tso_pkt_len);

	TRACE_FRD_OFFLOAD("toSend:%u, offset:%lu, toGen:%d\n", foh->toSend, foh->offset, toGen);
	remain = foh->toSend;
	for (i = 0; i < toGen; i++) {
		toSend = RTE_MIN(remain, max_tso_pkt_len);
		__generate_frd_offload_packet(lcore_id, port_id, (uint8_t *)in_ethh, nph_len,
				seq + i * max_tso_pkt_len, mw, toSend, foh->offset + i * max_tso_pkt_len);
		remain -= toSend;
		fo->tx_bytes += toSend;
		dpdk_send_pkts(lcore_id, port_id);
	}
#if SHOW_STATISTICS
	g_stat[lcore_id].disk_sent_bytes += foh->toSend;
#endif
	g_nbu[lcore_id].frd_offload += foh->toSend; //(foh->toSend + nph_len); 
out:
	return nph_len + (uint16_t)sizeof(struct frd_offload_hdr);
}

inline void 
frd_offload_process_transmission(frd_offload *fo, fht *ht, 
		                          uint16_t lcore_id, uint16_t port_id,
		                          uint8_t *pkt, uint16_t pkt_len) {
	struct rte_ether_hdr *ethh;
	struct rte_tcp_hdr *tcph;
	struct rte_ipv4_hdr *iph;
	uint16_t hlen = 0;

	for (; pkt_len > 0; pkt_len -= hlen) {

		ethh = (struct rte_ether_hdr *)pkt;
		iph = (struct rte_ipv4_hdr *)(ethh + 1);
		tcph = (struct rte_tcp_hdr *)(iph + 1);
		hlen = __frd_offload_process_meta(lcore_id, port_id, fo, ht, ethh, iph, tcph);
		pkt += hlen;
#if SHOW_STATISTICS
		g_stat[lcore_id].numFrdMeta++;
#endif
	}
#if SHOW_STATISTICS
	g_stat[lcore_id].numFrdSend++;
#endif
}

inline static uint16_t 
__frd_free_file_buffer(frd_offload *fo, fht *ht, uint16_t lcore_id, uint16_t port_id, 
		struct rte_ether_hdr *in_ethh, struct rte_ipv4_hdr *in_iph, struct rte_tcp_hdr *in_tcph)
{
	mbuf_wait *mw;
	struct frd_offload_hdr *foh;
	struct tcp_four_tuple tft = {
		.srcAddr = in_iph->src_addr,
		.dstAddr = in_iph->dst_addr,
		.sport = in_tcph->src_port,
		.dport = in_tcph->dst_port,
	};

	__to_big_endian(&tft);

	foh = (struct frd_offload_hdr *)(in_tcph + 1);

	mw = fht_get(ht, &tft, foh->id);
	if (!mw) {
		__generate_frd_offload_reply(lcore_id, port_id, (void *)in_ethh, 
			MBUF_WAIT_STATE_INACTIVE, foh->id);
		if (foh->id < 10)
			fprintf(stderr, "free but no mw, lcore: %d, id: %d\n", lcore_id, foh->id);
#if SHOW_STATISTICS
		g_stat[lcore_id].numRTOFrdTeardown++;
#endif
		goto out;
	}

	fht_delete(ht, &tft, foh->id);
	fb_free(fo->fbp, mw->b);

	__generate_frd_offload_reply(lcore_id, port_id, (void *)in_ethh, 
			MBUF_WAIT_STATE_INACTIVE, foh->id);
	/*if (foh->id < 10)
		fprintf(stderr, "free file buffer, lcore: %d, id:%d\n", lcore_id, foh->id); //
*/
	TAILQ_INSERT_TAIL(&fo->free_list, mw, mbuf_wait_link);

	TRACE_FRD_OFFLOAD("free file buffer, id:%d\n", foh->id);
#if SHOW_STATISTICS
	const uint32_t value = 1;
	__atomic_fetch_sub(&g_numFrdOffloads, value, __ATOMIC_RELAXED);
#endif
out :
	return (uint16_t)(sizeof(struct rte_ether_hdr) + 
			sizeof(struct rte_ipv4_hdr) +
			sizeof(struct rte_tcp_hdr) +
			sizeof(struct frd_offload_hdr));
}

inline void
frd_offload_free_file_buffer(frd_offload *fo, fht *ht,
					 uint16_t lcore_id, uint16_t port_id,
					 uint8_t *pkt, uint16_t pkt_len)
{
	struct rte_ether_hdr *ethh;
	struct rte_ipv4_hdr *iph;
	struct rte_tcp_hdr *tcph;
	uint16_t hlen;

	for (; pkt_len > 0; pkt_len -= hlen) {
		ethh = (struct rte_ether_hdr *)pkt;
		iph = (struct rte_ipv4_hdr *)(ethh + 1);
		tcph = (struct rte_tcp_hdr *)(iph + 1);
		hlen = __frd_free_file_buffer(fo, ht, lcore_id, port_id, ethh, iph, tcph);
		pkt += hlen;
#if SHOW_STATISTICS
		g_stat[lcore_id].numFrdTeardownHdr++;
#endif
	}
#if SHOW_STATISTICS
	g_stat[lcore_id].numFrdTeardown++;
#endif
}

void
frd_offload_destroy(frd_offload *fo) {
	/* TODO */
}
