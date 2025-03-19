#include <rte_branch_prediction.h>

#include "zero_copy.h"
#include "meta_send_buffer.h"
#include "general_data_buffer.h"
#include "debug.h"
#include "nic_cache.h"
#include "file_buffer.h"
#include "util.h"
#include "flex_debug.h"
#include "cache_buffer.h"

struct block_meta {
	uint16_t seq;
	void *next;
} __rte_packed ;

#define CACHE_BLOCK_SIZE (256 * 1024) //(128 * 1024) 
#define GET_BLOCK_INDEX(offset) ((offset) / CACHE_BLOCK_SIZE)
#define GET_BLOCK_PREFIX_LEN(offset) ((offset) % CACHE_BLOCK_SIZE)
#define GET_CACHE_BLOCK_IOVA(block, prefix_len) (rte_mempool_virt2iova((block)) + \
	sizeof(struct block_meta) + (prefix_len))
#define GET_CACHE_BLOCK_ADDR(block, prefix_len) ((uint8_t *)(block) + sizeof(struct block_meta) + (prefix_len))

#define NB_INDIRECT_MBUF 32876
#define MEMPOOL_CACHE_SIZE 250

#define DBG_ZERO_COPY 0
#if DBG_ZERO_COPY
#define TRACE_ZERO_COPY(f, ...) do{\
	fprintf(stderr, "(%10s:%4d) " f, __func__, __LINE__, ##__VA_ARGS__);\
} while(0)
#else
#define TRACE_ZERO_COPY(f, ...) (void)0
#endif

struct shinfo_ctx {
	uint16_t lcore_id;
	struct rte_mbuf_ext_shared_info shinfo;
};

static struct rte_mempool *g_payload_mbuf_pool[MAX_CPUS] = {NULL};
static struct rte_mempool *g_shinfo_ctx_pool[MAX_CPUS] = {NULL};

static void 
__ext_buf_callback(void *addr __rte_unused, void *opaque) {
	struct shinfo_ctx *shinfo = opaque;
	if (likely(shinfo)) {
		rte_mempool_put(g_shinfo_ctx_pool[shinfo->lcore_id], shinfo);
	}
}

void
zero_copy_setup(void) {
	int i;
	char name_buf[256];

	for (i = 0; i < CONFIG.num_cores; i++) {
		sprintf(name_buf, "shinfo_ctx%d", i);
		g_shinfo_ctx_pool[i] = rte_mempool_create(name_buf, NB_INDIRECT_MBUF, 
				sizeof(struct shinfo_ctx), 0, 0, 
				NULL, NULL, NULL, NULL,
				rte_socket_id(), 0);
		if (!g_shinfo_ctx_pool[i]) {
			TRACE_ERROR("Fail to create %s\n"
					"errno=%d ghttpd.conf -n 1 -D(%s)\n", 
					name_buf, rte_errno, rte_strerror(rte_errno));
			exit(EXIT_FAILURE);
		}

		sprintf(name_buf, "payload pool%d", i);
		g_payload_mbuf_pool[i] = rte_pktmbuf_pool_create(name_buf, NB_INDIRECT_MBUF, 
				MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
		if (!g_payload_mbuf_pool[i]) {
			TRACE_ERROR("Fail to create %s, errno=%d (%s)\n", 
					name_buf, rte_errno, rte_strerror(rte_errno));
			exit(EXIT_FAILURE);
		}
	}
}

inline static rte_iova_t
__get_iova(flex_buffer *flex_buf, int index, uint32_t offset)
{
	rte_iova_t iova;
	general_data_buffer *gdb;
	file_buffer *file_buf;
	cache_buffer *cb;
	uint32_t prefix_len;

	switch(flex_buf->type) {
		case GENERAL_DATA_BUFFER :
			gdb = (general_data_buffer *)flex_buf->opaque;
			iova = rte_mempool_virt2iova(gdb->data) + offset;
			break;
		case FILE_BUFFER :
			file_buf = (file_buffer *)flex_buf->opaque;
			prefix_len = offset % FILE_BUFFER_SIZE;
			iova = file_buf->am[index]->iova + prefix_len;
			break;
		case L2_CACHE_BUFFER :
			cb = (cache_buffer *)flex_buf->opaque;
			prefix_len = offset % CACHE_BLOCK_SIZE;
			iova = GET_CACHE_BLOCK_IOVA(cb->l2_block_map[index], prefix_len);
			break;
		default :
			TRACE_ERROR("Wrong options...\n");
			exit(EXIT_FAILURE);
	}
	return iova;
}

inline static void *
__get_addr(flex_buffer *flex_buf, int index, uint32_t offset) {

	uintptr_t addr;
	general_data_buffer *gdb;
	file_buffer *file_buf;
	cache_buffer *cb;
	uint32_t prefix_len;

	switch(flex_buf->type) {
		case GENERAL_DATA_BUFFER :
			gdb = (general_data_buffer *)flex_buf->opaque;
			addr = (uintptr_t)gdb->data + offset;
			break;
		case FILE_BUFFER :
			file_buf = (file_buffer *)flex_buf->opaque;
			prefix_len = offset % FILE_BUFFER_SIZE;
			addr = (uintptr_t)file_buf->am[index]->addr + prefix_len;
			break;
		case L2_CACHE_BUFFER :
			cb = (cache_buffer *)flex_buf->opaque;
			prefix_len = offset % CACHE_BLOCK_SIZE;
			addr = (uintptr_t)GET_CACHE_BLOCK_ADDR(cb->l2_block_map[index], prefix_len);
			break;
		default :
			TRACE_ERROR("Wrong options...\n");
			exit(EXIT_FAILURE);
	}

	return (void *)addr;
}

inline static int32_t 
__get_start_index(flex_buffer *flex_buf, uint32_t offset) {

	int32_t startIndex;

	switch(flex_buf->type) {
		case GENERAL_DATA_BUFFER :
			startIndex = 0;
			break;
		case FILE_BUFFER :
			startIndex = offset / FILE_BUFFER_SIZE;
			break;
		case L2_CACHE_BUFFER :
			startIndex = offset / CACHE_BLOCK_SIZE;
			break;
		default :
			TRACE_ERROR("Wrong options...\n");
			exit(EXIT_FAILURE);
	}
	return startIndex;
}

inline static uint32_t
__get_num_mbufs(flex_buffer *flex_buf, uint16_t payloadlen, uint32_t offset) {

	uint32_t num_mbufs, prefix_len;

	switch(flex_buf->type) {
		case GENERAL_DATA_BUFFER :
			num_mbufs = 1;
			break;
		case FILE_BUFFER :
			prefix_len = offset % FILE_BUFFER_SIZE;
			num_mbufs = (uint32_t)payloadlen + prefix_len > FILE_BUFFER_SIZE ? 2 : 1;
			break;
		case L2_CACHE_BUFFER :
			prefix_len = offset % CACHE_BLOCK_SIZE;
			num_mbufs = (uint32_t)payloadlen + prefix_len > CACHE_BLOCK_SIZE ? 2 : 1;
			break;
		default :
			TRACE_ERROR("Wrong options...\n");
			exit(EXIT_FAILURE);
	}

	return num_mbufs;
}

inline static uint16_t 
__get_data_length(int cpu, flex_buffer *flex_buf, uint32_t offset, uint16_t payloadlen) {

	uint32_t prefix_len, length;
#ifndef _GOODPUT
	(void)cpu;
#endif

	switch(flex_buf->type) {
		case GENERAL_DATA_BUFFER :
			prefix_len = offset;
			length = RTE_MIN(flex_buf->data_len - prefix_len, (uint32_t)payloadlen);
#ifdef _GOODPUT
			g_goodput[cpu].t_general_now += length;
#endif
			break;
		case FILE_BUFFER :
			prefix_len = offset % FILE_BUFFER_SIZE;
			length = RTE_MIN(FILE_BUFFER_SIZE - prefix_len, (uint32_t)payloadlen);
			//length = RTE_MIN(flex_buf->data_len - prefix_len, (uint32_t)payloadlen);
#ifdef _GOODPUT
			g_goodput[cpu].t_nvmes_now += length;
#endif
			break;
		case L2_CACHE_BUFFER :
			prefix_len = offset % CACHE_BLOCK_SIZE;
			length = RTE_MIN(CACHE_BLOCK_SIZE - prefix_len, (uint32_t)payloadlen);
#ifdef _GOODPUT
			g_goodput[cpu].t_l2_cache_now += length;
#endif
			break;
		default :
			TRACE_ERROR("Wrong options...\n");
			exit(EXIT_FAILURE);
	}

	assert(length <= 0xffff);
	return (uint16_t)length;
}

inline void
zero_copy_set(struct mtcp_manager *mtcp, struct rte_mbuf *m,
		uint32_t seq, flex_buffer *flex_buf, uint16_t payloadlen) 
{
	uint16_t data_len;
	int32_t ret, i, startIndex;
	uint32_t offset, num_mbufs;
	struct rte_mempool *payload_mbuf_pool, *shinfo_ctx_pool;
	struct rte_mbuf *payloadm, *prev;
	struct shinfo_ctx *shinfo_ctx;
	rte_iova_t iova;
	void *addr;

	offset = flex_buffer_get_offset(flex_buf, seq);
	//remain = flex_buf->data_len - offset;
	m->data_len -= payloadlen;
	prev = m;

	num_mbufs = __get_num_mbufs(flex_buf, payloadlen, offset);

	payload_mbuf_pool = g_payload_mbuf_pool[mtcp->ctx->cpu];
	shinfo_ctx_pool = g_shinfo_ctx_pool[mtcp->ctx->cpu];
	startIndex = __get_start_index(flex_buf, offset);

	TRACE_SND("seq:%u, payloadlen:%u, pkt_len:%u, offset:%u, startIndex:%d, num_mbufs:%u\n", 
			seq, payloadlen, m->pkt_len, offset, startIndex, num_mbufs);

	for (i = startIndex; i < startIndex + num_mbufs; i++) {
		data_len = __get_data_length(mtcp->ctx->cpu, flex_buf, offset, payloadlen);
		//data_len = RTE_MIN(flex_buf->data_len, payloadlen);
		payloadm = rte_pktmbuf_alloc(payload_mbuf_pool);
		if (unlikely(!payloadm)) {
			TRACE_ERROR("fail to allocate payloadm, increase number of payloadm\n");
			exit(EXIT_FAILURE);
		}
		ret = rte_mempool_get(shinfo_ctx_pool, (void **)&shinfo_ctx);
		if (unlikely(ret < 0)) {
			TRACE_ERROR("Fail to allocate shinfo_ctx, increase number of shinfo_ctx\n");
			exit(EXIT_FAILURE);
		}

		payloadm->nb_segs = 1;
		payloadm->next = NULL;
		prev->next = payloadm;

		shinfo_ctx->shinfo.free_cb = __ext_buf_callback;
		shinfo_ctx->shinfo.fcb_opaque = shinfo_ctx;
		shinfo_ctx->lcore_id = mtcp->ctx->cpu;
#if 0
		if (offset > flex_buf->data_len) {
			TRACE_INFO("%s seq:%u, head_seq:%u, offset:%u, payloadlen:%u\n", 
					FLEX_BUFFER_TYPE(flex_buf), seq, flex_buf->head_seq, offset, payloadlen);
		}
#endif

		iova = __get_iova(flex_buf, i, offset);
		addr = __get_addr(flex_buf, i, offset);

		rte_mbuf_ext_refcnt_set(&shinfo_ctx->shinfo, 1);

		rte_pktmbuf_attach_extbuf(payloadm, addr, iova, data_len, &shinfo_ctx->shinfo);
		rte_pktmbuf_reset_headroom(payloadm);
		rte_pktmbuf_adj(payloadm, data_len);

		/*  */
		//payloadm->data_len = data_len;
		//rte_pktmbuf_reset_headroom(payloadm);
		//rte_pktmbuf_adj(payloadm, data_len);

		payloadm->data_len = data_len;
		payloadm->pkt_len = 0;
		payloadm->data_off = 0;


		TRACE_SND("seq:%u, payloadlen:%u, payloadm:%p, pkt_len:%u, data_len:%u "
				"offset:%u, startIndex:%d, num_mbufs:%u\n", 
			seq, payloadlen, payloadm, m->pkt_len, m->data_len, 
			offset, startIndex, num_mbufs);


		if (unlikely(payloadm->ol_flags != RTE_MBUF_F_EXTERNAL)) {
			TRACE_ERROR("Fail to attach external buffer\n");
			exit(EXIT_FAILURE);
		}

		m->nb_segs++;
		offset = 0;
		payloadlen -= data_len;
		prev = payloadm;

	}
}

#if 0
void
zero_copy_set_mbuf(struct mtcp_manager *mtcp, struct rte_mbuf *m,  uint16_t tcp_optlen,
		void *payload, uint16_t payloadlen, rte_iova_t buf_iova) {
#if ZERO_COPY
	int ret;
	struct rte_mempool *payload_mbuf_pool,  *shinfo_ctx_pool;
	struct rte_mbuf *payloadm;
	struct shinfo_ctx *shinfo_ctx;

	payload_mbuf_pool = g_payload_mbuf_pool[mtcp->ctx->cpu];
	shinfo_ctx_pool = g_shinfo_ctx_pool[mtcp->ctx->cpu];

	payloadm = rte_pktmbuf_alloc(payload_mbuf_pool);
	if (unlikely(!payloadm)) {
		TRACE_ERROR("Fail to allocate payloadm, increase number of payloadm\n");
		exit(EXIT_FAILURE);
	}

	ret = rte_mempool_get(shinfo_ctx_pool, (void **)&shinfo_ctx);
	if (unlikely(ret < 0)) {
		TRACE_ERROR("Fail to allocate shinfo_ctx, include number of shinfo_ctx\n");
		exit(EXIT_FAILURE);
	}

	payloadm->nb_segs = 1;
	payloadm->next = NULL;

	shinfo_ctx->shinfo.free_cb = ExtBufCallBackFunc;
	shinfo_ctx->shinfo.fcb_opaque = shinfo_ctx;
	shinfo_ctx->lcore_id = mtcp->ctx->cpu;
	rte_mbuf_ext_refcnt_set(&shinfo_ctx->shinfo, 1);

	rte_pktmbuf_attach_extbuf(payloadm, payload, buf_iova, payloadlen, &shinfo_ctx->shinfo);
	rte_pktmbuf_reset_headroom(payloadm);
	rte_pktmbuf_adj(payloadm, payloadlen);

	payloadm->data_len = payloadlen;
	payloadm->pkt_len = 0;
	payloadm->data_off = 0;

	if (unlikely(payloadm->ol_flags != EXT_ATTACHED_MBUF))
		rte_exit(EXIT_FAILURE,
				"Fail to attach external buffer\n");

	m->nb_segs++;
	m->data_len = tcp_optlen + TOTAL_TCP_HEADER_LEN;
	assert(m->nb_segs == 2);
	m->next = payloadm;
	//m->pkt_len += payloadlen;

#else
	UNUSED(mtcp);
	UNUSED(m);
#endif
}
#endif

#if 0
inline void
zero_copy_set_mbuf_for_cached_obj(struct mtcp_manager *mtcp, struct rte_mbuf *m, 
		struct tcp_send_buffer *buf, uint32_t seq, uint16_t head_mbuf_len, uint16_t payloadlen) 
{
	int ret, i;
	int numBlocks;
	uint16_t toSend, blockLen;
	uint32_t prefix_len, offset, startIdx;
	struct rte_mempool *payload_mbuf_pool,  *shinfo_ctx_pool;
	struct rte_mbuf *payloadm, *prev = NULL;
	struct shinfo_ctx *shinfo_ctx;
	meta_send_buffer *msb;

	payload_mbuf_pool = g_payload_mbuf_pool[mtcp->ctx->cpu];
	shinfo_ctx_pool = g_shinfo_ctx_pool[mtcp->ctx->cpu];

	msb = buf->msb_head;

	if (seq >= msb->head_seq) {
		offset = seq - msb->head_seq;
	} else {
		offset = seq + 1 + UINT32_MAX - msb->head_seq;
	}

	startIdx = GET_BLOCK_INDEX(offset);
	prefix_len = GET_BLOCK_PREFIX_LEN(offset);
	numBlocks = GetNumBlocks(payloadlen, prefix_len);

	prev = m;

	assert(numBlocks > 0 && numBlocks < msb->numBlocks);

	toSend = payloadlen;
	//m->data_len = tcp_optlen + TOTAL_TCP_HEADER_LEN;
	m->data_len = head_mbuf_len;

	TRACE_ZERO_COPY("----------------------------------------------------\n");
	TRACE_ZERO_COPY("head_seq:%u, seq:%u head_mbuf_len:%u startIdx:%u, "
			"prefix_len:%u payloadlen:%u offset:%u numBlocks:%d totNumBlock:%d\n", 
			buf->head_seq, seq - buf->init_seq, head_mbuf_len, startIdx, prefix_len, 
			toSend, offset, numBlocks, msb->numBlocks);

	for (i = 0; i < numBlocks; i++) {

		rte_iova_t blockIOVA;
		unsigned char *blockData;
		blockLen = RTE_MIN(CACHE_BLOCK_SIZE - prefix_len, toSend);

		payloadm = rte_pktmbuf_alloc(payload_mbuf_pool);
		if (unlikely(!payloadm)) {
			TRACE_ERROR("Fail to allocate payloadm, increase number of payloadm\n");
			exit(EXIT_FAILURE);
		}

		ret = rte_mempool_get(shinfo_ctx_pool, (void **)&shinfo_ctx);
		if (unlikely(ret < 0)) {
			TRACE_ERROR("Fail to allocate shinfo_ctx, increase number of shinfo_ctx\n");
			exit(EXIT_FAILURE);
		}

		payloadm->nb_segs = 1;
		payloadm->next = NULL;

		prev->next = payloadm;

		shinfo_ctx->shinfo.free_cb = ExtBufCallBackFunc;
		shinfo_ctx->shinfo.fcb_opaque = shinfo_ctx;
		shinfo_ctx->lcore_id = mtcp->ctx->cpu;

		blockIOVA = GET_CACHE_BLOCK_IOVA(msb->block_map[startIdx + i], prefix_len);
		blockData = GET_BLOCK_DATA(msb->block_map[startIdx + i], prefix_len);

		rte_mbuf_ext_refcnt_set(&shinfo_ctx->shinfo, 1);

		rte_pktmbuf_attach_extbuf(payloadm, blockData, blockIOVA, blockLen, &shinfo_ctx->shinfo);
		rte_pktmbuf_reset_headroom(payloadm);
		rte_pktmbuf_adj(payloadm, blockLen);

		payloadm->data_len = blockLen;
		payloadm->pkt_len = 0;
		payloadm->data_off = 0;

		TRACE_ZERO_COPY("blockIdx : %d, blockLen : %u, toSend=%u\n", 
				startIdx + i, blockLen, toSend);

		if (unlikely(payloadm->ol_flags != EXT_ATTACHED_MBUF)) {
			TRACE_ERROR("Fail to attach external buffer\n");
			exit(EXIT_FAILURE);
		}

		m->nb_segs++;
		prefix_len = 0;

		toSend -= blockLen;

		prev = payloadm;
	}
	assert(m->nb_segs <= 3);
}
#endif
#if 0
void
zero_copy_set_mbuf_for_file_buffer(struct mtcp_manager *mtcp, struct rte_mbuf *m,
		struct tcp_send_buffer *buf, uint32_t seq, 
		uint16_t head_mbuf_len, uint16_t payloadlen, uint16_t dport) 
{
	int ret, i;
	int num_mbufs;
	uint16_t fb_idx, data_len;
	uint32_t offset, remain, toSend;
	struct rte_mempool *payload_mbuf_pool, *shinfo_ctx_pool;
	struct rte_mbuf *payloadm, *prev;
	struct shinfo_ctx *shinfo_ctx;
	rte_iova_t fb_iova;
	void *fb_addr;
	file_buffer *fb = NULL, *fb_next = NULL;;

	payload_mbuf_pool = g_payload_mbuf_pool[mtcp->ctx->cpu];
	shinfo_ctx_pool = g_shinfo_ctx_pool[mtcp->ctx->cpu];

	/* Find file buffer */
	for (i = 0; i < buf->num_fb; i++) {
		fb = buf->fb_ptr[i];
		fb_next = buf->fb_ptr[i+1];
		if (fb_is_included(fb, fb_next, seq)) {
			fb_idx = i;
			break;
		}
	}

	if (seq >= fb->head_seq)
		offset = seq - fb->head_seq;
	else { 
		offset = seq + UINT32_MAX - fb->head_seq;
	}

	remain = fb->buf_len - offset;
	num_mbufs = remain > payloadlen ? 1 : 2;
	prev = m;

	toSend = payloadlen;

	m->data_len = head_mbuf_len;

	TRACE_ZERO_COPY("m:%p, seq:%u, head_mbuf_len:%u, payloadlen:%u\n", 
			m, seq, head_mbuf_len, payloadlen);

	TRACE_SINGLE_FLOW(dport, "m:%p, seq:%u, head_mbuf_len:%u, payloadlen:%u, seq:%u\n", 
			m, seq, head_mbuf_len, payloadlen, seq);


	for (i = 0; i < num_mbufs; i++) {
		data_len = RTE_MIN(fb->data_len - offset, toSend);

		payloadm = rte_pktmbuf_alloc(payload_mbuf_pool);
		if (unlikely(!payloadm)) {
			TRACE_ERROR("fail to allocate payloadm, increase number of payloadm\n");
			exit(EXIT_FAILURE);
		}
		ret = rte_mempool_get(shinfo_ctx_pool, (void **)&shinfo_ctx);
		if (unlikely(ret < 0)) {
			TRACE_ERROR("Fail to allocate shinfo_ctx, increase number of shinfo_ctx\n");
			exit(EXIT_FAILURE);
		}

		payloadm->nb_segs = 1;
		payloadm->next = NULL;
		prev->next = payloadm;

		shinfo_ctx->shinfo.free_cb = ExtBufCallBackFunc;
		shinfo_ctx->shinfo.fcb_opaque = shinfo_ctx;
		shinfo_ctx->lcore_id = mtcp->ctx->cpu;

		fb_iova = fb->iova + offset;
		fb_addr = fb->data + offset;

		rte_mbuf_ext_refcnt_set(&shinfo_ctx->shinfo, 1);

		rte_pktmbuf_attach_extbuf(payloadm, fb_addr, fb_iova, data_len, &shinfo_ctx->shinfo);
		rte_pktmbuf_reset_headroom(payloadm);
		rte_pktmbuf_adj(payloadm, data_len);

		payloadm->data_len = data_len;
		payloadm->pkt_len = 0;
		payloadm->data_off = 0;

		if (unlikely(payloadm->ol_flags != EXT_ATTACHED_MBUF)) {
			TRACE_ERROR("Fail to attach external buffer\n");
			exit(EXIT_FAILURE);
		}

		m->nb_segs++;
		offset = 0;
		toSend -= data_len;
		prev = payloadm;
		fb = buf->fb_ptr[++fb_idx];

		TRACE_ZERO_COPY("m:%p, nb_segs:%u, payloadm:%p, data_len:%u\n", 
				m, m->nb_segs, payloadm, payloadm->data_len);
		TRACE_SINGLE_FLOW(dport, "m:%p, nb_segs:%u, payloadm:%p, data_len:%u, seq:%u\n", 
				m, m->nb_segs, payloadm, payloadm->data_len, seq);

	}

	assert(m->nb_segs <= 3);
}
#endif

void
zero_copy_teardown(void) {
	/* TODO */
}
