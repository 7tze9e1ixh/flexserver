#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/queue.h>

#include "memory_mgt.h"
#include "debug.h"
#include "tcp_send_buffer.h"
#include "tcp_sb_queue.h"
#include "frd_offload_ctrl.h"
#include "util.h"

#include "general_data_buffer.h"
#include "flex_buffer.h"
#include "cache_buffer.h"
#include "flex_debug.h"

#if ENABLE_NIC_CACHE
#include "nic_cache.h"
#endif

#ifndef MAX
#define MAX(a, b) ((a)>(b)?(a):(b))
#endif

#ifndef MIN
#define MIN(a, b) ((a)<(b)?(a):(b))
#endif

#define ENABLE_MULTI_REAL_PAYLOAD FALSE

#define DBG_SEND_BUF FALSE
#if DBG_SEND_BUF
#define trace_snd_buf(f, ...) fprintf(stderr, "(%10s:%4d) " f, \
		__func__, __LINE__, ##__VA_ARGS__)
#else
#define trace_snd_buf(f, ...) (void)0
#endif
/*----------------------------------------------------------------------------*/
struct sb_manager
{
	mtcp_manager_t mtcp;
	size_t chunk_size;
	uint32_t cur_num;
	uint32_t cnum;
#if !ENABLE_FLEX_BUFFER
	mem_pool_t mp;
#endif
	sb_queue_t freeq;
#if ENABLE_NIC_CACHE
	meta_send_buffer_pool *msbp;
#endif
} sb_manager;

/*----------------------------------------------------------------------------*/

#if ENABLE_NIC_CACHE
#if 0
static size_t RemoveRealPayload(struct tcp_send_buffer *buf, size_t len);
static size_t RemoveMetaPayload(sb_manager_t sbm, struct tcp_send_buffer *buf, size_t len,
		int cpu, int sockid);
static void PushMSB(struct tcp_send_buffer *buf, meta_send_buffer *msb);
static void PopMSB(struct tcp_send_buffer *buf, meta_send_buffer *msb);

inline static void 
PushMSB(struct tcp_send_buffer *buf, meta_send_buffer *msb)
{

#if !ENABLE_MULTI_REAL_PAYLOAD
	assert(!buf->msb_head && !buf->msb_tail); 
#endif
	if (buf->msb_head == NULL && buf->msb_tail == NULL) {
		msb->next = NULL;
		msb->prev = NULL;
		buf->msb_head = msb;
		buf->msb_tail = msb;
	} else {
		buf->msb_tail->next = msb;
		msb->prev = buf->msb_tail;
		msb->next = NULL;
		buf->msb_tail = msb;
	}
}

inline static void 
PopMSB(struct tcp_send_buffer *buf, meta_send_buffer *msb)
{
	if (msb == buf->msb_head) {
		if (buf->msb_head == buf->msb_tail) {
			buf->msb_head = buf->msb_tail = NULL;
		} else {
			buf->msb_head = buf->msb_head->next;
			buf->msb_head->prev = NULL;
		}
	} else if (msb == buf->msb_tail) {
		buf->msb_tail = buf->msb_tail->prev;
		buf->msb_tail->next = NULL;
	} else {
		msb->prev->next = msb->next;
		msb->next->prev = msb->prev;
	} 
	msb->prev = NULL;
	msb->next = NULL;
}

inline static size_t
RemoveRealPayload(struct tcp_send_buffer *buf, size_t len)
{
	size_t to_remove;

	if (len <= 0) 
		return 0;

	to_remove = MIN(len, buf->len);
	if (to_remove <= 0)
		return -2;
/*
	TRACE_INFO("before:head_seq=%u(%u), to_remove=%u \t after:head_seq=%u(%u)\n",
			buf->head_seq, buf->head_seq - buf->init_seq, 
			(uint32_t)len,
			buf->head_seq + (uint32_t)len, buf->head_seq + (uint32_t)len - buf->init_seq);*/

	buf->head_off += to_remove;
	buf->head = buf->data + buf->head_off;
	buf->head_seq += to_remove;
	buf->len -= to_remove;
	buf->total_buf_size -= to_remove;

	if (buf->len == 0 && buf->head_off > 0) {
		buf->head = buf->data;
		buf->head_off = buf->tail_off = 0;
	}

	return to_remove;
}

/* @@ Case 1
 * +----------------------------------+  +----------------------------------+  
 * | seq=100, sz=100, already_sent=20 |--| seq=200, sz=100, already_sent=0  |
 * +----------------------------------+  +----------------------------------+ 
 *
 * @@ Case 2
 * +----------------------------------+  +----------------+  +----------------------------------+  
 * | seq=100, sz=100, already_sent=20 |--| seq=200, sz=50 |--|  seq=250, sz=100, already_sent=0 |
 * +----------------------------------+  +----------------+  +----------------------------------+ 
 *                                      |
 *                                    Return
 * */

/* Remove consecutive meta payload */
inline static size_t
RemoveMetaPayload(sb_manager_t sbm, struct tcp_send_buffer *buf, size_t len, int cpu, int stream_id) 
{
	size_t rmlen = 0, to_rm;
	meta_send_buffer *msb, *next;
	uint32_t seq_off = 0, seq = 0, diff;

	if (len <= 0)
		return len;

	msb = buf->msb_head;

	if (!msb) 
		return 0;

	while (len > 0)
	{
		seq = msb->head_seq + msb->already_sent; // buf->head_seq
/*
		NIC_CACHE_DUMP("RemoveMetaPayload, seq(before)=%x, already_sent=%u, r_len=%lu, tot_len=%u\n",
				seq + seq_off, msb->already_sent, len, buf->total_buf_size);*/

		if (!msb) {
			buf->total_buf_size -= rmlen;
			buf->head_seq += seq_off;
			/*
			NIC_CACHE_DUMP("Free all meta payloads, seq=%x(%u), tot_len=%u\n", 
					buf->head_seq, buf->head_seq - buf->init_seq,  buf->total_buf_size);*/
			return rmlen;
		}

		if (seq + seq_off >= msb->head_seq + msb->already_sent) {
			diff = msb->size - msb->already_sent;
			to_rm = MIN(len, diff);
			if (msb->already_sent + to_rm == msb->size) {
				seq_off += to_rm;
				rmlen += to_rm;
				len -= to_rm;
				next = msb->next;
				PopMSB(buf, msb);
				nic_cache_free_obj_by_hv(cpu, stream_id, msb->hv);
				meta_send_buffer_free(sbm->msbp, msb);
				msb = next;
			} else {
				/* len < to_rm */
				seq_off += to_rm;
				rmlen += to_rm;
				len -= to_rm;
				msb->already_sent += to_rm;
			}
		} else {
			/* Case 2 */
			NIC_CACHE_DUMP("Free all meta payload in range\n");
			break;
		}
	}

	buf->total_buf_size -= rmlen;
	buf->head_seq += seq_off;
	
	return rmlen;
}
#endif

size_t
SBMetaPut(sb_manager_t sbm, struct tcp_send_buffer *buf, uint64_t hv, uint32_t size,
		void *block_map, int numBlocks)
{
#if ENABLE_FLEX_BUFFER
	cache_buffer *cb;
	int32_t ret;

	if (numBlocks > 0) {
		cb = cache_buffer_l2_alloc(sbm->mtcp);
		if (!cb) {
			TRACE_ERROR("Increase # of cache buffer\n");
			exit(EXIT_FAILURE);
		}
		cb->hv = hv;
		cb->numBlocks = numBlocks;
		memcpy(cb->l2_block_map, block_map, sizeof(void *) * numBlocks);

		ret = flex_buffer_attach_without_lock(sbm->mtcp, buf, L2_CACHE_BUFFER, cb, size,
				buf->head_seq + buf->total_buf_size);
		if (ret < 0) {
			TRACE_ERROR("Increase # of flex_buffer\n");
			exit(EXIT_FAILURE);
		}
	} else {
		cb = cache_buffer_l1_alloc(sbm->mtcp);
		if (!cb) {
			TRACE_ERROR("Increase # of cache buffer\n");
			exit(EXIT_FAILURE);
		}

		cb->hv = hv;
		ret = flex_buffer_attach_without_lock(sbm->mtcp, buf, L1_CACHE_BUFFER, cb, size,
				buf->head_seq + buf->total_buf_size);
		if (ret < 0) {
			TRACE_ERROR("Increase # of flex_buffer\n");
			exit(EXIT_FAILURE);
		}
	}

	buf->total_buf_size += size;

	return size;
#else /* !ENABLE_FLEX_BUFFER */
	meta_send_buffer *msb;

	msb = meta_send_buffer_get(sbm->msbp);
	assert(msb);

	msb->hv = hv;
	msb->size = size;
	msb->already_sent = 0;
	msb->head_seq = buf->head_seq + buf->total_buf_size;

	/* head.prev = NULL
	 * tail.next = NULL */
	PushMSB(buf, msb);

	assert(numBlocks == 0);

	if (numBlocks > 0) {
		msb->block_map = (void **)block_map;
		msb->numBlocks = numBlocks;
	} else {
		msb->block_map = NULL;
		msb->numBlocks = -1;
	}

	buf->total_buf_size += size;

	return size;
#endif /* ENABLE_FLEX_BUFFER */
}
#endif
/*----------------------------------------------------------------------------*/
#if 0
inline static uint32_t
RemoveFB(struct tcp_send_buffer *buf, uint32_t len) {

	file_buffer *fb;
	uint32_t remain, toRemove, numRemoved;

	numRemoved = len;

	while (len > 0) {
		fb = buf->fb_ptr[0];
		remain = fb->data_len - fb->already_sent;
		toRemove = MIN(remain, len);

		trace_snd_buf("fb:%p, fb's head_seq:%u, already_sent:%u, num_fb:%d, toRemove:%u\n",
				fb, fb->head_seq, fb->already_sent, buf->num_fb, toRemove);

		fb->already_sent += toRemove;
		if (fb->already_sent == fb->data_len) {
			buf->num_fb--;
			fb_clean_up(fb);
			memmove(buf->fb_ptr, &buf->fb_ptr[1], 
					(MAX_FILE_BUFFER_ENTRIES - 1) * sizeof(file_buffer *));
		}
		len -= toRemove;
	}
	buf->total_buf_size -= numRemoved;
	buf->head_seq += numRemoved;

	trace_snd_buf("total_buf_size:%u, buf's head_seq:%u\n", 
			buf->total_buf_size, buf->head_seq);

	return numRemoved;
}
/*----------------------------------------------------------------------------*/
inline static uint32_t
RemoveFrdOffload(struct tcp_send_buffer *buf, uint32_t len) {

	struct foc_tx_state *fts;
	uint32_t remain, toRemove, numRemoved;

	numRemoved = len;
	fts = buf->fts;

	while (len > 0) {
		remain = fts->size - fts->already_sent;
		toRemove = MIN(remain, len);

/*		TRACE_FRD_OFFLOAD_CTRL("fts:%p, fts' head_seq:%u, already_sent:%lu, toRemove:%u\n",
				fts, fts->head_seq, fts->already_sent, toRemove);*/

		fts->already_sent += toRemove;
		if (fts->already_sent == fts->size) 
			foc_teardown_offload(fts, fts->mtcp->cur_ts);
			//foc_teardown_offload(fts->mtcp, fts->stream, fts->mtcp->cur_ts);
		len -= toRemove;
	}

	buf->total_buf_size -= numRemoved;
	buf->head_seq += numRemoved;

	return numRemoved;
}
#endif
/*----------------------------------------------------------------------------*/
uint32_t 
SBGetCurnum(sb_manager_t sbm)
{
	return sbm->cur_num;
}
/*----------------------------------------------------------------------------*/
sb_manager_t 
SBManagerCreate(mtcp_manager_t mtcp, size_t chunk_size, uint32_t cnum)
{
	sb_manager_t sbm = (sb_manager_t)calloc(1, sizeof(sb_manager));
	if (!sbm) {
		TRACE_ERROR("SBManagerCreate() failed. %s\n", strerror(errno));
		return NULL;
	}

	sbm->chunk_size = chunk_size;
	sbm->cnum = cnum;
#if ENABLE_FLEX_BUFFER
	sbm->mtcp = mtcp;
	//general_data_buffer_pool_create(mtcp, chunk_size, cnum * 4);
//	cache_buffer_pool_create(mtcp, cnum * 4);
#else
#if !defined(DISABLE_DPDK) && !defined(ENABLE_ONVM)
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	sprintf(pool_name, "sbm_pool_%d", mtcp->ctx->cpu);
	sbm->mp = (mem_pool_t)MPCreate(pool_name, chunk_size, (uint64_t)chunk_size * cnum);	
#else
	sbm->mp = (mem_pool_t)MPCreate(chunk_size, (uint64_t)chunk_size * cnum);
#endif
	if (!sbm->mp) {
		TRACE_ERROR("Failed to create mem pool for sb.\n");
		free(sbm);
		return NULL;
	}
#endif

	sbm->freeq = CreateSBQueue(cnum);
	if (!sbm->freeq) {
		TRACE_ERROR("Failed to create free buffer queue.\n");
		//MPDestroy(sbm->mp);
		free(sbm);
		return NULL;
	}

#if ENABLE_NIC_CACHE
	sbm->msbp = meta_send_buffer_pool_create(cnum, mtcp->ctx->cpu);
	if (!sbm->msbp) {
		TRACE_ERROR("Failed to create meta send buffer pool.\n");
		//MPDestroy(sbm->mp);
		DestroySBQueue(sbm->freeq);
		free(sbm);
		return NULL;
	}
#endif

	/* DEBUG sbm_pool */
#if 0
	TRACE_INFO("name:%s, len=%lu, hugepage_sz=%lu, socket_id=%d, flags=%u "
			"phys_addr=%p, iova=%p, addr=%p, addr_64=%lx, mp=%p\n",
			sbm->mp->mz->name, sbm->mp->mz->len, sbm->mp->mz->hugepage_sz, sbm->mp->mz->socket_id,
			sbm->mp->mz->flags, (void *)sbm->mp->mz->phys_addr, (void *)sbm->mp->mz->iova, 
			sbm->mp->mz->addr, sbm->mp->mz->addr_64, sbm->mp);
#endif

	return sbm;
}
/*----------------------------------------------------------------------------*/
struct tcp_send_buffer *
SBInit(sb_manager_t sbm, uint32_t init_seq)
{
	struct tcp_send_buffer *buf;

	/* first try dequeue from free buffer queue */
	buf = SBDequeue(sbm->freeq);
	if (!buf) {
		buf = (struct tcp_send_buffer *)malloc(sizeof(struct tcp_send_buffer));
		if (!buf) {
			perror("malloc() for buf");
			return NULL;
		}
#if ENABLE_FLEX_BUFFER
		buf->flex_buffer_list = malloc(sizeof(TAILQ_HEAD(, flex_buffer)));
		if (!buf->flex_buffer_list) {
			perror("malloc() for flex_buffer_list");
			free(buf);
			return NULL;
		}
#else
		buf->data = MPAllocateChunk(sbm->mp);
		if (!buf->data) {
			TRACE_ERROR("Failed to fetch memory chunk for data.\n");
			free(buf);
			return NULL;
		}
#endif
		sbm->cur_num++;
	}
#if ENABLE_FLEX_BUFFER
	TAILQ_INIT((TAILQ_HEAD(, flex_buffer) *)buf->flex_buffer_list);
#else
	buf->head = buf->data;
	buf->head_off = buf->tail_off = 0;
	buf->len = buf->cum_len = 0;
	buf->size = sbm->chunk_size;
#endif /* !ENABLE_FLEX_BUFFER */

	buf->init_seq = buf->head_seq = init_seq;
	buf->total_buf_size = 0;

#if !ENABLE_NIC_CACHE
	buf->fts = NULL;
#if ENABLE_NIC_CACHE
	buf->msb_head = NULL;
	buf->msb_tail = NULL;
#endif
#endif /* !ENABLE_FLEX_BUFFER */

#if 0
#if ZERO_COPY
	struct rte_mempool_objhdr *hdr;
	hdr = (struct rte_mempool_objhdr *)RTE_PTR_SUB((void*)buf->data, sizeof(*hdr));
#if !ENABLE_FLEX_BUFFER
	buf->iova_base = rte_mempool_virt2iova(buf->data);
#endif
#if 0
	TRACE_INFO("iova_base=%lx, %p %lx, %lx\n", 
			buf->iova_base, hdr->mp, hdr->iova, hdr->physaddr);
#endif
#endif
#endif

#if USE_AIO_READ
	pthread_spinlock_init(&buf->sl_frag, PTHREAD_PROCESS_PRIVATE);
	buf->frag = NULL;
#endif

	buf->num_fb = 0;
	bzero(buf->fb_ptr, sizeof(file_buffer *) * MAX_FILE_BUFFER_ENTRIES);
	
	return buf;
}
/*----------------------------------------------------------------------------*/
#if 0
static void 
SBFreeInternal(sb_manager_t sbm, struct tcp_send_buffer *buf)
{
	if (!buf)
		return;

	if (buf->data) {
		MPFreeChunk(sbm->mp, buf->data);
		buf->data = NULL;
	}

	sbm->cur_num--;
	free(buf);
}
#endif
/*----------------------------------------------------------------------------*/
void 
SBFree(sb_manager_t sbm, struct tcp_send_buffer *buf)
{
#if ENABLE_FLEX_BUFFER
	flex_buffer *flex_buf;
	TAILQ_HEAD(, flex_buffer) *flex_buffer_list = buf->flex_buffer_list;

	while ((flex_buf = TAILQ_FIRST(flex_buffer_list))) {
		TAILQ_REMOVE(flex_buffer_list, flex_buf, flex_buffer_link);
		flex_buffer_free(sbm->mtcp, flex_buf);
	}
#else
	int i;
	if (!buf)
		return;
#if ENABLE_NIC_CACHE
	meta_send_buffer *msb = buf->msb_head;
	while (msb) {
		//TRACE_INFO("Free hv=%lu\n", msb->hv);
		PopMSB(buf, msb);
		nic_cache_free_obj_by_hv(0, 0, msb->hv);
		meta_send_buffer_free(sbm->msbp, msb);
		msb = buf->msb_head;
	}
#endif

	for (i = 0; i < buf->num_fb; i++)
		fb_clean_up(buf->fb_ptr[i]);

#endif
	SBEnqueue(sbm->freeq, buf);
}
/*----------------------------------------------------------------------------*/
size_t 
SBPut(sb_manager_t sbm, struct tcp_send_buffer *buf, const void *data, size_t len)
{
	size_t to_put;

	if (len <= 0)
		return 0;

	/* if no space, return -2 */
#if ENABLE_FLEX_BUFFER
	int32_t i, numGDBs, ret;
	size_t numPuts = 0;
	uint32_t buf_len, offset = 0;
	flex_buffer *flex_buf;
	general_data_buffer *gdb;
	TAILQ_HEAD(, flex_buffer) *flex_buffer_list;

	buf_len = general_data_buffer_get_buf_size(sbm->mtcp);
	flex_buffer_list = buf->flex_buffer_list;
	flex_buf = TAILQ_LAST(flex_buffer_list, flex_buffer_head);

	if (flex_buf && flex_buf->type == GENERAL_DATA_BUFFER) {
		to_put = MIN(len, buf_len - flex_buf->data_len);
		gdb = flex_buf->opaque;
		memcpy(gdb->data + flex_buf->data_len, data + offset, to_put);

		len -= to_put;
		offset += to_put;
		numPuts += to_put;
		flex_buf->data_len += to_put;

		numGDBs = get_howmany(to_put, buf_len);
		for (i = 0; i < numGDBs; i++) {
			to_put = MIN(len, buf_len);
			gdb = general_data_buffer_alloc(sbm->mtcp);
			if (!gdb) 
				break;

			memcpy(gdb->data, data + offset, to_put);
			ret = flex_buffer_attach_without_lock(sbm->mtcp, buf, GENERAL_DATA_BUFFER, gdb, to_put,
					buf->head_seq + buf->total_buf_size + offset);
			if (ret < 0) {
				general_data_buffer_free(sbm->mtcp, gdb);
				break;
			}

			offset += to_put;
			len -= to_put;
			numPuts += to_put;
		}
	} else {
		numGDBs = get_howmany(len, buf_len);
		for (i = 0; i < numGDBs; i++) {
			to_put = MIN(len, buf_len);
			gdb = general_data_buffer_alloc(sbm->mtcp);
			if (!gdb) 
				break;

			memcpy(gdb->data, data + offset, to_put);
			ret = flex_buffer_attach_without_lock(sbm->mtcp, buf, GENERAL_DATA_BUFFER, gdb, to_put,
					buf->head_seq + buf->total_buf_size + offset);
			if (ret < 0) {
				general_data_buffer_free(sbm->mtcp, gdb);
				break;
			}
			offset += to_put;
			len -= to_put;
			numPuts += to_put;
		}
	}
#else
	to_put = MIN(len, buf->size - buf->len);
	if (to_put <= 0) {
		return -2;
	}

	if (buf->tail_off + to_put < buf->size) {
		/* if the data fit into the buffer, copy it */
		memcpy(buf->data + buf->tail_off, data, to_put);
/*
		NIC_CACHE_DUMP("Put real payload seq=%x(%u), r_len=%u, total_len=%u\n", 
				buf->head_seq + buf->tail_off, buf->head_seq + buf->tail_off - buf->init_seq,
				len, buf->total_buf_size);*/

		buf->tail_off += to_put;

	} else {
		/* if buffer overflows, move the existing payload and merge */
		memmove(buf->data, buf->head, buf->len);
		buf->head = buf->data;
		buf->head_off = 0;
		memcpy(buf->head + buf->len, data, to_put);
		buf->tail_off = buf->len + to_put;
	}
#endif /* ENABLE_FLEX_BUFFER */

#if !ENABLE_FLEX_BUFFER
	buf->len += to_put;
	buf->cum_len += to_put;
#endif

	buf->total_buf_size += numPuts;

	return numPuts;
}/*----------------------------------------------------------------------------*/

#if ENABLE_NIC_CACHE
size_t 
SBRemove(sb_manager_t sbm, struct tcp_send_buffer *buf, size_t len, int cpu, int sockid)
{
	size_t to_remove, rmlen;
	uint32_t numRemoved = 0;
#if ENABLE_FLEX_BUFFER
	flex_buffer *flex_buf;
	uint32_t remain;
	TAILQ_HEAD(, flex_buffer) *flex_buffer_list = buf->flex_buffer_list;

	to_remove = MIN(len, buf->total_buf_size);

	while (to_remove) {
		flex_buf = TAILQ_FIRST(flex_buffer_list);
		remain = flex_buf->data_len - flex_buf->already_sent;
		rmlen = MIN(remain, to_remove);

		TRACE_RCV("%6s, seq:%u, len:%lu, total_buf_size:%u, rmlen:%lu already_sent:%u\n",
				FLEX_BUFFER_TYPE(flex_buf), buf->head_seq, len, 
				buf->total_buf_size, rmlen, flex_buf->already_sent);

		flex_buf->already_sent += rmlen;

		if (flex_buf->already_sent == flex_buf->data_len) {
	//		TRACE_INFO("Remove %6s\n", FLEX_BUFFER_TYPE(flex_buf));
			TAILQ_REMOVE(flex_buffer_list, flex_buf, flex_buffer_link);
			flex_buffer_free(sbm->mtcp, flex_buf);
#ifdef CHECK_CONTROLPLANE_ACCESS_LATENCY
			if (flex_buf->type == FILE_BUFFER)
				nic_cache_free_obj_by_hv(cpu, 0, buf->obj_hv);
#endif
#if 0
			if (flex_buf->type == FRD_OFFLOAD_BUFFER)
				buf->prev_type = 0;
			else if (flex_buf->type == FILE_BUFFER)
				buf->prev_type = 1;
#endif
		}
		numRemoved += rmlen;
		to_remove -= rmlen;
	}

	buf->total_buf_size -= numRemoved;
	buf->head_seq += numRemoved;

	//TRACE_INFO("total_buf_size:%u, head_seq:%u\n", buf->total_buf_size, buf->head_seq);

	return numRemoved;
#else
	meta_send_buffer *msb;

	if (len <= 0)
		return 0;

	to_remove = MIN(len, buf->total_buf_size);
	if (to_remove <= 0) {
		return -2;
	}

	numRemoved = to_remove;

	while (to_remove > 0)
	{
		msb = buf->msb_head;
		if (!msb) {
			trace_snd_buf("num_fb:%u, to_remove:%lu, head_seq:%u\n", 
					buf->num_fb, to_remove, buf->head_seq);
			if (buf->num_fb == 0) {
				if (buf->len > 0)
					rmlen = RemoveRealPayload(buf, to_remove);
				else 
					rmlen = RemoveFrdOffload(buf, to_remove);
			} else if (buf->head_seq == buf->fb_ptr[0]->head_seq + buf->fb_ptr[0]->already_sent) {
				rmlen = RemoveFB(buf, to_remove);
			} else { 
				rmlen = RemoveRealPayload(buf, to_remove);
				assert(rmlen < 300);
			}
			to_remove -= rmlen;
		} else if (buf->head_seq == msb->head_seq + msb->already_sent) {
			rmlen = RemoveMetaPayload(sbm, buf, to_remove, cpu, sockid);
			to_remove -= rmlen;
		} else if (buf->head_seq < msb->head_seq + msb->already_sent){
			rmlen = RemoveRealPayload(buf, msb->head_seq + msb->already_sent - buf->head_seq);
			to_remove -= rmlen;
		} else {
			/* TODO 
			 * Sequence number is wrapped around */
			TRACE_ERROR("Sequence number is wrapped around\n");
		}

	}

	return numRemoved;
#endif
}
/*----------------------------------------------------------------------------*/
#else /* ENABLE_NIC_CACHE */
size_t 
SBRemove(sb_manager_t sbm, struct tcp_send_buffer *buf, size_t len)
{
	size_t to_remove;

	if (len <= 0)
		return 0;

	to_remove = MIN(len, buf->len);
	if (to_remove <= 0) {
		return -2;
	}

	buf->head_off += to_remove;
	buf->head = buf->data + buf->head_off;
	buf->head_seq += to_remove;
	buf->len -= to_remove;

	/* if buffer is empty, move the head to 0 */
	if (buf->len == 0 && buf->head_off > 0) {
		buf->head = buf->data;
		buf->head_off = buf->tail_off = 0;
	}

	return to_remove;
}
#endif /* ENABLE_NIC_CACHE */
/*---------------------------------------------------------------------------*/
#if 0
const void
SBGetHeadFlexBufferType(struct tcp_send_buffer *buf, uint16_t dport, uint32_t seq) {
	flex_buffer *flex_buf, *flex_buf_next;
	TAILQ_HEAD(, flex_buffer) *flex_buffer_list = buf->flex_buffer_list;
	flex_buf = TAILQ_FIRST(flex_buffer_list);

	if (!flex_buf)
		return;
	flex_buf_next = TAILQ_NEXT(flex_buf, flex_buffer_link);
	if (flex_buf_next) {
		TRACE_INFO("cur:%s next:%s, port:%u, head_seq:%u, flex_head_seqs:%u, seq:%u\n", 
				FLEX_BUFFER_TYPE(flex_buf), FLEX_BUFFER_TYPE(flex_buf_next), dport,
				buf->head_seq, flex_buf->head_seq, seq);
	} else {
		TRACE_INFO("cur:%s, dport:%u, head_seq:%u, flex_head_seqs:%u, seq:%u\n", 
				FLEX_BUFFER_TYPE(flex_buf), dport,
				buf->head_seq, flex_buf->head_seq, seq);
	}
}
#endif
/*---------------------------------------------------------------------------*/
bool
SBIsHostPath(struct tcp_send_buffer *buf) {
	flex_buffer *flex_buf, *flex_buf_next;
	TAILQ_HEAD(, flex_buffer) *flex_buffer_list = buf->flex_buffer_list;
	flex_buf = TAILQ_FIRST(flex_buffer_list);

	if (!flex_buf) {
		return true;
	}
	flex_buf_next = TAILQ_NEXT(flex_buf, flex_buffer_link);
	if (!flex_buf_next) {
		if (flex_buf->type == L1_CACHE_BUFFER ||flex_buf->type == FRD_OFFLOAD_BUFFER) {
			return false;
		} 
	} else {
		if (flex_buf_next->type == L1_CACHE_BUFFER || flex_buf_next->type == FRD_OFFLOAD_BUFFER) {
			return false;
		} 
	}
	return true;
}
