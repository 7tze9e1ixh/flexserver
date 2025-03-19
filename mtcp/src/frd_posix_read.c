#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/queue.h>
#include <assert.h>
#include <sys/mman.h>

#include <rte_common.h>
#include <rte_branch_prediction.h>

#include "frd.h"
#include "debug.h"
#include "memory_mgt.h"
#include "util.h"
#include "file_buffer.h"
#include "flex_buffer.h"

//#define NUM_PER_MTCP_CPUS 2
#define MAX_PER_CORE_FRD_WORKERS 16
#define NUM_PER_CORE_FRD_WORKERS 1
#define TOTAL_ENTRIES 16384
#define USE_O_DIRECT TRUE
#define MAX_IOVS MAX_ALIGNED_MEMCHUNKS
#define ENABLE_FRD_PROC FALSE
//#define FRD_PROCESS_ALL TRUE

#define DBG_FRD FALSE
#define DBG_FW_MAPPING FALSE
#define DO_SANITY_CHECK FALSE
#define TMPBUF_SIZE (8 * 1024 * 1024)

#define SHOW_FRD_STATUS FALSE

#define CID_MASK (NUM_PER_MTCP_CPUS - 1)
#define WID_MASK (NUM_PER_CORE_FRD_WORKERS - 1)
#define GET_CID(hv) (uint16_t)((hv) & CID_MASK)
#define GET_WID(hv) (uint16_t)( (hv)  & WID_MASK)

#define FRD_POSIX_READ_ENABLE_UNIX_DOMAIN_SOCKET TRUE

#if DBG_FRD
#define TRACE_FRD(f, ...)  fprintf(stderr, "(%10s:%4d) " f, \
		__func__, __LINE__, ##__VA_ARGS__)
#else
#define TRACE_FRD(f, ...) (void)0
#endif

#if USE_O_DIRECT
#define FRD_TMPBUF_SIZE (1024 * 1024 * 4)
#endif

typedef struct frd_request {
	int frr_fd;
	tcp_stream *frr_stream;
	uint32_t frr_toRead;
	TAILQ_ENTRY(frd_request) frr_link;
#if DBG_FW_MAPPING
	uint16_t cid;
	uint16_t wid;
#endif
} frd_request;

struct frr_pool {
	frd_request *frr_ptr;
	pthread_spinlock_t frr_pool_sl;
	TAILQ_HEAD(, frd_request) frr_free_list;
	uint32_t numFrrs;
};

typedef struct frd_worker {
	pthread_t frd_tid;
	mtcp_manager_t frd_mtcp;
	uint16_t frd_cid;
	uint16_t frd_wid;
	TAILQ_HEAD(, frd_request) frr_q;
	uint32_t frr_q_sz;
	pthread_mutex_t frr_mtx;
	pthread_cond_t frr_cnd;
	pthread_spinlock_t frr_sl;

	struct frr_pool *pool;
#if ENABLE_FRD_PROC
	TAILQ_HEAD(, frd_request) frr_compl;
	pthread_spinlock_t frr_compl_sl;
	uint32_t frr_compl_q_sz;
	uint32_t ts;
#endif
	file_buffer_pool *frd_fbp;
	bool run;

#if SHOW_FRD_STATUS
	uint64_t us_proc_thread;
	uint64_t us_proc_prev;
#endif

#if DO_SANITY_CHECK
	unsigned char *tmpbuf;
#endif
} frd_worker;

static uint32_t g_numMPChunks;
static uint16_t g_start_cpu;
static frd_worker *g_frd_worker[MAX_CPUS][MAX_PER_CORE_FRD_WORKERS] = {0};
//static file_buffer_pool *g_fb_pool[MAX_CPUS] = {NULL};
//static mem_pool_t g_frr_mp[MAX_CPUS];
//static mtcp_manager_t g_mtcp_manager[MAX_CPUS];

inline static struct frr_pool *
__create_frr_pool(uint32_t numFrrs) {

	int i;
	struct frr_pool *pool;

	pool = calloc(1, sizeof(struct frr_pool));
	if (!pool) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	pool->numFrrs = numFrrs;
	pthread_spin_init(&pool->frr_pool_sl, PTHREAD_PROCESS_PRIVATE);
	TAILQ_INIT(&pool->frr_free_list);

	pool->frr_ptr = calloc(numFrrs, sizeof(frd_request));
	if (!pool->frr_ptr) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < numFrrs; i++) 
		TAILQ_INSERT_TAIL(&pool->frr_free_list, &pool->frr_ptr[i], frr_link);

	return pool;
}

inline static frd_request *
__alloc_frr(struct frr_pool *pool) {
	frd_request *frr;
	pthread_spin_lock(&pool->frr_pool_sl);
	frr = TAILQ_FIRST(&pool->frr_free_list);
	TAILQ_REMOVE(&pool->frr_free_list, frr, frr_link);
	pthread_spin_unlock(&pool->frr_pool_sl);
	return frr;
}

inline static void
__free_frr(struct frr_pool *pool, frd_request *frr) {
	pthread_spin_lock(&pool->frr_pool_sl);
	TAILQ_INSERT_TAIL(&pool->frr_free_list, frr, frr_link);
	pthread_spin_unlock(&pool->frr_pool_sl);
}

inline static void
__destroy_frr_pool(struct frr_pool *pool) {
	free(pool->frr_ptr);
	pthread_spin_destroy(&pool->frr_pool_sl);
	free(pool);
}

#if DO_SANITY_CHECK
static void
__do_sanity_check(frd_worker *fw, int frr_fd, unsigned char *data, uint32_t data_len) {
	int open_flag;
	ssize_t ret;

	open_flag = fcntl(frr_fd, F_GETFL);
	if (open_flag < 0) 
		goto err_fcntl;
	open_flag &= ~O_DIRECT;
	ret = fcntl(frr_fd, F_SETFL, open_flag);
	if (ret < 0)
		goto err_fcntl;

	ret = pread(frr_fd, fw->tmpbuf, data_len, 0);
	assert(ret == data_len);

	ret = memcmp(data, fw->tmpbuf, data_len);
	assert(ret == 0);
	return;
err_fcntl :
	perror("fcntl()");
	exit(EXIT_FAILURE);
}
#endif

inline static void 
__activate_flow(mtcp_manager_t mtcp, frd_worker *fw, frd_request *frr) {
	tcp_stream *stream;

	stream = frr->frr_stream;

	if (!(stream->sndvar->on_sendq || stream->sndvar->on_send_list)) {
		SQ_LOCK(&mtcp->ctx->sendq_lock);
		stream->sndvar->on_sendq = TRUE;
		StreamEnqueue(mtcp->sendq, stream);
		SQ_UNLOCK(&mtcp->ctx->sendq_lock);
		mtcp->wakeup_flag = TRUE;
	}

	close(frr->frr_fd);
	__free_frr(fw->pool, frr);
}

static void *
__posix_file_read(void *opaque) {

	frd_request *frr;
	struct tcp_send_buffer *buf;
	tcp_stream *stream;
	ssize_t rdlen, toRead;
	frd_worker *fw;
#if ENABLE_FLEX_BUFFER
	struct iovec iovs[MAX_IOVS];
#endif

	fw = opaque;

	set_thread_core_affinity(fw->frd_cid);
#if SHOW_FRD_STATUS
	uint64_t before, after, start, numLoops=0, end;
	uint64_t sum_frr_sl_lat = 0, sum_frr_coml_lat = 0, 
			 sum_tot_lat = 0, sum_file_io_lat = 0, sum_activate_flow = 0;
	fprintf(stderr, "%lu\n", (uint64_t)gettid());
#endif

	while (fw->run) {
		pthread_mutex_lock(&fw->frr_mtx);
		if (fw->frr_q_sz <= 0) 
			pthread_cond_wait(&fw->frr_cnd, &fw->frr_mtx);
#if SHOW_FRD_STATUS
		numLoops++;
		start = get_cur_us();
#endif
		pthread_spin_lock(&fw->frr_sl);
#if SHOW_FRD_STATUS
		after = get_cur_us();
		sum_frr_sl_lat += (after - start);
#endif
		frr = TAILQ_FIRST(&fw->frr_q);
		TAILQ_REMOVE(&fw->frr_q, frr, frr_link);
		fw->frr_q_sz--;
		assert(frr);
		pthread_spin_unlock(&fw->frr_sl);

		if (unlikely(frr->frr_toRead > FILE_BUFFER_SIZE)) {
			TRACE_ERROR("File size larger than 4MB is not supported yet...\n");
			exit(EXIT_FAILURE);
		}

		stream = frr->frr_stream;
		buf = stream->sndvar->sndbuf;

		if (!buf) 
			goto frr_clean_up;
		toRead = frr->frr_toRead;
		TRACE_FRD("cid:%u, wid:%u, frr:%p, frr_toRead:%u, frr_fd:%d, stream:%p, mtcp:%p\n", 
				fw->frd_cid, fw->frd_wid, frr, 
				frr->frr_toRead, frr->frr_fd, stream, fw->frd_mtcp);

		file_buffer *fb;
#if ENABLE_FLEX_BUFFER
		int32_t ret;
		uint32_t numIOVs, i;
		fb = fb_alloc(fw->frd_fbp, toRead);
		if (!fb) {
			TRACE_ERROR("Increase # of file buffers\n");
			exit(EXIT_FAILURE);
		}

		numIOVs = get_howmany(toRead, FILE_BUFFER_SIZE);
		for (i = 0; i < numIOVs; i++) {
			iovs[i].iov_base = fb->am[i]->addr;
			iovs[i].iov_len = FILE_BUFFER_SIZE;
		}

		rdlen = preadv(frr->frr_fd, iovs, numIOVs, 0);
		if (rdlen < 0) {
			TRACE_ERROR("read(), %s, frr:%p, fd:%d cid:%u, wid:%u\n", 
						strerror(errno), frr, frr->frr_fd, fw->frd_cid, fw->frd_wid);
			exit(EXIT_FAILURE);
		}

		ret = flex_buffer_attach_with_lock(fw->frd_mtcp, stream, FILE_BUFFER, fb, toRead);
		if (ret < 0) {
			TRACE_ERROR("Increase # of flex buffer\n");
			exit(EXIT_FAILURE);
		}

		buf->total_buf_size += toRead;
#else /* !ENABLE_FLEX_BUFFER */
		uint32_t seq_offset = 0;
		assert(buf->num_fb == 0);
#if SHOW_FRD_STATUS
		before = get_cur_us();
#endif
		while (toRead > 0) {
			fb = fb_alloc(fw->frd_fbp);
			rdlen = read(frr->frr_fd, fb->data, fb->buf_len);
			if (rdlen < 0) {
				TRACE_ERROR("read(), %s, frr:%p, fd:%d cid:%u, wid:%u\n", 
						strerror(errno), frr, frr->frr_fd, fw->frd_cid, fw->frd_wid);
				exit(EXIT_FAILURE);
			}
			fb->data_len = rdlen;
			fb->head_seq = buf->head_seq + buf->total_buf_size + seq_offset;
			fb->already_sent = 0;
			seq_offset += rdlen;
			toRead -= rdlen;

			TRACE_FRD("cid:%u, wid:%u, fb:%p, head_seq:%u\n",
					fw->frd_cid, fw->frd_wid, fb, fb->head_seq);
		}
#if SHOW_FRD_STATUS
		after = get_cur_us();
		sum_file_io_lat += (after - before);
#endif

		SBUF_LOCK(&stream->sndvar->write_lock);

		/* TODO */
		buf->fb_ptr[0] = fb;
		buf->num_fb = 1;

#if DO_SANITY_CHECK
		__do_sanity_check(fw, frr->frr_fd, fb->data, fb->data_len);
#endif

		buf->tail_off += frr->frr_toRead;
		//buf->len += frr->frr_toRead;
		buf->cum_len += frr->frr_toRead;
#if ENABLE_NIC_CACHE
		buf->total_buf_size += frr->frr_toRead;
#endif
		SBUF_UNLOCK(&stream->sndvar->write_lock);

#if SHOW_FRD_STATUS
		before = get_cur_us();
#endif
#endif /* ENABLE_FLEX_BUFFER */

#if ENABLE_FRD_PROC
		pthread_spin_lock(&fw->frr_compl_sl);
#if SHOW_FRD_STATUS
		after = get_cur_us();
		sum_frr_coml_lat += (after - before);
#endif
		TAILQ_INSERT_TAIL(&fw->frr_compl, frr, frr_link);
		fw->frr_compl_q_sz++;
		pthread_spin_unlock(&fw->frr_compl_sl);
		TRACE_FRD("Enqueue frr, fd:%d, frr:%p, frr_mp:%p\n", frr->frr_fd, frr, fw->frr_pool);
#else /* !ENABLE_FRD_PROC */
#if SHOW_FRD_STATUS
		before = get_cur_us();
#endif
		__activate_flow(fw->frd_mtcp, fw, frr);
#if SHOW_FRD_STATUS
		after = get_cur_us();
		sum_activate_flow += (after - before);
#endif
#endif /* ENABLE_FRD_PROC */


#if SHOW_FRD_STATUS
		end = get_cur_us();
		sum_tot_lat += (end - start);
		if (end - fw->us_proc_thread >= 1000000) {
			fprintf(stderr, "avg frr_sl lat:%4.2lf, "
					"avg frr_coml_lat:%4.2lf, "
					"avg file io lat:%4.2lf, "
					"avg activate_flow:%4.2lf, "
					"avg tot lat:%4.2lf\n ",
					(double)(sum_frr_sl_lat) / numLoops, 
					(double)(sum_frr_coml_lat) / numLoops,
					(double)(sum_file_io_lat) / numLoops,
					(double)(sum_activate_flow) / numLoops,
					(double)(sum_tot_lat) / numLoops);
			fw->us_proc_thread = end;
		}
#endif

frr_clean_up :
		pthread_mutex_unlock(&fw->frr_mtx);
	}

	return NULL;
}

void 
frd_global_init(uint32_t maxQueueDepth) {

	//char tmpbuf[256];

	(void)maxQueueDepth;

	g_start_cpu = CONFIG.num_cores;
	g_numMPChunks = 32768 / CONFIG.num_cores;
}

static frd_worker *
__frd_create_worker(mtcp_manager_t mtcp, uint16_t cid, uint16_t wid) {

        int ret;
        frd_worker *fw;

        fw = calloc(1, sizeof(frd_worker));
        if (!fw) {
			perror("malloc()");
			exit(EXIT_FAILURE);
        }

		TAILQ_INIT(&fw->frr_q);
		fw->frd_cid = cid;
		fw->frd_wid = wid;
		fw->frr_q_sz = 0;
		fw->run = true;
		fw->frd_mtcp = mtcp;

		TRACE_INFO("Create worker(cid:%u wid:%u)\n", cid, wid);
/*
		char tmpbuf[256];
		sprintf(tmpbuf, "frr_mp-%u-%u", cid, wid);
		fw->frr_mp = MPCreate(tmpbuf, sizeof(frd_request), sizeof(frd_request) * g_numMPChunks);
		if (!fw->frr_mp) {
			TRACE_ERROR("Fail to create %s\n", tmpbuf);
			exit(EXIT_FAILURE);
		}*/
		fw->pool = __create_frr_pool(g_numMPChunks);

	    ret = pthread_mutex_init(&fw->frr_mtx, NULL);
		if (ret != 0) {
			TRACE_ERROR("Fail to init frr_mtx (%s)\n", strerror(ret));
			exit(EXIT_FAILURE);
		}

		ret = pthread_cond_init(&fw->frr_cnd, NULL);
		if (ret != 0) {
			TRACE_ERROR("Fail to init frr_cnd (%s)\n", strerror(ret));
			exit(EXIT_FAILURE);
		}

		ret = pthread_spin_init(&fw->frr_sl, PTHREAD_PROCESS_PRIVATE);
		if (ret != 0) {
			TRACE_ERROR("Fail to init frr_sl (%s)\n", strerror(ret));
			exit(EXIT_FAILURE);
		}

		fw->frd_fbp = fb_pool_create(cid, wid, MAX_FILE_BUFFERS /
				(CONFIG.num_cores * NUM_PER_CORE_FRD_WORKERS));

#if DO_SANITY_CHECK
		ret = posix_memalign((void **)&fw->tmpbuf, TMPBUF_SIZE, TMPBUF_SIZE);
		if (ret != 0) {
			TRACE_ERROR("Fail to allocate tmpbuf, %s\n", strerror(ret));
			exit(EXIT_FAILURE);
		}
#endif

#if ENABLE_FRD_PROC
		TAILQ_INIT(&fw->frr_compl);
		pthread_spin_init(&fw->frr_compl_sl, PTHREAD_PROCESS_PRIVATE);
		fw->ts = mtcp->cur_ts;
#endif /* ENABLE_FRD_PROC */

		ret = pthread_create(&fw->frd_tid, NULL, __posix_file_read, fw);
		if (ret != 0) {
			TRACE_ERROR("Fail to create __worker_thread (%s)\n", strerror(ret));
			exit(EXIT_FAILURE);
		}

		return fw;
}

void
frd_create_worker(mtcp_manager_t mtcp) {
	int i;

	for (i = 0; i < NUM_PER_CORE_FRD_WORKERS; i++)
		g_frd_worker[mtcp->ctx->cpu][i] = __frd_create_worker(mtcp, mtcp->ctx->cpu, i);
}

void
frd_destroy_worker(mtcp_manager_t mtcp) {
    frd_worker *fw ;
    int i, j;
    uint16_t cid;
	cid = mtcp->ctx->cpu;
	UNUSED(j);

	for (i = 0; i < NUM_PER_CORE_FRD_WORKERS; i++) {
		fw = g_frd_worker[cid][i];
		//MPDestroy(fw->frr_mp);
		free(fw);
		pthread_cond_destroy(&fw->frr_cnd);
		pthread_mutex_destroy(&fw->frr_mtx);
		pthread_spin_destroy(&fw->frr_sl);
		__destroy_frr_pool(fw->pool);
	}
}

int
frd_issue_request(mtcp_manager_t mtcp, int fr_fd, tcp_stream *cur_stream) {

	uint32_t frr_toRead;
	frd_worker *fw;
	frd_request *frr;
	uint16_t cid, wid;
	uint64_t hv;
//	int ret;

	hv = HashFlow(cur_stream);
	cid = mtcp->ctx->cpu;
	wid = GET_WID(hv);

	fw = g_frd_worker[cid][wid];
	frr_toRead = lseek(fr_fd, 0, SEEK_END);
	lseek(fr_fd, 0, SEEK_SET);
	assert(frr_toRead > 0);

	//buf = cur_stream->sndvar->sndbuf;
#if !ENABLE_FLEX_BUFFER
	struct tcp_send_buffer *buf;
	buf = cur_stream->sndvar->sndbuf;
    if (buf->tail_off + frr_toRead >= buf->size) {
        memmove(buf->data, buf->head, buf->len);
        buf->head = buf->data;
        buf->head_off = 0;
        buf->tail_off = buf->len;
    }
#endif

	frr = __alloc_frr(fw->pool);
/*
    frr = MPAllocateChunk(fw->frr_mp);
    if (!frr) {
        TRACE_ERROR("Increase # of chunks, q_sz:%u\n", fw->frr_q_sz);
        exit(EXIT_FAILURE);
    }*/
#if 0
	ret = posix_fadvise(fr_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
	if (ret != 0) {
		TRACE_ERROR("posix_fadvise(), %s\n", strerror(ret));
		exit(EXIT_FAILURE);
	}
#endif

    frr->frr_stream = cur_stream;
    frr->frr_toRead = frr_toRead;
    frr->frr_fd = fr_fd;
#if DBG_FW_MAPPING
	frr->cid = cid;
	frr->wid = wid;
#endif


	TRACE_FRD("Issue cid:%u, wid:%u, frr:%p, stream:%p, toRead:%u, fd:%d, fw:%p mtcp:%p "
			"hv:%lu, reversed:%lu\n",
			cid, wid, frr, frr->frr_stream, frr->frr_toRead, frr->frr_fd, fw, mtcp,
			hv, (hv >> 32) | (hv << 32));

    pthread_spin_lock(&fw->frr_sl);
    TAILQ_INSERT_TAIL(&fw->frr_q, frr, frr_link);
    fw->frr_q_sz++;
    pthread_cond_signal(&fw->frr_cnd);
    pthread_spin_unlock(&fw->frr_sl);

	return frr_toRead;
}

#define MAX_FRR_SIZE 4096
#define FRD_PROC_TIMEOUT 10

void
frd_process_response(mtcp_manager_t mtcp) {
#if ENABLE_FRD_PROC
	int wid, ret;
	uint32_t frr_compl_q_sz, i;
	frd_worker *fw;
	frd_request *frr, *frr_arr[MAX_FRR_SIZE];
	//tcp_stream *stream;

	for (wid = 0; wid < NUM_PER_CORE_FRD_WORKERS; wid++) {
		fw = g_frd_worker[mtcp->ctx->cpu][wid];
#if 1
		if (mtcp->cur_ts - fw->ts < FRD_PROC_TIMEOUT / CONFIG.num_cores)
			continue;
#endif

		fw->ts = mtcp->cur_ts;

		ret = pthread_spin_trylock(&fw->frr_compl_sl);
		if (ret == EBUSY)
			continue;

		assert(ret == 0);
		frr_compl_q_sz = RTE_MIN(fw->frr_compl_q_sz, MAX_FRR_SIZE);

		if (frr_compl_q_sz == 0) {
			pthread_spin_unlock(&fw->frr_compl_sl);
			continue;
		}

		for (i = 0; i < frr_compl_q_sz; i++) {
			frr_arr[i] = TAILQ_FIRST(&fw->frr_compl);
			TAILQ_REMOVE(&fw->frr_compl, frr_arr[i], frr_link);
		}
		fw->frr_compl_q_sz -= frr_compl_q_sz;
		pthread_spin_unlock(&fw->frr_compl_sl);

		for (i = 0; i < frr_compl_q_sz; i++) {
			frr = frr_arr[i];
			__activate_flow(mtcp, fw, frr);
#if 0
			stream = frr->frr_stream;

			TRACE_FRD("frr_compl_q_sz:%u, cid:%u, wid:%u, frr:%p fd:%d, %lu\n", 
					frr_compl_q_sz, mtcp->ctx->cpu, wid, frr, frr->frr_fd, ts);

			if (!(stream->sndvar->on_sendq || stream->sndvar->on_send_list)) {
				SQ_LOCK(&mtcp->ctx->sendq_lock);
				stream->sndvar->on_sendq = TRUE;
				StreamEnqueue(mtcp->sendq, stream);
				SQ_UNLOCK(&mtcp->ctx->sendq_lock);
				mtcp->wakeup_flag = TRUE;
			}

			close(frr->frr_fd);
			frr->frr_fd = -1;
			__free_frr(fw->pool, frr);
#endif
		}
	}
#endif /* ENABLE_FRD_PROC */
}

void
frd_global_destroy(void) {
	/* TODO */
}
