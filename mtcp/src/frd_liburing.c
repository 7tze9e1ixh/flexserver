#include <liburing.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/uio.h>
#include <pthread.h>

#include <rte_atomic.h>
#include <rte_common.h>

#include "debug.h"
#include "frd_liburing.h"
#include "memory_mgt.h"
#include "file_buffer.h"
#include "util.h"
#include "nic_cache.h"
#include "flex_buffer.h"
#include "flex_debug.h"
#include "frd_rate_limit.h"

#define DBG_FRD_LIBURING FALSE
#define MAX_IOV 512
#define MAX_IOV_LEN FILE_BUFFER_SIZE //(4 * 1024 * 1024)
#define FRR_BATCH_SIZE 256
#define FRR_THRESH 32 //(FRR_BATCH_SIZE / 16)
#define FRD_WORKER_TIMEOUT 50000 // 50000(ns)
#define SANITY_CHECK FALSE
#define DUMMY_BUF_SIZE (16 * 1024 * 1024)

#if DBG_FRD_LIBURING
#define trace_frd_liburing(f, ...) fprintf(stderr, "(%10s:%4d) " f, \
		__func__, __LINE__, ##__VA_ARGS__)
#else
#define trace_frd_liburing(f, ...) (void)0
#endif

typedef struct frd_request {
	tcp_stream *frr_stream;
	uint32_t frr_toRead;
	int frr_fd;
	struct iovec *frr_iov;
	file_buffer *frr_fb;
#if SANITY_CHECK
	unsigned char *data;
#endif
	TAILQ_ENTRY(frd_request) frr_link;

#if DBG_DISK_STACK_STATUS || FRD_RATE_LIMIT_DBG_STATUS
	uint64_t us_submitted;
#endif

#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT
	uint32_t nvme_id;
#endif
} frd_request;

typedef struct frd_worker {
	struct io_uring *frd_io_uring;
	rte_atomic32_t frd_io_pending;
	//struct io_uring_cqe **frd_cqe;
	mem_pool_t frd_mp;
	mem_pool_t frr_iov_mp;
#if !NO_WORKER_THREAD
	TAILQ_HEAD(, frd_request) frr_q;
	uint32_t frr_q_sz;
	pthread_mutex_t frr_mtx;
	pthread_cond_t frr_cnd;
	pthread_spinlock_t frr_sl;
	bool run;
#endif
	struct file_buffer_pool *frd_fbp;
#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT || FRD_LIBURING_ENABLE_QUEUE_DEPTH_COORDINATION
	TAILQ_HEAD(, frd_request) frr_wait_list;
	uint32_t frr_wait_list_size;
#endif

} frd_worker;

//static unsigned g_uring_queue_flags = (IORING_SETUP_IOPOLL | IORING_SETUP_SINGLE_ISSUER);
//static unsigned g_uring_queue_flags = IORING_SETUP_IOPOLL;
static unsigned g_uring_queue_flags = 0;
static unsigned g_maxNumEntries = 0;
static frd_worker *g_frd_worker[MAX_CPUS];
static unsigned char *g_dummy_buf;

#if SANITY_CHECK
inline static void
__do_sanity_check(int frr_fd, unsigned char *data, uint32_t data_len) {

	unsigned char *buf;
	ssize_t ret;
	int open_flag;
	
	open_flag = fcntl(frr_fd, F_GETFL);
	if (open_flag < 0) 
		goto err_fcntl;

	open_flag &= ~O_DIRECT;

	ret = fcntl(frr_fd, F_SETFL, open_flag);
	if (ret < 0)
		goto err_fcntl;

	buf = malloc(data_len);
	if (!buf) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}

	ret = pread(frr_fd, buf, data_len, 0);
	if (ret != data_len) {
		TRACE_ERROR("Asynchronous read fails\n");
		exit(EXIT_FAILURE);
	}

	ret = memcmp(data, buf, data_len);
	if (ret != 0) {
		TRACE_ERROR("Asynchronous read fails\n");
		exit(EXIT_FAILURE);
	}

	free(buf);

	return;
err_fcntl :
	perror("fcntl()");
	exit(EXIT_FAILURE);
}
#endif

inline static int
__prep_read(frd_worker *fw, frd_request *frr, unsigned char *data, uint32_t toRead) {
	struct io_uring_sqe *sqe;
	int i;
	//uint32_t iov_len;
	file_buffer *fb;

	fb = fb_alloc(fw->frd_fbp, toRead);
	if (!fb) 
		return -1;

	sqe = io_uring_get_sqe(fw->frd_io_uring);
	if (!sqe) {
		fb_clean_up(fb);
		return -1;
	}

	for (i = 0; i < fb->numChunks; i++) {
		frr->frr_iov[i].iov_base = fb->am[i]->addr;
		frr->frr_iov[i].iov_len = MAX_IOV_LEN;
	}

	frr->frr_fb = fb;

	trace_frd_liburing("sqe:%p, frr:%p, numChunks:%u\n", sqe, frr, fb->numChunks);

	io_uring_prep_readv(sqe, frr->frr_fd, &frr->frr_iov[0], fb->numChunks, 0);
	io_uring_sqe_set_data(sqe, frr);
#if KERNEL_POLL_MODE
	io_uring_submit(fw->frd_io_uring);
#endif

	return 1;
}

#if !NO_WORKER_THREAD
static void *
__worker_thread(void *opaque) {

	mtcp_manager_t mtcp;
	frd_worker *fw;
	uint32_t numProcess, totSQEs;
	frd_request *frr;
	frd_request *frr_arr[FRR_BATCH_SIZE];
	int i, numSQEs, ret;
	//uint32_t numIOPending;
	struct tcp_send_buffer *buf;
	struct timespec ts_now;

	mtcp = (mtcp_manager_t )opaque;
	fw = g_frd_worker[mtcp->ctx->cpu];

	set_thread_core_affinity(mtcp->ctx->cpu);

	while (fw->run) {
		pthread_mutex_lock(&fw->frr_mtx);

		clock_gettime(CLOCK_REALTIME, &ts_now);
		ts_now.tv_nsec += FRD_WORKER_TIMEOUT;
		pthread_cond_timedwait(&fw->frr_cnd, &fw->frr_mtx, &ts_now);

		if (fw->frr_q_sz == 0) {
			pthread_mutex_unlock(&fw->frr_mtx);
			continue;
		}

		//pthread_spin_lock(&fw->frr_sl);
		ret = pthread_spin_trylock(&fw->frr_sl);
		if (ret == EBUSY) {
			pthread_mutex_unlock(&fw->frr_mtx);
			continue;
		}

		numProcess = RTE_MIN(FRR_BATCH_SIZE, fw->frr_q_sz);

		for (i = 0; i < numProcess; i++) {
			frr = TAILQ_FIRST(&fw->frr_q);
			TAILQ_REMOVE(&fw->frr_q, frr, frr_link);
			frr_arr[i] = frr;
		}

		fw->frr_q_sz -= numProcess;

		pthread_spin_unlock(&fw->frr_sl);

		totSQEs = 0;
#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT
		uint32_t count = 0, max_count = fw->frr_wait_list_size;
		while(count < max_count) {
			frr = TAILQ_FIRST(&fw->frr_wait_list);
			count++;

			if (!frr) 
				break;

			TAILQ_REMOVE(&fw->frr_wait_list, frr, frr_link);
			if (!frd_rate_limit_can_submit_now(mtcp, frr->nvme_id)) {
				TAILQ_INSERT_TAIL(&fw->frr_wait_list, frr, frr_link);
				continue;
			}

			numSQEs = __prep_read(fw, frr, NULL, frr->frr_toRead);

			fw->frr_wait_list_size--;
			rte_atomic32_add(&fw->frd_io_pending, numSQEs);
		}
#endif
		for (i = 0; i < numProcess; i++) {
#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT
			if (!frd_rate_limit_can_submit_now(mtcp, frr_arr[i]->nvme_id)) {
				TAILQ_INSERT_TAIL(&fw->frr_wait_list, frr_arr[i], frr_link);
				fw->frr_wait_list_size++;
				continue;
			}
#endif
			buf = frr_arr[i]->frr_stream->sndvar->sndbuf;
			if (!buf) {
				numSQEs = __prep_read(fw, frr_arr[i], g_dummy_buf, frr->frr_toRead);
			} else {
				numSQEs = __prep_read(fw, frr_arr[i], NULL, frr->frr_toRead);
				buf->numChunks = numSQEs;
				rte_atomic32_init(&buf->numCompletes);
			}
			rte_atomic32_add(&fw->frd_io_pending, numSQEs);
#if FRD_RATE_LIMIT_DBG_STATUS
			frd_rate_limit_incr_numIOPendings(mtcp, frr_arr[i]->frr_fd);
			frd_rate_limit_add_num_req_bytes(mtcp, frr_arr[i]->frr_fd);
#endif
			totSQEs += numSQEs;
		}

#if !KERNEL_POLL_MODE
		io_uring_submit(fw->frd_io_uring);
#endif

		pthread_mutex_unlock(&fw->frr_mtx);
	}

	return NULL;
}
#endif

void
frd_global_init(uint32_t maxNumEntries) {

	// 32768
	g_maxNumEntries = maxNumEntries * 8;

	g_dummy_buf = malloc(DUMMY_BUF_SIZE);
	if (!g_dummy_buf) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}
}

void
frd_create_worker(mtcp_manager_t mtcp) {

	int ret, i;
	frd_worker *fw;
	char tmpbuf[256];
#if !NO_WORKER_THREAD
	pthread_t workerThread;
#endif

	fw = malloc(sizeof(frd_worker));
	if (!fw) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}

	bzero(fw, sizeof(frd_worker));

	g_frd_worker[mtcp->ctx->cpu] = fw;

	fw->frd_io_uring = malloc(sizeof(struct io_uring));
	if (!fw->frd_io_uring) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}

	sprintf(tmpbuf, "frr-mp-%d", mtcp->ctx->cpu);
	fw->frd_mp = MPCreate(tmpbuf, sizeof(frd_request), 
			sizeof(frd_request) * g_maxNumEntries);
	if (!fw->frd_mp) {
		TRACE_ERROR("Fail to create memory pool for frd_mp\n");
		exit(EXIT_FAILURE);
	}

	sprintf(tmpbuf, "frr_iov_mp-%d", mtcp->ctx->cpu);
	fw->frr_iov_mp = MPCreate(tmpbuf, sizeof(struct iovec) * MAX_IOV,
			sizeof(struct iovec) * MAX_IOV * g_maxNumEntries);
	if (!fw->frr_iov_mp) {
		TRACE_ERROR("Fail to create memory pool for frr_iov_mp\n");
		exit(EXIT_FAILURE);
	}

#if POLL_MODE
	/**/
#elif KERNEL_POLL_MODE
	struct io_uring_params params;
	bzero(&params, sizeof(struct io_uring_params));
#if ENABLE_DEDICATED_SHARED_CPU_FOR_SQ_POLL_THREAD
	/* currently I changed this code for only using 8 cores */
#define NUM_POLLING_CPUS 4
	if (mtcp->ctx->cpu < NUM_POLLING_CPUS) {
		params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
		params.sq_thread_cpu = CONFIG.num_cores + mtcp->ctx->cpu % NUM_POLLING_CPUS;
		params.sq_thread_idle = SQ_THREAD_IDLE_TIME;
	} else {
		while(1) {
			/* Wait for master cpu's io_uring */
			if (g_frd_worker[mtcp->ctx->cpu % NUM_POLLING_CPUS])
				break;
		}

		params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_ATTACH_WQ;
		params.wq_fd = g_frd_worker[mtcp->ctx->cpu % NUM_POLLING_CPUS]->frd_io_uring->ring_fd;
	}
#else
	params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
	params.sq_thread_cpu = mtcp->ctx->cpu + CONFIG.num_cores;
#endif
	//params.sq_thread_idle = 2000;
	//ret = io_uring_queue_init_params(g_maxNumEntries, fw->frd_io_uring, &params);
	ret = io_uring_queue_init_params(QUEUE_DEPTH, fw->frd_io_uring, &params);
	(void)g_uring_queue_flags;

	TRACE_INFO("iou-s\n");
#else
#define URING_MAX_ENTRIES (4 * 1024) //16 * 1024 
	ret = io_uring_queue_init(URING_MAX_ENTRIES, fw->frd_io_uring, g_uring_queue_flags);
#endif
	if (ret != 0) {
		TRACE_ERROR("CPU%d, io_uring_queue_init(), %s\n", mtcp->ctx->cpu, strerror(-ret));
		exit(EXIT_FAILURE);
	}
	rte_atomic32_init(&fw->frd_io_pending);

#if !NO_WORKER_THREAD
	TAILQ_INIT(&fw->frr_q);
	fw->frr_q_sz = 0;
	fw->run = true;

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
#endif

	fw->frd_fbp = fb_pool_create(mtcp->ctx->cpu, 0, MAX_FILE_BUFFERS / CONFIG.num_cores);

#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT || FRD_LIBURING_ENABLE_QUEUE_DEPTH_COORDINATION
	TAILQ_INIT(&fw->frr_wait_list);
	fw->frr_wait_list_size = 0;
#endif

#if !NO_WORKER_THREAD
	ret = pthread_create(&workerThread, NULL, __worker_thread, mtcp);
	if (ret != 0) {
		TRACE_ERROR("Fail to create worker_thread (%s)\n", strerror(ret));
		exit(EXIT_FAILURE);
	}
#endif

	uint32_t count = 0;
	while (1) {
		if (g_frd_worker[count])
			count++;
		if (count == CONFIG.num_cores)
			break;
		usleep(10);
	}
}

void
frd_destroy_worker(mtcp_manager_t mtcp) {
	frd_worker *fw;
	fw = g_frd_worker[mtcp->ctx->cpu];
	io_uring_queue_exit(fw->frd_io_uring);
	free(fw->frd_io_uring);
	MPDestroy(fw->frd_mp);
	MPDestroy(fw->frr_iov_mp);
	free(fw);
}

#if FRD_LIBURING_ENABLE_QUEUE_DEPTH_COORDINATION
inline static void 
__frd_liburing_process_wait_list(frd_worker *fw) {

	int32_t ret;
	uint32_t numIOPendings;
	frd_request *frr;

	numIOPendings = rte_atomic32_read(&fw->frd_io_pending);

	while (numIOPendings <= FRD_LIBURING_MAX_IOPENDINGS) {
		frr = TAILQ_FIRST(&fw->frr_wait_list);
		if (!frr) break;
		TAILQ_REMOVE(&fw->frr_wait_list, frr, frr_link);
		
		ret = __prep_read(fw, frr, NULL, frr->frr_toRead);
		if (ret < 0) {
			TRACE_ERROR("Error occurs\n")
			exit(EXIT_FAILURE);
		}

		rte_atomic32_add(&fw->frd_io_pending, ret);
	}

	io_uring_submit(fw->frd_io_uring);
}
#endif

int
frd_issue_request(mtcp_manager_t mtcp, int fr_fd, tcp_stream *cur_stream) {

	uint32_t frd_toRead;
	frd_worker *fw;
	frd_request *frr;
	struct iovec *frr_iov;

#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT
	uint32_t nvme_id = frd_rate_limit_get_nvme_id(mtcp, fr_fd);
/*
	if (!frd_rate_limit_can_issue_now(mtcp, nvme_id)) {
		errno = EAGAIN;
		return -1;
	}*/
#endif

	fw = g_frd_worker[mtcp->ctx->cpu];

	trace_frd_liburing("issue (fr_fd=%d, stream:%p)\n", fr_fd, cur_stream);

#if FRD_LIBURING_ENABLE_QUEUE_DEPTH_COORDINATION && NO_WORKER_THREAD
	__frd_liburing_process_wait_list(fw);
#endif

	frd_toRead = lseek(fr_fd, (off_t)0, SEEK_END);
#if !ENABLE_FLEX_BUFFER
	struct tcp_send_buffer *buf;
	buf = cur_stream->sndvar->sndbuf;
	if (buf->tail_off + frd_toRead >= buf->size) {
		memmove(buf->data, buf->head, buf->len);
		buf->head = buf->data;
		buf->head_off = 0;
		buf->tail_off = buf->len;
	}
#endif

	frr = MPAllocateChunk(fw->frd_mp);
	if (!frr) {
		TRACE_ERROR("Increase # of chunks\n");
		exit(EXIT_FAILURE);
	}

	frr_iov = MPAllocateChunk(fw->frr_iov_mp);
	if (!frr_iov) {
		TRACE_ERROR("Increase # of frr_iov\n");
		exit(EXIT_FAILURE);
	}

	frr->frr_stream = cur_stream;
	frr->frr_toRead = frd_toRead;
	frr->frr_fd = fr_fd;
	frr->frr_iov = frr_iov;
#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT
	frr->nvme_id = nvme_id;
#endif

#if DBG_DISK_STACK_STATUS || FRD_RATE_LIMIT_DBG_STATUS
	frr->us_submitted = get_cur_us();
#endif

#if FRD_LIBURING_ENABLE_QUEUE_DEPTH_COORDINATION && NO_WORKER_THREAD
	uint32_t numIOPendings = rte_atomic32_read(&fw->frd_io_pending);
	if (numIOPendings <= FRD_LIBURING_MAX_IOPENDINGS) {
		TAILQ_INSERT_TAIL(&fw->frr_wait_list, frr, frr_link);
		return frd_toRead;
	}
#endif

#if NO_WORKER_THREAD
#if ENABLE_FLEX_BUFFER
	int numSQEs = __prep_read(fw, frr, NULL, frr->frr_toRead); 
#else
	int numSQEs = __prep_read(fw, frr, buf->data + buf->tail_off, frr->frr_toRead); 
#endif
	if (numSQEs == -1) {
		/* It will never occurs */
		MPFreeChunk(fw->frd_mp, frr);
		MPFreeChunk(fw->frr_iov_mp, frr_iov);
		errno = EAGAIN;
		return -1;
	}
	rte_atomic32_add(&fw->frd_io_pending, numSQEs);
	io_uring_submit(fw->frd_io_uring);
#else
	pthread_spin_lock(&fw->frr_sl);
	TAILQ_INSERT_TAIL(&fw->frr_q, frr, frr_link);
	fw->frr_q_sz++;
	if (fw->frr_q_sz >= FRR_THRESH)
		pthread_cond_signal(&fw->frr_cnd);
	pthread_spin_unlock(&fw->frr_sl);

#if DBG_DISK_STACK_STATUS
	g_nic_cache_stat[mtcp->ctx->cpu].numIssueReq_now++;
#endif

#endif
	return frd_toRead;
}

void
frd_process_response(mtcp_manager_t mtcp) {

	int ret;
	uint32_t i, numProc;
	uint32_t numIOPending;
	struct io_uring_cqe *frd_cqe;
	frd_worker *fw;
	frd_request *frr;
	struct tcp_send_buffer *buf;

	fw = g_frd_worker[mtcp->ctx->cpu];

	numProc = 0;
	numIOPending = rte_atomic32_read(&fw->frd_io_pending);
	for (i = 0; i < numIOPending; i++) {
	//	uint32_t numCompletes;
		ret = io_uring_peek_cqe(fw->frd_io_uring, &frd_cqe);
		//ret = io_uring_wait_cqe(frd_worker->frd_io_uring, &frd_cqe);
		if (ret == -EAGAIN) {
			break;
		}
		frr = io_uring_cqe_get_data(frd_cqe);
		buf = frr->frr_stream->sndvar->sndbuf;
		if (!buf) {
			close(frr->frr_fd);
			MPFreeChunk(fw->frr_iov_mp, frr->frr_iov);
			MPFreeChunk(fw->frd_mp, frr);
			io_uring_cqe_seen(fw->frd_io_uring, frd_cqe);
			rte_atomic32_dec(&fw->frd_io_pending);
			continue;
		}

		trace_frd_liburing("cqe:%p, stream:%p, numCompletes:%u, frr : %p, frr_fd : %d, res:%d(%s)\n", 
				frd_cqe, frr->frr_stream, numCompletes, frr, frr->frr_fd, 
				frd_cqe->res, strerror(-frd_cqe->res));

		if (frd_cqe->res <= 0) {
			TRACE_ERROR("Read fail\n");
			exit(EXIT_FAILURE);
		}

#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT
		frd_rate_limit_end(mtcp, frr->nvme_id);
#endif

#if DBG_DISK_STACK_STATUS
		g_nic_cache_stat[mtcp->ctx->cpu].numIOs_now++;
		g_nic_cache_stat[mtcp->ctx->cpu].totalLatency_now += (get_cur_us() - frr->us_submitted);
		g_nic_cache_stat[mtcp->ctx->cpu].numReadBytes_now += frd_cqe->res;
		g_nic_cache_stat[mtcp->ctx->cpu].numIOPendings_now += (numIOPending - 1);
#endif

		file_buffer *fb = frr->frr_fb;
#if ENABLE_FLEX_BUFFER
		ret = flex_buffer_attach_with_lock(mtcp, frr->frr_stream, FILE_BUFFER, fb, frr->frr_toRead);
		if (ret < 0) {
			TRACE_ERROR("Increase # of flex buffer\n");
			exit(EXIT_FAILURE);
		}
		buf->total_buf_size += frr->frr_toRead;
#else /* !ENABLE_FLEX_BUFFER */
		SBUF_LOCK(&frr->frr_stream->sndvar->write_lock);
		fb->data_len = frr->frr_toRead;
		fb->head_seq = buf->head_seq + buf->total_buf_size;
		fb->already_sent = 0;
		buf->fb_ptr[0] = fb;
		buf->num_fb = 1;
		buf->tail_off += frr->frr_toRead;
		//buf->len += frr->frr_toRead;
		buf->cum_len += frr->frr_toRead;
#if ENABLE_NIC_CACHE
		buf->total_buf_size += frr->frr_toRead;
#endif /* ENABLE_NIC_CACHE */
		SBUF_UNLOCK(&frr->frr_stream->sndvar->write_lock);
#endif /* ENABLE_FLEX_BUFFER */

#if SANITY_CHECK
		__do_sanity_check(frr->frr_fd, buf->fb_ptr[0]->data, frr->frr_toRead);
#endif
		if (!(frr->frr_stream->sndvar->on_sendq || frr->frr_stream->sndvar->on_send_list)) {
			SQ_LOCK(&mtcp->ctx->sendq_lock);
			frr->frr_stream->sndvar->on_sendq = TRUE;
			StreamEnqueue(mtcp->sendq, frr->frr_stream);
			SQ_UNLOCK(&mtcp->ctx->sendq_lock);
			mtcp->wakeup_flag = TRUE;
		}

#if FRD_RATE_LIMIT_DBG_STATUS
		frd_rate_limit_incr_read_length(mtcp, frr->frr_fd);
		frd_rate_limit_add_latency(mtcp, frr->frr_fd, get_cur_us() - frr->us_submitted);
		frd_rate_limit_incr_numIOs(mtcp, frr->frr_fd);
		frd_rate_limit_decr_numIOPendings(mtcp, frr->frr_fd);
#endif
		close(frr->frr_fd);
		MPFreeChunk(fw->frr_iov_mp, frr->frr_iov);
		MPFreeChunk(fw->frd_mp, frr);

		io_uring_cqe_seen(fw->frd_io_uring, frd_cqe);
		rte_atomic32_dec(&fw->frd_io_pending);
		trace_frd_liburing("frd_io_pending : %u\n", fw->frd_io_pending.cnt);
		//__atomic_sub_fetch(&frd_worker->frd_io_pending, 1, __ATOMIC_RELAXED);
		numProc++;
	}
}

void
frd_global_destroy(void) {
	free(g_dummy_buf);
}
