#ifndef __FRD_LIBURING_POLL_MODE_H__
#define __FRD_LIBURING_POLL_MODE_H__

#include <liburing.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/uio.h>
#include <pthread.h>
#include <stdio.h>

#include <rte_atomic.h>
#include <rte_common.h>

#include "debug.h"
#include "frd_liburing.h"
#include "memory_mgt.h"
#include "util.h"
#include "file_buffer.h"

#define DUMMPY_BUFFER_SIZE (8*1024*1024)
#define SHOW_FRD_STATS FALSE
#define MAX_ENTRIES 32768
#define MAX_IOV 256
#define MAX_IOV_LEN FILE_BUFFER_SIZE
#define DBG_FRD_LIBURING FALSE
#define FRR_BATCH_SIZE 4096
#define FRR_THRESH 16
#define FRD_WORKER_TIMEOUT 100 // us

#define SUBMIT_THREAD_CPU 9
#define KERNEL_POLLING_THREAD_CPU 10

#if DBG_FRD_LIBURING
#define trace_frd_liburing(f, ...) fprintf(stderr, "(%10s:%4d) " f, \
		__func__, __LINE__, ##__VA_ARGS__)
#else
#define trace_frd_liburing(f, ...) (void)0
#endif

typedef struct frd_request {
	tcp_stream *frr_stream;
	mtcp_manager_t frr_mtcp;
	uint32_t frr_toRead;
	int frr_fd;
	file_buffer *frr_fb;
	struct iovec *frr_iov;
#if SANITIY_CHECK
	char *data;
#endif
#if SHOW_FRD_STATS
	uint64_t timestamp;
#endif
	TAILQ_ENTRY(frd_request) frr_link;
} frd_request;

typedef struct frd_worker {
	pthread_t frd_tid;
	uint16_t num_cores;
	struct io_uring *frd_io_uring;
	rte_atomic32_t frd_io_pending;

	mem_pool_t frr_mp[MAX_CPUS];
	mem_pool_t frr_iov_mp[MAX_CPUS];
	TAILQ_HEAD(, frd_request) frr_q[MAX_CPUS];
	uint16_t frr_q_sz[MAX_CPUS];
	file_buffer_pool *frd_fbp[MAX_CPUS];
	pthread_mutex_t frr_mtx[MAX_CPUS];
	pthread_cond_t frr_cnd[MAX_CPUS];
	pthread_spinlock_t frr_sl[MAX_CPUS];
	uint64_t timestamp[MAX_CPUS];
	bool run;
#if SHOW_FRD_STATS
	uint64_t numIOReqs;
	uint64_t numIOReqs_prev;
	uint64_t numPerCoreIO[MAX_CPUS];
	uint64_t sumLatency;
#endif
} frd_worker;

static frd_worker *g_frd_worker = NULL;
static unsigned char *g_dummy_buf = NULL;

inline static int
__prep_read(frd_worker *fw, frd_request *frr, unsigned char *data, uint32_t toRead) {
	struct io_uring_sqe *sqe;
	int i, ret;
	int numChunks = toRead % MAX_IOV_LEN ?
			toRead / MAX_IOV_LEN + 1 :
			toRead / MAX_IOV_LEN;
	uint32_t iov_len;
	file_buffer *fb;

#if SHOW_FRD_STATS
	fw->numIOReqs++;
#endif
	assert(numChunks <= MAX_IOV);
	fb = fb_alloc(fw->frd_fbp[frr->frr_mtcp->ctx->cpu]);

	for (i = 0; i < numChunks; i++) {
		iov_len = RTE_MIN(toRead, MAX_IOV_LEN);
		sqe = io_uring_get_sqe(fw->frd_io_uring);
		if (!sqe) {
				TRACE_ERROR("io_uring_get_sqe(), no entries \n");
				exit(EXIT_FAILURE);
		}

		frr->frr_iov[i].iov_base = fb->data + i * MAX_IOV_LEN;
		frr->frr_iov[i].iov_len = MAX_IOV_LEN;
		frr->frr_fb = fb;
#if SHOW_FRD_STATS
		frr->timestamp = get_cur_us();
#endif

#if USE_LIBURING_FIXED_BUFFER
		if (fb->is_fixed) {
			io_uring_prep_read_fixed(sqe, frr->frr_fd, fb->data, MAX_IOV_LEN, 0, fb->id);
		} else {
			io_uring_prep_readv(sqe, frr->frr_fd, &frr->frr_iov[i], 1, i * MAX_IOV_LEN);
		}
#else
		io_uring_prep_readv(sqe, frr->frr_fd, &frr->frr_iov[i], 1, i * MAX_IOV_LEN);
#endif
		io_uring_sqe_set_data(sqe, frr);

		trace_frd_liburing("sqe:%p, frr:%p, iov:%p, stream:%p, "
						"iov_base:%p, iov_len=%lu\n",
						sqe, frr, &frr->frr_iov[i],
						frr->frr_stream, frr->frr_iov[i].iov_base, frr->frr_iov[i].iov_len);

		toRead -= iov_len;
	}

        return numChunks;
}

inline static void
__proc_cqe(frd_worker *fw, struct io_uring_cqe *frd_cqe) {

        struct tcp_send_buffer *buf;
        tcp_stream *stream;
        frd_request *frr;
        uint32_t numCompl;
		uint16_t cid;
		mtcp_manager_t mtcp;
		file_buffer *fb;

        frr = io_uring_cqe_get_data(frd_cqe);
		mtcp = frr->frr_mtcp;
        stream = frr->frr_stream;
        buf = frr->frr_stream->sndvar->sndbuf;
		fb = frr->frr_fb;
		cid = mtcp->ctx->cpu;

        if (!buf) {
			close(frr->frr_fd);
			MPFreeChunk(fw->frr_iov_mp[cid], frr->frr_iov);
			MPFreeChunk(fw->frr_mp[cid], frr);
			io_uring_cqe_seen(fw->frd_io_uring, frd_cqe);
			rte_atomic32_dec(&fw->frd_io_pending);
			return;
        }

        rte_atomic32_inc(&buf->numCompletes);
        numCompl = rte_atomic32_read(&buf->numCompletes);

        trace_frd_liburing("cqe:%p, stream:%p, numCompletes:%u, frr : %p, frr_fd : %d, res:%d(%s)\n",
                        frd_cqe, frr->frr_stream, numCompl, frr, frr->frr_fd,
                        frd_cqe->res, strerror(-frd_cqe->res));

        if (numCompl < buf->numChunks) {
			io_uring_cqe_seen(fw->frd_io_uring, frd_cqe);
			rte_atomic32_dec(&fw->frd_io_pending);
			return;
        }

        SBUF_LOCK(&stream->sndvar->write_lock);
		fb->data_len = frr->frr_toRead;
		fb->head_seq = buf->head_seq + buf->total_buf_size;
		fb->already_sent = 0;
		buf->fb_ptr[0] = fb;
		buf->num_fb = 1;

        buf->tail_off += frr->frr_toRead;
        buf->cum_len += frr->frr_toRead;
#if ENABLE_NIC_CACHE
        buf->total_buf_size += frr->frr_toRead;
#endif
        SBUF_UNLOCK(&stream->sndvar->write_lock);

#if SANITY_CHECK
        __do_sanity_check(frr->frr_fd, frr->data, frr->frr_toRead);
#endif

        if (!(stream->sndvar->on_sendq || stream->sndvar->on_send_list)) {
                SQ_LOCK(&mtcp->ctx->sendq_lock);
                stream->sndvar->on_sendq = TRUE;
                StreamEnqueue(mtcp->sendq, stream);
                SQ_UNLOCK(&mtcp->ctx->sendq_lock);
                mtcp->wakeup_flag = TRUE;
        }
#if SHOW_FRD_STATS
		fw->sumLatency += (get_cur_us() - frr->timestamp);
#endif
        close(frr->frr_fd);
        MPFreeChunk(fw->frr_iov_mp[cid], frr->frr_iov);
        MPFreeChunk(fw->frr_mp[cid], frr);

        io_uring_cqe_seen(fw->frd_io_uring, frd_cqe);
        rte_atomic32_dec(&fw->frd_io_pending);
}

static void *
__worker_thread(void *opaque) {

	uint32_t numProcess, i, totalSQEs, numIOPendings;
	struct tcp_send_buffer *buf;
	struct io_uring_cqe *frd_cqe;
	uint16_t cid;
	int32_t numSQEs, ret;
	uint64_t us_now;
	frd_worker *fw;
	frd_request *frr_arr[FRR_BATCH_SIZE], *frr;

	fw = (frd_worker *)opaque;

	set_thread_core_affinity(SUBMIT_THREAD_CPU);

	while (fw->run) {
		for (cid = 0; cid < fw->num_cores; cid++) {
			//pthread_mutex_lock(&fw->frr_mtx[cid]);
#if 0
			us_now = get_cur_us();
			if ((us_now - fw->timestamp[cid] < FRD_WORKER_TIMEOUT) && 
					(fw->frr_q_sz[cid] < FRR_THRESH))
				continue;
#endif
#if SHOW_FRD_STATS
			us_now = get_cur_us();
			if (us_now - fw->timestamp[cid] >= 1000000) {
				fw->timestamp[cid] = us_now;
				fprintf(stdout, "numIOReqs/s:%6.2luus, average_latency:%6.2lfus, per_core_load:%6lu\n",
						fw->numIOReqs - fw->numIOReqs_prev,
						(double)fw->sumLatency / fw->numIOReqs,
						fw->numPerCoreIO[cid]);
				fw->numIOReqs_prev = fw->numIOReqs;
			}
#endif

			if (fw->frr_q_sz[cid] > 0) {
				pthread_spin_lock(&fw->frr_sl[cid]);
				numProcess = RTE_MIN(FRR_BATCH_SIZE, fw->frr_q_sz[cid]);
				for (i = 0; i < numProcess; i++) {
					frr = TAILQ_FIRST(&fw->frr_q[cid]);
					TAILQ_REMOVE(&fw->frr_q[cid], frr, frr_link);
					frr_arr[i] = frr;
				}
				fw->frr_q_sz[cid] -= numProcess;
				pthread_spin_unlock(&fw->frr_sl[cid]);
				trace_frd_liburing("frr_q_sz:%u\n", fw->frr_q_sz[cid]);

				numSQEs = 0;
				totalSQEs = 0;
				for (i = 0; i < numProcess; i++) {
					buf = frr_arr[i]->frr_stream->sndvar->sndbuf;
					if (!buf) {
						numSQEs = __prep_read(fw, frr_arr[i], g_dummy_buf, frr->frr_toRead);
					} else {
						numSQEs = __prep_read(fw, frr_arr[i], buf->data + buf->tail_off, frr->frr_toRead);
						buf->numChunks = numSQEs;
						rte_atomic32_init(&buf->numCompletes);
					}
					rte_atomic32_add(&fw->frd_io_pending, numSQEs);
					totalSQEs += numSQEs;
				}
#if SHOW_FRD_STATS
				fw->numPerCoreIO[cid] += totalSQEs;
#endif
				ret = io_uring_submit(fw->frd_io_uring);
				if (ret <= 0) {
					TRACE_ERROR("io_uring_submit, %s\n", strerror(-ret));
					exit(EXIT_FAILURE);
				} else if (ret != totalSQEs) {
					TRACE_ERROR("io_uring_submit submitted less %d, totalSQEs=%d\n", 
							ret, totalSQEs);
					exit(EXIT_FAILURE);
				}

				trace_frd_liburing("io_uring_submit(), ret:%d, numProcess:%u\n", ret, numProcess);
			}

			numIOPendings = rte_atomic32_read(&fw->frd_io_pending);
			for (i = 0; i < numIOPendings; i++) {
				ret = io_uring_peek_cqe(fw->frd_io_uring, &frd_cqe);
				if (ret < 0) {
					if (ret == -EAGAIN) {
						break;
					} else{
						TRACE_ERROR("io_uring_peek_cqe(), %s\n", strerror(-ret));
						exit(EXIT_FAILURE);
					}
				}

				__proc_cqe(fw, frd_cqe);
			}
		}
	}

	return NULL;
}

void 
frd_global_init(uint32_t maxQueueDepth) {
	UNUSED(maxQueueDepth);

	g_dummy_buf = malloc(DUMMPY_BUFFER_SIZE);
	if (!g_dummy_buf) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}
}

void
frd_global_destroy(void) {
	free(g_dummy_buf);
}

void
frd_create_worker(mtcp_manager_t mtcp) {

	int i;
	int ret;
	char tmpbuf[256];
	frd_worker *fw;
	struct io_uring_params frd_io_uring_params;
	if (mtcp->ctx->cpu != 0)
		return;

	fw = calloc(1, sizeof(frd_worker));
	if (!fw) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	fw->frd_io_uring = calloc(1, sizeof(struct io_uring));
	if (!fw->frd_io_uring) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}
//IORING_SETUP_IOPOLL
	bzero(&frd_io_uring_params, sizeof(struct io_uring_params));
	frd_io_uring_params.flags |= IORING_SETUP_IOPOLL;
	ret = io_uring_queue_init_params(MAX_ENTRIES, fw->frd_io_uring, &frd_io_uring_params);
	//ret = io_uring_queue_init(MAX_ENTRIES, fw->frd_io_uring, 0);
	if (ret < 0) {
		TRACE_ERROR("io_uring_queue_init_params() %s\n", strerror(ret));
		exit(EXIT_FAILURE);
	}

	rte_atomic32_init(&fw->frd_io_pending);

	fw->run = true;
	fw->num_cores = CONFIG.num_cores;

	for (i = 0; i < fw->num_cores; i++) {

		TAILQ_INIT(&fw->frr_q[i]);

		sprintf(tmpbuf, "frr_mp-%d", i);
		fw->frr_mp[i] = MPCreate(tmpbuf, sizeof(frd_request), 
				sizeof(frd_request) * (MAX_ENTRIES / fw->num_cores));
		if (!fw->frr_mp[i]) {
			TRACE_ERROR("Fail to create memory pool for frd_mp\n");
			exit(EXIT_FAILURE);
		}

		sprintf(tmpbuf, "frr_iov_mp-%d", i);
		fw->frr_iov_mp[i] = MPCreate(tmpbuf, sizeof(struct iovec) * MAX_IOV,
				sizeof(struct iovec) * MAX_IOV * MAX_ENTRIES);
		if (!fw->frr_iov_mp[i]) {
			TRACE_ERROR("Fail to create memory pool for frr_iov_mp\n");
			exit(EXIT_FAILURE);
		}

		fw->frd_fbp[i] = fb_pool_create(fw->frd_io_uring, i, 0, 
				MAX_FILE_BUFFERS / fw->num_cores);

		ret = pthread_mutex_init(&fw->frr_mtx[i], NULL);
		if (ret != 0) {
			TRACE_ERROR("pthread_mutex_init(), %s\n", strerror(ret));
			exit(EXIT_FAILURE);
		}

		ret = pthread_spin_init(&fw->frr_sl[i], PTHREAD_PROCESS_PRIVATE);
		if (ret != 0) {
			TRACE_ERROR("pthread_spin_init(), %s\n", strerror(ret));
			exit(EXIT_FAILURE);
		}

		ret = pthread_cond_init(&fw->frr_cnd[i], NULL);
		if (ret != 0) {
			TRACE_ERROR("pthread_cond_init(), %s\n", strerror(ret));
			exit(EXIT_FAILURE);
		}

	}

	ret = pthread_create(&fw->frd_tid, NULL, __worker_thread, fw);
	if (ret != 0) {
		TRACE_ERROR("Fail to create __worker_thread, %s\n", strerror(ret));
		exit(EXIT_FAILURE);
	}

	g_frd_worker = fw;
}

void
frd_destroy_worker(mtcp_manager_t mtcp) {
	uint16_t cid;
	frd_worker *fw = g_frd_worker;
	UNUSED(mtcp);
	for (cid = 0; cid < fw->num_cores; cid++) {
		pthread_mutex_destroy(&fw->frr_mtx[cid]);
		pthread_cond_destroy(&fw->frr_cnd[cid]);
		pthread_spin_destroy(&fw->frr_sl[cid]);
		MPDestroy(fw->frr_mp[cid]);
		MPDestroy(fw->frr_iov_mp[cid]);
	}

	io_uring_queue_exit(fw->frd_io_uring);
	free(fw);
}

int
frd_issue_request(mtcp_manager_t mtcp, int fr_fd, tcp_stream *cur_stream) {

	uint16_t cid = mtcp->ctx->cpu;
	struct tcp_send_buffer *buf;
	uint32_t frr_toRead;
	frd_request *frr;
	struct iovec *frr_iov;
	frd_worker *fw = g_frd_worker;

	frr_toRead = lseek(fr_fd, (off_t)0, SEEK_END);

	buf = cur_stream->sndvar->sndbuf;
	if (buf->tail_off + frr_toRead >= buf->size) {
		memmove(buf->data, buf->head, buf->len);
		buf->head = buf->data;
		buf->head_off = 0;
		buf->tail_off = buf->len;
	}

	frr = MPAllocateChunk(fw->frr_mp[cid]);
	if (!frr) {
		TRACE_ERROR("Increase max # of entries\n");
		exit(EXIT_FAILURE);
	}

	frr_iov = MPAllocateChunk(fw->frr_iov_mp[cid]);
	if (!frr_iov) {
		TRACE_ERROR("Increase max # of entries\n");
		exit(EXIT_FAILURE);
	}

	frr->frr_stream = cur_stream;
	frr->frr_mtcp = mtcp;
	frr->frr_toRead = frr_toRead;
	frr->frr_fd = fr_fd;
	frr->frr_iov = frr_iov;

	pthread_spin_lock(&fw->frr_sl[cid]);
	TAILQ_INSERT_TAIL(&fw->frr_q[cid], frr, frr_link);
	fw->frr_q_sz[cid]++;
#if 0
	if (fw->frr_q_sz[cid] >= FRR_THRESH)
		pthread_cond_signal(&fw->frr_cnd[cid]);
#endif
	pthread_spin_unlock(&fw->frr_sl[cid]);

	return frr_toRead;
}

void
frd_process_response(mtcp_manager_t mtcp) {

}


#endif
