/* Use libaio*/

#include <libaio.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <rte_common.h>
//#include <sys/param.h>

#include "debug.h"
#include "frd_async.h"
#include "util.h"

#define FRD_STAT TRUE
#define DBG_FRD_ASYNC FALSE
#if DBG_FRD_ASYNC
#define TRACE_FRD_ASYNC(f, ...) fprintf(stderr, "(%10s:%4d) " f, \
		__func__, __LINE__, ##__VA_ARGS__)
#else
#define TRACE_FRD_ASYNC(f, ...) (void)0
#endif


typedef struct frd_req {
	tcp_stream *frr_stream;
	int frr_fildes;
	uint32_t frr_toRead;
	//struct iocb frr_iocb;
	TAILQ_ENTRY(frd_req) frr_qlink;
} frd_req;

typedef struct frd_worker {
	io_context_t frd_ioctx;
	mem_pool_t frd_mp;
	mtcp_manager_t mtcp;
	bool run;
	pthread_mutex_t frd_mutex;
	pthread_cond_t frd_cond;
	pthread_spinlock_t frd_sl;
	TAILQ_HEAD(, frd_req) frd_q;
	uint32_t frd_q_sz;
#if FRD_STAT
	uint64_t duration_io_submit;
	uint64_t duration_io_submit_prev;
#endif
} frd_worker;

static uint32_t g_maxAioReqs;
const static char *g_diskMountedPath[] = {
	"/dev/nvme0n1",
	"/dev/nvme1n1",
	"/dev/nvme2n1",
	"/dev/nvme3n1",
};

static int g_diskFd[NUM_DISK];
static unsigned char *g_dummp_buf;

static void *
run_worker_thread(void *opaque) {

	struct timespec ts_now;
	struct tcp_send_buffer *buf;
	struct iocb frr_iocb[MAX_IO_EVENTS];
	struct iocb *frr_iocbpp[MAX_IO_EVENTS];
	struct io_event frr_io_event[MAX_IO_EVENTS];
	int rc, i, frr_arr_size;
	frd_req *frr;
	tcp_stream *frr_stream;
	frd_worker *frd_worker = opaque;
	mtcp_manager_t mtcp = frd_worker->mtcp;
	cpu_set_t cpuset;
#if FRD_STAT
	uint64_t cur_ms, prev_ms;
	prev_ms = get_cur_ms();
#endif

	CPU_ZERO(&cpuset);
	CPU_SET(mtcp->ctx->cpu, &cpuset);
	rc = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
	if (rc < 0) {
		perror("pthread_setaffinity_np()");
		return NULL;
	}

	frd_worker->run = true;

	while (frd_worker->run) {

		pthread_mutex_lock(&frd_worker->frd_mutex);
		clock_gettime(CLOCK_REALTIME, &ts_now);
		ts_now.tv_nsec += IO_EVENTS_TIMEOUT;

		if (frd_worker->frd_q_sz < IO_EVENTS_THRESH)
			pthread_cond_timedwait(&frd_worker->frd_cond, &frd_worker->frd_mutex, &ts_now);

		pthread_mutex_unlock(&frd_worker->frd_mutex);

		pthread_spin_lock(&frd_worker->frd_sl);
		frr_arr_size = RTE_MIN(frd_worker->frd_q_sz, MAX_IO_EVENTS);

		if (frr_arr_size == 0) {
			pthread_spin_unlock(&frd_worker->frd_sl);
			continue;
		}

		TRACE_FRD_ASYNC("arr_size=%u\n", frr_arr_size);
		for (i = 0; i < frr_arr_size; i++)  {
			frr = TAILQ_FIRST(&frd_worker->frd_q);
			TAILQ_REMOVE(&frd_worker->frd_q, frr, frr_qlink);
			buf = frr->frr_stream->sndvar->sndbuf;
			if (!buf) {
				io_prep_pread(&frr_iocb[i], frr->frr_fildes, 
						g_dummp_buf, frr->frr_toRead, 0);
				frr_iocb[i].data = frr;
				frr_iocbpp[i] = &frr_iocb[i];
			} else {
				io_prep_pread(&frr_iocb[i], frr->frr_fildes, 
						buf->data + buf->tail_off, frr->frr_toRead, 0);
				frr_iocb[i].data = frr;
				frr_iocbpp[i] = &frr_iocb[i];
			}

			TRACE_FRD_ASYNC("Process frr=%p, fildes=%d\n", frr, frr->frr_fildes);
		}

		frd_worker->frd_q_sz -= frr_arr_size;
		pthread_spin_unlock(&frd_worker->frd_sl);
#if FRD_STAT
		uint64_t ms_prev, ms_now;
		ms_prev = get_cur_ms();
#endif
		rc = io_submit(frd_worker->frd_ioctx, frr_arr_size, frr_iocbpp);
		if (rc < 0) {
			TRACE_ERROR("io_submit fail, %s\n", strerror(rc));
			exit(1);
		}
#if FRD_STAT
		ms_now = get_cur_ms();
		frd_worker->duration_io_submit += (ms_now - ms_prev);
		cur_ms = get_cur_ms();
		if (cur_ms - prev_ms >= 1000) {
			prev_ms = get_cur_ms();
			fprintf(stderr, "delay : %lu\n", ms_now - ms_prev);
			frd_worker->duration_io_submit_prev = frd_worker->duration_io_submit;
		}
#endif

		rc = io_getevents(frd_worker->frd_ioctx, MIN_IO_EVENTS, MAX_IO_EVENTS, 
				frr_io_event, NULL);
		if (rc < 0 && rc != -4) {
			TRACE_ERROR("io_getevents error %d (%s)\n", rc, strerror(rc));
			exit(1);
		}

		for (i = 0; i < rc; i++) {
			frr = frr_io_event[i].data;
			if (frr_io_event[i].res2 != 0) {
				perror("aio read");
				exit(1);
			}

			if (frr_io_event[i].res != frr->frr_toRead) {
				TRACE_ERROR("read misses bytes, expect %u, got %ld\n", 
						frr->frr_toRead, frr_io_event[i].res2);
				exit(1);
			}

			frr_stream = frr->frr_stream;

			SBUF_LOCK(&frr_stream->sndvar->write_lock);
			buf = frr_stream->sndvar->sndbuf;
			if (!buf) {
				close(frr->frr_fildes);
				MPFreeChunk(frd_worker->frd_mp, frr);
				SBUF_UNLOCK(&frr_stream->sndvar->write_lock);
				continue;
			}

			buf->tail_off += frr->frr_toRead;
			buf->len += frr->frr_toRead;
			buf->cum_len += frr->frr_toRead;
#if ENABLE_NIC_CACHE
			buf->total_buf_size += frr->frr_toRead;
#endif
			if (!(frr_stream->sndvar->on_sendq || frr_stream->sndvar->on_send_list)) {
				SQ_LOCK(&mtcp->ctx->sendq_lock);
				frr_stream->sndvar->on_sendq = TRUE;
				StreamEnqueue(mtcp->sendq, frr_stream);
				SQ_UNLOCK(&mtcp->ctx->sendq_lock);
				mtcp->wakeup_flag = TRUE;
			}
			SBUF_UNLOCK(&frr_stream->sndvar->write_lock);

			TRACE_FRD_ASYNC("Complete to process %d\n", frr->frr_fildes);
			close(frr->frr_fildes);
			MPFreeChunk(frd_worker->frd_mp, frr);
		}
	}

	return NULL;
}

void
frd_global_init(uint32_t maxAioReqs) {
	int i;
	g_maxAioReqs = maxAioReqs;
	g_maxAioReqs = (1<<15);

	for (i = 0; i < NUM_DISK; i++) {
		g_diskFd[i] = open(g_diskMountedPath[i], O_RDONLY | O_DIRECT);
		if (!g_diskFd[i]) {
			TRACE_ERROR("Fail to open disk %s\n", g_diskMountedPath[i]);
			exit(EXIT_FAILURE);
		}
	}

	g_dummp_buf = malloc(1024 * 1024 * 4);
	if (!g_dummp_buf) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}
}

void
frd_global_destroy(void) {
	int i;
	for (i = 0; i < NUM_DISK; i++)
		 close(g_diskFd[i]);
}

void
frd_create_worker(mtcp_manager_t mtcp) {

	frd_worker *frd_worker;
	pthread_t worker_thread;
	char tmpbuf[256];

	frd_worker = malloc(sizeof(frd_worker));
	if (!frd_worker) {
		perror("Fail to allocate memory for frd_worker");
		exit(EXIT_FAILURE);
	}

	memset(&frd_worker->frd_ioctx, 0, sizeof(struct iocb));

	io_queue_init(g_maxAioReqs, &frd_worker->frd_ioctx);

	sprintf(tmpbuf, "frd_mp-%d", mtcp->ctx->cpu);
	frd_worker->frd_mp = MPCreate(tmpbuf, sizeof(frd_req), sizeof(frd_req) * g_maxAioReqs);
	if (!frd_worker->frd_mp) {
		fprintf(stderr, "Fail to create memory pool for frd_mp\n");
		exit(EXIT_FAILURE);
	}

	TAILQ_INIT(&frd_worker->frd_q);
	frd_worker->frd_q_sz = 0;
	pthread_spin_init(&frd_worker->frd_sl, PTHREAD_PROCESS_PRIVATE);
	pthread_mutex_init(&frd_worker->frd_mutex, NULL);
	pthread_cond_init(&frd_worker->frd_cond, NULL);

	mtcp->frd_worker = (void *)frd_worker;
	frd_worker->mtcp = mtcp;

	if (pthread_create(&worker_thread, NULL, run_worker_thread, frd_worker) != 0) {
		perror("pthread_create()");
		exit(EXIT_FAILURE);
	}
}

void
frd_destroy_worker(mtcp_manager_t mtcp) {

	frd_worker *frd_worker = mtcp->frd_worker;

	pthread_mutex_destroy(&frd_worker->frd_mutex);
	pthread_cond_destroy(&frd_worker->frd_cond);
	pthread_spin_destroy(&frd_worker->frd_sl);

	MPDestroy(frd_worker->frd_mp);

	free(frd_worker);
}

int
frd_issue_request(mtcp_manager_t mtcp, int fr_fd, tcp_stream *cur_stream) {

	struct tcp_send_buffer *buf;
	uint32_t frr_toRead;
	frd_req *frr;
	frd_worker *frd_worker = mtcp->frd_worker;

	frr_toRead = lseek(fr_fd, (off_t)0, SEEK_END);

	buf = cur_stream->sndvar->sndbuf;
	if (buf->tail_off + frr_toRead >= buf->size) {
		memmove(buf->data, buf->head, buf->len);
		buf->head = buf->data;
		buf->head_off = 0;
		buf->tail_off = buf->len;
	}

	frr = MPAllocateChunk(frd_worker->frd_mp);
	if (!frr) {
		TRACE_ERROR("Fail ao allocate frr\n");
		errno = EAGAIN;
		return -1;
	}

	frr->frr_stream = cur_stream;
	frr->frr_toRead = frr_toRead;
	frr->frr_fildes = fr_fd;

	pthread_spin_lock(&frd_worker->frd_sl);
	TAILQ_INSERT_TAIL(&frd_worker->frd_q, frr, frr_qlink);
	frd_worker->frd_q_sz++;
	if (frd_worker->frd_q_sz >= IO_EVENTS_THRESH)
		pthread_cond_signal(&frd_worker->frd_cond);

	TRACE_FRD_ASYNC("Insert file (fildes=%d, strea=%p)\n", fr_fd, cur_stream);

	pthread_spin_unlock(&frd_worker->frd_sl);

	return frr_toRead;
}
