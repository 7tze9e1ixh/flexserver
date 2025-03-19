#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <errno.h>

#include "util.h"
#include "mtcp.h"
#include "frd_rate_limit.h"
#include "debug.h"

struct frd_rate_limit *g_frd_rate_limit[MAX_CPUS];

#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT
static _Atomic uint32_t g_numIOPendings[FRD_RATE_LIMIT_NUM_NVMES] = {0};

const static char *g_nvme_mounted_path[FRD_RATE_LIMIT_NUM_NVMES] = {
	"/srv/nvme0",
	"/srv/nvme1",
	"/srv/nvme2",
	"/srv/nvme3",
};

static dev_t g_nvme_dev_id[FRD_RATE_LIMIT_NUM_NVMES];

inline static int32_t
__get_nvme_id(dev_t dev_id) {
	int i;

	for (i = 0; i < FRD_RATE_LIMIT_NUM_NVMES; i++) {
		if (g_nvme_dev_id[i] == dev_id)
			return i;
	}
	return 0;
}
#endif

#if FRD_RATE_LIMIT_DBG_STATUS

#define FRD_RATE_LIMIT_DBG_STATUS_POLL_MODE 0
#define PRINT_NVME_THROUGHPUT_PERIOD 1.0 // ms

#define FRD_RATE_LIMIT_TO_GBPS(B) (double)(((B) << 3) * 1e+3 / \
		PRINT_NVME_THROUGHPUT_PERIOD / (1e9))


static void *
__print_nvme_status(void *arg) {

	int32_t i, j;
	uint64_t us_flush;
	FILE *fp_nvme_stat;
#if !FRD_RATE_LIMIT_DBG_STATUS_POLL_MODE
	struct timespec ts_now;
	static pthread_mutex_t ns_mutex = PTHREAD_MUTEX_INITIALIZER;
	static pthread_cond_t ns_cond = PTHREAD_COND_INITIALIZER;
#endif

	fp_nvme_stat = fopen("log/nvme_stat.csv", "w");
	if (!fp_nvme_stat) {
		perror("fopen()");
		exit(EXIT_FAILURE);
	}

	us_flush = get_cur_us();

	set_thread_core_affinity(10);

	/* Wait for other thread setup */
	while (1) {
		int cnt = 0;
		for (i = 0; i < CONFIG.num_cores; i++) {
			if (g_frd_rate_limit[i]) 
				cnt++;
		}

		if (cnt == CONFIG.num_cores)
			break;
	}

#if FRD_RATE_LIMIT_DBG_STATUS_POLL_MODE
	uint64_t us_next = get_cur_us() + PRINT_NVME_THROUGHPUT_PERIOD * 1e+3;
#endif

	while(1) {
		uint64_t us_now;
#if !FRD_RATE_LIMIT_DBG_STATUS_POLL_MODE
		pthread_mutex_lock(&ns_mutex);
		clock_gettime(CLOCK_REALTIME, &ts_now);
		ts_now.tv_nsec += PRINT_NVME_THROUGHPUT_PERIOD * 1e+6;
		pthread_cond_timedwait(&ns_cond, &ns_mutex, &ts_now);
#endif
		us_now = get_cur_us();

#if FRD_RATE_LIMIT_DBG_STATUS_POLL_MODE
		if (us_now >= us_next) 
			us_next = us_now + PRINT_NVME_THROUGHPUT_PERIOD * 1e+3;
		 else 
			continue;
#endif
		 uint64_t totalReqsBytes = 0;
		 uint64_t sumTxBytes = 0;
		 uint64_t sumLatency[FRD_RATE_LIMIT_NUM_NVMES] = {0},
				  sumReadBytes[FRD_RATE_LIMIT_NUM_NVMES] = {0},
				  sum_numIOs[FRD_RATE_LIMIT_NUM_NVMES] = {0},
				  sum_numIOPendings[FRD_RATE_LIMIT_NUM_NVMES] = {0},
				  sum_numReqBytes[FRD_RATE_LIMIT_NUM_NVMES] = {0};
		 struct frd_rate_limit_nvme_stat *ns;

		 for (j = 0; j < CONFIG.num_cores; j++) {
			 ns = &g_frd_rate_limit[j]->nvme_stat;
			 sumTxBytes += (ns->numTxBytes_now - ns->numTxBytes_prev);
			 ns->numTxBytes_prev = ns->numTxBytes_now;
		 }

		 for (i = 0; i < FRD_RATE_LIMIT_NUM_NVMES; i++) {
			 for (j = 0; j < CONFIG.num_cores; j++) {
				 ns = &g_frd_rate_limit[j]->nvme_stat;

				 sumReadBytes[i] += (ns->numBytes_now[i] - ns->numBytes_prev[i]);
				 ns->numBytes_prev[i] = ns->numBytes_now[i];

				 sumLatency[i] += (ns->sumTotLatency_now[i] - ns->sumTotLatency_prev[i]);
				 ns->sumTotLatency_prev[i] = ns->sumTotLatency_now[i];

				 sum_numIOs[i] += (ns->numIOs_now[i] - ns->numIOs_prev[i]);
				 ns->numIOs_now[i] = ns->numIOs_prev[i];

				 sum_numReqBytes[i] += (ns->numReqsBytes_now[i] - ns->numReqsBytes_prev[i]);
				 ns->numReqsBytes_prev[i] = ns->numReqsBytes_now[i];

				 sum_numIOPendings[i] = ns->numIOPendings[i];
			 }
		 }

		 for (i = 0; i < FRD_RATE_LIMIT_NUM_NVMES; i++) 
			 fprintf(fp_nvme_stat, "%8.2lf,", FRD_RATE_LIMIT_TO_GBPS(sumReadBytes[i]));

		 for (i = 0; i < FRD_RATE_LIMIT_NUM_NVMES; i++)
			 fprintf(fp_nvme_stat, "%8.2lf,", (double)sumLatency[i] / sum_numIOs[i]);

		 for (i = 0; i < FRD_RATE_LIMIT_NUM_NVMES; i++) 
			 fprintf(fp_nvme_stat, "%8lu,", sum_numIOPendings[i]);

		 for (i = 0; i < FRD_RATE_LIMIT_NUM_NVMES; i++)
			 totalReqsBytes += sum_numReqBytes[i];

		 for (i = 0; i < FRD_RATE_LIMIT_NUM_NVMES; i++) 
			 fprintf(fp_nvme_stat, "%8.2lf,", 
					 sum_numReqBytes[i] == 0.0 ? 
					 0.0 :
					 (double)sum_numReqBytes[i] / totalReqsBytes);

		 for (i = 0; i < FRD_RATE_LIMIT_NUM_NVMES; i++)
			 fprintf(fp_nvme_stat, "%8.2lf,", FRD_RATE_LIMIT_TO_GBPS(sum_numReqBytes[i]));


		 fprintf(fp_nvme_stat, "%8.2lf\n", FRD_RATE_LIMIT_TO_GBPS(sumTxBytes));

		if (us_flush - us_now >= 1e+6) {
			us_flush = us_now;
			fflush(fp_nvme_stat);
		}
#if !FRD_RATE_LIMIT_DBG_STATUS_POLL_MODE
		pthread_mutex_unlock(&ns_mutex);
#endif
	}
	fclose(fp_nvme_stat);
#if !FRD_RATE_LIMIT_DBG_STATUS_POLL_MODE
	pthread_mutex_destroy(&ns_mutex);
	pthread_cond_destroy(&ns_cond);
#endif

}

inline static void
__add_or_substract(mtcp_manager_t mtcp, int32_t fd, int flag, uint64_t value) {

	int32_t ret, id;
	struct stat open_file_stat;
	struct frd_rate_limit *frl = g_frd_rate_limit[mtcp->ctx->cpu];

	ret = fstat(fd, &open_file_stat);
	if (ret < 0) {
		TRACE_ERROR("fstat(), %s, flag=%d\n", strerror(errno), flag);
		exit(EXIT_FAILURE);
	}

	id = __get_nvme_id(open_file_stat.st_dev);

	if (flag == 0) { 
		frl->nvme_stat.numBytes_now[id] += open_file_stat.st_size;
	} else if (flag == 2) {
		frl->nvme_stat.numReqsBytes_now[id] += open_file_stat.st_size;
	} else if (flag == 3) {
		frl->nvme_stat.numIOPendings[id]++;
	} else if (flag == 4) {
		if (frl->nvme_stat.numIOPendings[id] > 0)
			frl->nvme_stat.numIOPendings[id]--;
	} else if (flag == 5) {
		frl->nvme_stat.sumTotLatency_now[id] += value;
	} else if (flag == 6) {
		frl->nvme_stat.numIOs_now[id]++;
	}
}

inline void
frd_rate_limit_incr_tx_bytes(mtcp_manager_t mtcp, uint32_t numBytes) {
	struct frd_rate_limit *frl = g_frd_rate_limit[mtcp->ctx->cpu];
	frl->nvme_stat.numTxBytes_now += numBytes;
}

inline void
frd_rate_limit_incr_read_length(mtcp_manager_t mtcp, int32_t fd) {
	__add_or_substract(mtcp, fd, 0, 0);
}

inline void
frd_rate_limit_incr_reqs(mtcp_manager_t mtcp, int32_t fd) {
	__add_or_substract(mtcp, fd, 1, 0);
}

inline void
frd_rate_limit_add_latency(mtcp_manager_t mtcp, int32_t fd, uint64_t latency) {
	__add_or_substract(mtcp, fd, 5, latency);
}

inline void
frd_rate_limit_incr_numIOs(mtcp_manager_t mtcp, int32_t fd) {
	__add_or_substract(mtcp, fd, 6, 0);
}

inline void
frd_rate_limit_incr_numIOPendings(mtcp_manager_t mtcp, int fd) {
	__add_or_substract(mtcp, fd, 3, 0);
}

inline void
frd_rate_limit_decr_numIOPendings(mtcp_manager_t mtcp, int fd) {
	__add_or_substract(mtcp, fd, 4, 0);
}

inline void
frd_rate_limit_add_num_req_bytes(mtcp_manager_t mtcp, int32_t fd) {
	__add_or_substract(mtcp, fd, 2, 0);
}

#endif /* FRD_RATE_LIMIT_DBG_STATUS */

void
frd_rate_limit_setup(mtcp_manager_t mtcp) {
#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT
	struct frd_rate_limit *frl;
	int i, ret;

	frl = calloc(1, sizeof(struct frd_rate_limit));
	if (!frl) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < FRD_RATE_LIMIT_NUM_NVMES; i++) {
		struct stat nvme_stat;
		ret = stat(g_nvme_mounted_path[i], &nvme_stat);
		if (ret < 0) {
			perror("stat()");
			exit(EXIT_FAILURE);
		}
		g_nvme_dev_id[i] = nvme_stat.st_dev;
	}

	g_frd_rate_limit[mtcp->ctx->cpu] = frl;

#if FRD_RATE_LIMIT_DBG_STATUS
	pthread_t tid;
	if (mtcp->ctx->cpu == 0) {
		ret = pthread_create(&tid, NULL, __print_nvme_status, NULL);
		if (ret != 0) {
			perror("pthread_create()");
			exit(EXIT_FAILURE);
		}
	}
#endif /* FRD_RATE_LIMIT_DBG_STATUS */
#endif /* FRD_RATE_LIMIT_ENABLE_RATE_LIMIT */
}

#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT
inline bool
frd_rate_limit_can_submit_now(mtcp_manager_t mtcp, uint32_t id) {

	uint32_t ret;
	uint32_t val = 1;

	ret = __atomic_add_fetch(&g_numIOPendings[id], val, __ATOMIC_RELAXED);
	if (ret > FRD_RATE_LIMIT_MAX_IO_PENDINGS) {
		__atomic_sub_fetch(&g_numIOPendings[id], val, __ATOMIC_RELAXED);
		return false;
	}

	return true;
}

inline void
frd_rate_limit_end(mtcp_manager_t mtcp, uint32_t id) {

	uint32_t val = 1;
	__atomic_sub_fetch(&g_numIOPendings[id], val, __ATOMIC_RELAXED);
	assert((int64_t)g_numIOPendings[id] < 0);
}

inline uint32_t 
frd_rate_limit_get_nvme_id(mtcp_manager_t mtcp, int fd) {

	int ret;
	struct stat fs;

	ret = fstat(fd, &fs);
	if (ret < 0) {
		TRACE_ERROR("fstat(), %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	return __get_nvme_id(fs.st_dev);
}
#endif /* FRD_RATE_LIMIT_ENABLE_RATE_LIMIT */

void
frd_rate_limit_destroy(mtcp_manager_t mtcp) {
#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT
	struct frd_rate_limit *frl = g_frd_rate_limit[mtcp->ctx->cpu];
	free(frl);
#endif
}
