#include <rte_malloc.h>
#include <unistd.h>

#include "log.h"
#include "dataplane.h"
#include "dpdk_io.h"

#define NB_FWRT (1024 * 1024)

struct log_buf {
	char *buf;
	size_t sz;
	size_t len;
	FILE *fp;
	uint16_t lcore_id;
};

static log_buf *g_lb[MAX_CPUS] = {NULL};

static void FlushLogToFile(log_buf *lb);

static void
FlushLogToFile(log_buf *lb) {

	size_t nwrt;
	off_t lb_off = 0;
	size_t to_wr = lb->len;

	do {
		nwrt = fwrite(lb->buf + lb_off, NB_FWRT, 1, lb->fp);
		to_wr -= nwrt * NB_FWRT;
		lb_off += nwrt * NB_FWRT;;
	} while (to_wr > NB_FWRT);

	if (to_wr > 0) {
		memmove(lb->buf, lb->buf + lb_off, to_wr);
	}

	lb->len = to_wr;
}

static log_buf *
log_buf_create(uint16_t lcore_id) {

	char filename[256];
	log_buf *lb;

	lb = malloc(sizeof(log_buf));
	if (!lb) {
		perror("Fail to allocate memory for log_buf.");
		return NULL;
	}

	sprintf(filename, "CPU%u.log", lcore_id);

	lb->lcore_id = lcore_id;
	lb->sz = LOG_BUF_SIZE;
	lb->len = 0;
	lb->fp = fopen(filename, "w");
	if (!lb->fp) {
		perror("Fail to open log file");
		free(lb);
		return NULL;
	}

	lb->buf = (char *)malloc(LOG_BUF_SIZE);
	if (!lb->buf) {
		perror("Fail to allocate buffer of log_buf.");
		free(lb);
		fclose(lb->fp);
		return NULL;
	}

	return lb;
}

void
log_buf_write(char *log, size_t log_len) {

	log_buf *lb = g_lb[rte_lcore_id()];
	if (lb->sz - lb->len < log_len) {
		FlushLogToFile(lb);
	}
	rte_memcpy(lb->buf + lb->len, log, log_len);
	lb->len += log_len;
}

static void
log_buf_destroy(log_buf *lb) {
	size_t nwrt, to_wr;
	off_t lb_off = 0;
	to_wr = lb->len;

	fprintf(stderr, "Desytroy logbuf, coreid=%u, to_wr=%lu\n", lb->lcore_id, to_wr);

	do {
		nwrt = fwrite(lb->buf + lb_off, 1, lb->len - lb_off, lb->fp);
		to_wr -= (lb->len - lb_off);
		lb_off += (lb->len - lb_off);
	} while (nwrt > 0);

	fclose(lb->fp);
	free(lb->buf);
	free(lb);
}

void
log_buf_global_init(uint16_t nb_cores) {
	uint16_t i;
	for (i = 0; i < nb_cores; i++) {
		g_lb[i] = log_buf_create(i);
		if (!g_lb[i]) {
			fprintf(stderr, "Fail to create log buffer\n");
			exit(EXIT_FAILURE);
		}
	}
}

void
log_buf_global_destroy(void) {
	uint16_t i;

	for (i = 0 ; i < MAX_CPUS; i++) {
		if (!g_lb[i])
			break;
		fprintf(stderr, "Destroy log buf %u\n", i);
		usleep(10);
		log_buf_destroy(g_lb[i]);
	}
}
