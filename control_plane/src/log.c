#include <stdio.h>

#include "debug.h"
#include "log.h"

#define LOG_FILE_NAME "log/control_plane.log"

struct log_buf {
	uint8_t buf[LOG_BUF_SIZE];
	size_t sz;
	size_t len;
};

static struct log_buf g_buf[2];
static uint8_t g_idx_cur = 0;
static uint8_t g_idx_prev = 1;
static FILE *g_log_fp = NULL;
static pthread_mutex_t mutex_log = PTHREAD_MUTEX_INITIALIZER;
static bool run_flush_thread = true;

static uint16_t g_nb_tasks = 0;
static pthread_mutex_t mutex_flush = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_flush = PTHREAD_COND_INITIALIZER;

#if DBG_RTT
#define MAX_RTT_SIZE 4096
struct pkt_rtt {
	/* us */
	FILE *fp_o_rtt;
	FILE *fp_e_rtt;
	FILE *fp_o_time;
	uint64_t o_rtt[MAX_RTT_SIZE];
	uint16_t o_rtt_idx;
	uint64_t e_rtt[MAX_RTT_SIZE];
	uint16_t e_rtt_idx;
	uint64_t o_time[MAX_RTT_SIZE];
	uint16_t o_time_idx;
	uint64_t us_prev_flush;
};

static struct pkt_rtt g_prtt;
#endif

static void *
FlushToFileThread(void *opaque) {

	struct timespec ts_now;
	int ret;

	while(run_flush_thread) {
		off_t b_off = 0;
		size_t toWrite;
		struct log_buf *pbuf;
		pthread_mutex_lock(&mutex_flush);
		clock_gettime(CLOCK_REALTIME, &ts_now);
		ts_now.tv_sec += FLUSH_PERIOD;

		if (g_nb_tasks <= 0)
			pthread_cond_timedwait(&cond_flush, &mutex_flush, &ts_now);

		ret = pthread_mutex_trylock(&mutex_log);
		if (ret < 0 && errno == EBUSY)
			continue;

		pbuf = &g_buf[g_idx_cur];
		toWrite = pbuf->len;

		while (toWrite > 0) {
			ret = fwrite(pbuf->buf + b_off, 1, pbuf->len - b_off, g_log_fp);
			toWrite -= ret;
			b_off += ret;
		}

		if (pbuf->len > 0)
			fflush(g_log_fp);

		pbuf->len = 0;

		pthread_mutex_unlock(&mutex_log);
		if (g_nb_tasks > 0)	
			g_nb_tasks--;

		pthread_mutex_unlock(&mutex_flush);
	}

	return NULL;
}

static void
SignalToThread(void) {
	pthread_mutex_lock(&mutex_flush);
	g_nb_tasks++;
	pthread_cond_signal(&cond_flush);
	pthread_mutex_unlock(&mutex_flush);
}

void
log_setup(void) {
	int ret, i;
	pthread_t flush_thread;
	g_log_fp = fopen(LOG_FILE_NAME, "w");
	if (!g_log_fp) {
		LOG_ERROR("Fail to open %s for control plane logging\n", LOG_FILE_NAME);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < 2; i++) {
		g_buf[i].len = 0;
		g_buf[i].sz = LOG_BUF_SIZE;
	}

	ret = pthread_create(&flush_thread, NULL, FlushToFileThread, NULL);
	if (ret != 0) {
		LOG_ERROR("Fail to create thread for FlushToFileThread");
		exit(EXIT_FAILURE);
	}
#if DBG_RTT
#define O_RTT_FN "log/o_rtt.csv"
#define E_RTT_FN "log/e_rtt.csv"
#define O_TIME_FN "log/o_time.csv"
	g_prtt.fp_o_rtt = fopen(O_RTT_FN, "w");
	if (!g_prtt.fp_o_rtt) {
		LOG_ERROR("Fail to open %s\n", O_RTT_FN);
		exit(EXIT_FAILURE);
	}

	g_prtt.fp_e_rtt = fopen(E_RTT_FN, "w");
	if (!g_prtt.fp_e_rtt) {
		LOG_ERROR("Fail to open %s\n", E_RTT_FN);
		exit(EXIT_FAILURE);
	}

	g_prtt.fp_o_time = fopen(O_TIME_FN, "w");
	if (!g_prtt.fp_o_time) {
		LOG_ERROR("Fail to open %s\n", O_TIME_FN);
		exit(EXIT_FAILURE);
	}
	g_prtt.o_rtt_idx = -1;
	g_prtt.e_rtt_idx = -1;
	g_prtt.o_time_idx = -1;

	GET_CUR_US(g_prtt.us_prev_flush);
#endif
}

void
log_write(char *log, size_t log_len) {

	uint8_t temp;
	struct log_buf *pbuf;

	pthread_mutex_lock(&mutex_log);
	pbuf = &g_buf[g_idx_cur];

	if (pbuf->sz - pbuf->len < log_len) {
		temp = g_idx_prev;
		g_idx_prev = (g_idx_cur + 1) % 2;
		g_idx_cur = (temp + 1) % 2;

		SignalToThread();

		pbuf = &g_buf[g_idx_cur];
		memcpy(pbuf->buf + pbuf->len, log, log_len);
	} 

	memcpy(pbuf->buf + pbuf->len, log, log_len);
	pbuf->len += log_len;

	pthread_mutex_unlock(&mutex_log);
}

inline static void 
FlushPktRtt(void) {
#if DBG_RTT
	int i;

	for (i = 0; i <= g_prtt.o_rtt_idx; i++)
		fprintf(g_prtt.fp_o_rtt, "%lu,", g_prtt.o_rtt[i]);
	g_prtt.o_rtt_idx = -1;

	for (i = 0; i <= g_prtt.e_rtt_idx; i++)
		fprintf(g_prtt.fp_e_rtt, "%lu,", g_prtt.e_rtt[i]);
	g_prtt.e_rtt_idx = -1;

	for (i = 0; i <= g_prtt.o_time_idx; i++)
		fprintf(g_prtt.fp_o_time, "%lu,", g_prtt.o_time[i]);
	g_prtt.o_time_idx = -1;
	
	GET_CUR_US(g_prtt.us_prev_flush);
#endif
}

void
log_pkt_rtt(uint64_t o_rtt, uint64_t e_rtt, uint64_t o_time) {
#if DBG_RTT
	uint64_t us_now;

	GET_CUR_US(us_now);

	if (USEC_TO_SEC(g_prtt.us_prev_flush - us_now) > 3 && 
			!o_rtt && !e_rtt && !o_time) {
		FlushPktRtt();
		return;
	}

	if (o_rtt > 0) {
		if (g_prtt.o_rtt_idx == MAX_RTT_SIZE - 1)
			FlushPktRtt();
		g_prtt.o_rtt[++g_prtt.o_rtt_idx] = o_rtt;
	} else if (e_rtt > 0) {
		if (g_prtt.e_rtt_idx == MAX_RTT_SIZE - 1)
			FlushPktRtt();
		g_prtt.e_rtt[++g_prtt.e_rtt_idx] = e_rtt;
	} else {
		if (g_prtt.o_time_idx == MAX_RTT_SIZE - 1)
			FlushPktRtt();
		g_prtt.o_time[++g_prtt.o_time_idx] = o_time;
	}
#endif
}

void
log_teardown(void) {
	run_flush_thread = false;

#if DBG_RTT
	fclose(g_prtt.fp_o_rtt);
	fclose(g_prtt.fp_e_rtt);
	fclose(g_prtt.fp_o_time);
#endif
}
