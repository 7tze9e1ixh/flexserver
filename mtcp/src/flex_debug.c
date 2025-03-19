#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>

#include "flex_debug.h"
#include "mtcp.h"
#include "util.h"

//#define FLEX_LOG_BUFFER_SIZE (8 * 1024 * 1024)
#define NUM_BUFFERS 32
#define FLEX_LOG_BUFFER_SIZE (32 * 1024 * 1024)

//#if DUMP_FLEX_LOG
struct flex_log_buffer {
	int32_t fildes;
	int32_t consumer_fd;
	int32_t producer_fd;
	uint64_t timestamp;
	char buf[NUM_BUFFERS][FLEX_LOG_BUFFER_SIZE];
	uint16_t index;
	uint64_t length;
	pthread_spinlock_t sl;
};

struct flex_log_toFlush {
	char *buf;
	uint64_t length;
};

static struct flex_log_buffer *g_log_buffer = NULL;


static void *
__flush_log(void *arg) {

	ssize_t numWrites, numReads;
	struct flex_log_toFlush toFlush;
	int32_t sock_fd = g_log_buffer->consumer_fd;

	while (1) {
		numReads = read(sock_fd, &toFlush, sizeof(struct flex_log_toFlush));
		if (numReads <= 0) {
			perror("read()");
			exit(EXIT_FAILURE);
		} 

		numWrites = write(g_log_buffer->fildes, toFlush.buf, toFlush.length);
		if (numWrites < 0) {
			perror("write()");
			exit(EXIT_FAILURE);
		}
	}

	return NULL;
}

void
flex_log_buf_setup(void) {

	int sv[2];
	int ret;
	pthread_t flushThread;

	g_log_buffer = calloc(1, sizeof(struct flex_log_buffer));
	if (!g_log_buffer) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}
	g_log_buffer->fildes = open("flex_log.txt", O_WRONLY | O_CREAT | O_SYNC);
	if (g_log_buffer->fildes < 0) {
		perror("open()");
		exit(EXIT_FAILURE);
	}

	g_log_buffer->timestamp = get_cur_us();

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		perror("socketpair()");
		exit(EXIT_FAILURE);
	}

	g_log_buffer->producer_fd = sv[0];
	g_log_buffer->consumer_fd = sv[1];

	ret = pthread_create(&flushThread, NULL, __flush_log, NULL);
	if (ret != 0) {
		perror("pthread_create()");
		exit(EXIT_FAILURE);
	}

	pthread_spin_init(&g_log_buffer->sl, PTHREAD_PROCESS_PRIVATE);
}

void 
flex_log_buf_destroy(void) {
	close(g_log_buffer->fildes);
	close(g_log_buffer->producer_fd);
	close(g_log_buffer->consumer_fd);
	free(g_log_buffer);
}

void 
flex_dump_log(char *log, ...) {

	va_list ap;
	size_t length;
	uint64_t us_cur;

	us_cur = get_cur_us();

	pthread_spin_lock(&g_log_buffer->sl);
	length = strlen(log);
	if (length + g_log_buffer->length > FLEX_LOG_BUFFER_SIZE) {
		ssize_t numWrites;
		struct flex_log_toFlush toFlush;

		toFlush.buf = g_log_buffer->buf[g_log_buffer->index];
		toFlush.length = g_log_buffer->length;

		numWrites = write(g_log_buffer->producer_fd, &toFlush, sizeof(struct flex_log_toFlush));
		if (numWrites <= 0) {
			perror("write()");
			exit(EXIT_FAILURE);
		}

		g_log_buffer->index = (g_log_buffer->index + 1) % NUM_BUFFERS;
		g_log_buffer->length = 0;
		g_log_buffer->timestamp = us_cur;
	}

	va_start(ap, log);
	vsprintf(g_log_buffer->buf[g_log_buffer->index] + 
			g_log_buffer->length, log, ap);
	va_end(ap);

	g_log_buffer->length += length;

	pthread_spin_unlock(&g_log_buffer->sl);
}

//#endif /* DUMP_FLEX_LOG */
