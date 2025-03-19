#ifndef __LIB_URING_H__
#define __LIB_URING_H__

#include "tcp_stream.h"
#include "mtcp.h"

#include <stdint.h>

#define KERNEL_POLL_MODE FALSE
#define QUEUE_DEPTH					(4 * 1024)
#define FRD_LIBURING_MAX_IOPENDINGS 256

#if KERNEL_POLL_MODE
#define NO_WORKER_THREAD FALSE
#else
#define NO_WORKER_THREAD FALSE
#endif

#if NO_WORKER_THREAD
#define FRD_LIBURING_ENABLE_QUEUE_DEPTH_COORDINATION TRUE
#endif

#if KERNEL_POLL_MODE
#define ENABLE_CPU_SHARING_WITH_MTCP FALSE
#define ENABLE_DEDICATED_SHARED_CPU_FOR_SQ_POLL_THREAD TRUE
#define SQ_THREAD_IDLE_TIME 1
#endif
//#define NO_WORKER_THREAD TRUE

#if 0
void
frd_global_init(uint32_t maxQueueDepth);

void
frd_create_worker(mtcp_manager_t mtcp);

void
frd_destroy_worker(mtcp_manager_t mtcp);

int
frd_issue_request(mtcp_manager_t mtcp, int fr_fd, tcp_stream *cur_stream);

void
frd_process_response(mtcp_manager_t mtcp);

void
frd_global_destroy(void);
#endif

#endif
