#ifndef __FRD_ASYNC_H__
#define __FRD_ASYNC_H__

#include "tcp_stream.h"
#include "mtcp.h"

#include <stdint.h>

#define NUM_DISK 10
#define MIN_IO_EVENTS 1
#define MAX_IO_EVENTS 8
#define IO_EVENTS_THRESH (MAX_IO_EVENTS / 2)
#define IO_EVENTS_TIMEOUT 500000	// ns

void 
frd_global_init(uint32_t maxAioReqs);

void
frd_create_worker(mtcp_manager_t mtcp);

void
frd_destroy_worker(mtcp_manager_t mtcp);

int 
frd_issue_request(mtcp_manager_t mtcp, int fr_fd, tcp_stream *cur_stream);

void
frd_global_destroy(void);
#endif
