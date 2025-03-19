#ifndef __FRD_H__
#define __FRD_H__

#include "tcp_stream.h"
#include "mtcp.h"

#include <stdint.h>

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
