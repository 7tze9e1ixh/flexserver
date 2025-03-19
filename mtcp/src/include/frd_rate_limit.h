#ifndef __FRD_RATE_LIMIT_H__
#define __FRD_RATE_LIMIT_H__

#include "mtcp.h"
#include <stdint.h>

#define FRD_RATE_LIMIT_DBG_STATUS 0
#define FRD_RATE_LIMIT_NUM_NVMES 10
#define FRD_RATE_LIMIT_MAX_IO_PENDINGS 64
#define FRD_RATE_LIMIT_ENABLE_RATE_LIMIT 0

struct frd_rate_limit_nvme_stat {

	uint64_t numTxBytes_now;
	uint64_t numTxBytes_prev;

	uint64_t numBytes_now[FRD_RATE_LIMIT_NUM_NVMES];
	uint64_t numBytes_prev[FRD_RATE_LIMIT_NUM_NVMES];

	uint64_t sumTotLatency_now[FRD_RATE_LIMIT_NUM_NVMES];
	uint64_t sumTotLatency_prev[FRD_RATE_LIMIT_NUM_NVMES];

	uint64_t numIOs_now[FRD_RATE_LIMIT_NUM_NVMES];
	uint64_t numIOs_prev[FRD_RATE_LIMIT_NUM_NVMES];

	uint64_t numIOPendings[FRD_RATE_LIMIT_NUM_NVMES];

	uint64_t numReqsBytes_now[FRD_RATE_LIMIT_NUM_NVMES];
	uint64_t numReqsBytes_prev[FRD_RATE_LIMIT_NUM_NVMES];

	uint64_t numSubmits_now[FRD_RATE_LIMIT_NUM_NVMES];
	uint64_t numSubmits_prev[FRD_RATE_LIMIT_NUM_NVMES];
};

struct frd_rate_limit {
#if FRD_RATE_LIMIT_DBG_STATUS
	struct frd_rate_limit_nvme_stat nvme_stat;
#endif
};

#if FRD_RATE_LIMIT_DBG_STATUS
extern void
frd_rate_limit_incr_read_length(mtcp_manager_t mtcp, int32_t fd);

extern void
frd_rate_limit_incr_tx_bytes(mtcp_manager_t mtcp, uint32_t numBytes);

extern void
frd_rate_limit_add_latency(mtcp_manager_t mtcp, int32_t fd, uint64_t latency);

extern void
frd_rate_limit_incr_numIOs(mtcp_manager_t mtcp, int fd);

extern void
frd_rate_limit_incr_numIOPendings(mtcp_manager_t mtcp, int fd);

extern void
frd_rate_limit_decr_numIOPendings(mtcp_manager_t mtcp, int fd);

extern void
frd_rate_limit_add_num_req_bytes(mtcp_manager_t mtcp, int fd);

#endif

#if FRD_RATE_LIMIT_ENABLE_RATE_LIMIT
extern bool
frd_rate_limit_can_submit_now(mtcp_manager_t mtcp, uint32_t id);

extern void
frd_rate_limit_end(mtcp_manager_t mtcp, uint32_t id);

extern uint32_t 
frd_rate_limit_get_nvme_id(mtcp_manager_t mtcp, int fd);

#endif

void
frd_rate_limit_setup(mtcp_manager_t mtcp);

void
frd_rate_limit_destroy(mtcp_manager_t mtcp);

#endif /* __FRD_RATE_LIMIT_H__ */
