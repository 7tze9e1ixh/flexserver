#ifndef __ZERO_COPY_H__
#define __ZERO_COPY_H__

#include <rte_common.h>
#include <rte_mbuf.h>

#include "mtcp.h"
#include "flex_buffer.h"
#include "tcp_send_buffer.h"
/* Zero-Copy mTCP*/

void 
zero_copy_setup(void);

extern void
zero_copy_set(struct mtcp_manager *mtcp, struct rte_mbuf *m,
		 uint32_t seq, flex_buffer *flex_buf, uint16_t payloadlen);

void
zero_copy_teardown(void);

#endif /* __ZERO_COPY_H__ */
