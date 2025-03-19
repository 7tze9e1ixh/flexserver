#include <string.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_mempool.h>
#include <rte_errno.h>

#include "meta_send_buffer.h"

#define NAME_BUF_SIZE 256

meta_send_buffer_pool *
meta_send_buffer_pool_create(const size_t threshold, const int cpu)
{
	ssize_t sz;
	char nm_buf[NAME_BUF_SIZE];
	meta_send_buffer_pool *msbp;
	msbp = calloc(1, sizeof(meta_send_buffer_pool));
	if (!msbp) {
		RTE_LOG(ERR, USER1, "Memroy allocation error "
				"errno:%d\n", errno);
		exit(EXIT_FAILURE);
	}

	sprintf(nm_buf, "CPU%d %s", cpu, "Meta-Send-Buffer");

	sz = RTE_ALIGN_CEIL(sizeof(meta_send_buffer), RTE_CACHE_LINE_SIZE);
	msbp->msbmp = rte_mempool_create(nm_buf, threshold, sz, 0, 0, NULL,
			0, NULL, 0, rte_socket_id(),
			MEMPOOL_F_NO_SPREAD);

	if (!msbp->msbmp) {
		RTE_LOG(ERR, USER1, "Memroy allocation error "
				"errno:%d\n", errno);
		exit(EXIT_FAILURE);
	}

	return msbp;
}

meta_send_buffer *
meta_send_buffer_get(meta_send_buffer_pool *msbp)
{
	meta_send_buffer *msb;
	int rc;

	rc = rte_mempool_get(msbp->msbmp, (void **)&msb);
	if (rc != 0) {
		RTE_LOG(ERR, USER1, "Fail to get meta buffer\n");
		return NULL;
	}
	msbp->nb_objs--;

	return msb;
}

void
meta_send_buffer_free(meta_send_buffer_pool *msbp, meta_send_buffer *msb)
{
	msbp->nb_objs++;
	rte_mempool_put(msbp->msbmp, msb);

}

void
meta_send_buffer_pool_destroy(meta_send_buffer_pool *msbp)
{
	rte_mempool_free(msbp->msbmp);
}
