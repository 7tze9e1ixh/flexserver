#include <stdlib.h>
#include <string.h>
#include "item_mp.h"
#include "debug.h"

#define NAME_BUF_SIZE (256)

item_mp *
item_mp_create(const size_t max_nitem, const int cpu)
{
	ssize_t sz;
	char nm_buf[NAME_BUF_SIZE];
	item_mp *imp;

	imp = calloc(1, sizeof(item_mp));
	if (!imp) {
		LOG_ERROR("[CPU%d] Fail to allocate memory for item_mp\n", cpu);
		exit(EXIT_FAILURE);
	}

	sprintf(nm_buf, "CPU%d %s", cpu, "it-mp");
	sz = RTE_ALIGN_CEIL(sizeof(item), RTE_CACHE_LINE_SIZE);
	imp->mp_item = rte_mempool_create(nm_buf, max_nitem, sz, 0, 0, NULL,
			0, NULL, 0, rte_socket_id(), MEMPOOL_F_NO_SPREAD);

	if (!imp->mp_item)
		goto error;

	sprintf(nm_buf, "CPU%d %s", cpu, "vv-mp");
	sz = RTE_ALIGN_CEIL(sizeof(varying_value), RTE_CACHE_LINE_SIZE);
	imp->mp_varying_value = rte_mempool_create(nm_buf, max_nitem, sz, 0, 0, NULL,
			0, NULL, 0, rte_socket_id(), MEMPOOL_F_NO_SPREAD);

	if (!imp->mp_varying_value)
		goto error;

	sprintf(nm_buf, "CPU%d %s", cpu, "ss-mp");
	sz = RTE_ALIGN_CEIL(sizeof(static_value), RTE_CACHE_LINE_SIZE);
	imp->mp_static_value = rte_mempool_create(nm_buf, max_nitem, sz, 0, 0, NULL,
			0, NULL, 0, rte_socket_id(), MEMPOOL_F_NO_SPREAD);

	if (!imp->mp_static_value)
		goto error;

	LOG_INFO("[CPU%d] Item memory pool creation success!\n", cpu);

	return imp;

error :
	rte_exit(EXIT_FAILURE, "[CPU%d] (%10s:%4d) Item memory pool creation fails! "
			"errno=%d, %s\n", 
			cpu, __func__, __LINE__, rte_errno, rte_strerror(rte_errno));
}

item *
item_mp_get(item_mp *itmp)
{
	int rc;
	void *obj_p;
	item *it;
	rc = rte_mempool_get(itmp->mp_item, (void **)&obj_p);
	if (rc != 0) 
		return NULL;

	memset(obj_p, 0, itmp->mp_item->elt_size);
	it = (item *)obj_p;

	rc = rte_mempool_get(itmp->mp_varying_value, (void **)&obj_p);
	if (rc != 0) {
		rte_mempool_put(itmp->mp_item, (void *)it);
		return NULL;
	}

	memset(obj_p, 0, itmp->mp_varying_value->elt_size);
	it->vv = (varying_value *)obj_p;

	rc = rte_mempool_get(itmp->mp_static_value, (void **)&obj_p);
	if (rc != 0) {
		rte_mempool_put(itmp->mp_item, (void *)it->sv);
		rte_mempool_put(itmp->mp_varying_value, (void *)it);
		return NULL;
	}

	memset(obj_p, 0, itmp->mp_static_value->elt_size);
	it->sv = (static_value *)obj_p;

	return it;
}

void
item_mp_free(item_mp *itmp, item *it)
{
	rte_mempool_put(itmp->mp_static_value, (void *)it->sv);
	rte_mempool_put(itmp->mp_varying_value, (void *)it->vv);
	rte_mempool_put(itmp->mp_item, (void *)it);
}

void
item_mp_destroy(item_mp *itmp)
{
	rte_mempool_free(itmp->mp_static_value);
	rte_mempool_free(itmp->mp_varying_value);
	rte_mempool_free(itmp->mp_item);
}

