#include <assert.h>
#include <string.h>
#include "debug.h"
#include "item.h"

inline void
item_set_state(item *it, uint16_t desired)
{
	rte_atomic16_set(&it->state, desired);
}

inline void
item_incr_refcount(item *it) 
{
	uint32_t refcount;
	rte_atomic32_inc(&it->vv->refcount);
	refcount = rte_atomic32_read(&it->vv->refcount);
#if DBG_SINGLE_CLIENT
	assert(refcount == 1);
#endif
	assert(refcount > 0);
}

inline void
item_decr_refcount(item *it)
{
	uint32_t refcount;
	rte_atomic32_dec(&it->vv->refcount);
	refcount = rte_atomic32_read(&it->vv->refcount);
#if DBG_SINGLE_CLIENT
	assert(refcount == 0);
#endif
	assert((int)refcount >= 0);

}

inline uint64_t
item_get_hv(item *it) {
	return it->sv->hv;
}

inline uint64_t 
item_get_nb_requests(item *it) {
	return (uint64_t)it->vv->n_requests;
}

bool
item_cmp_hv(item *x, item *y) {
	return x->sv->hv < y->sv->hv;
}

