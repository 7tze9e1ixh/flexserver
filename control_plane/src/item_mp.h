#ifndef __ITEM_MP_H__
#define __ITEM_MP_H__

#include "item.h"

typedef struct item_mp_s item_mp;

struct item_mp_s {
	struct rte_mempool *mp_item;
	struct rte_mempool *mp_varying_value;
	struct rte_mempool *mp_static_value;
}; 

item_mp *item_mp_create(const size_t max_nitem, const int cpu);
item *item_mp_get(item_mp *itmp);
void item_mp_free(item_mp *itmp, item *it);
void item_mp_destroy(item_mp *itmp);

#endif
