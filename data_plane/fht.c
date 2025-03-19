#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_random.h>
#include <rte_common.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_errno.h>

#include "fht.h"
#include "debug.h"
#include "memory_mgt.h"

static uint32_t g_fht_init_val;

struct fht_item {
	void *data;
	uint64_t hv;
	uint32_t id;
	TAILQ_ENTRY(fht_item) fht_item_link;
};

struct fht {
	uint32_t numEntries;
	uint32_t mask;
	mem_pool_t mp_item;
	TAILQ_HEAD(, fht_item) *bucket;
};

inline static uint64_t 
__fht_cal_hv(struct tcp_four_tuple *tuple) {
	uint32_t sdport = ((uint32_t)tuple->sport << 16) | (uint32_t)tuple->dport;
	return rte_jhash_3words(tuple->srcAddr, tuple->dstAddr, sdport, g_fht_init_val);
}

inline static void *
__fht_get_bucket(struct fht *ht, uint64_t hv) {
	return &ht->bucket[hv & ht->mask];
}

inline static struct fht_item *
__fht_find_item(struct fht *ht, void *b, uint64_t hv, uint32_t id) {

	struct fht_item *it;

	TAILQ_FOREACH(it, (TAILQ_HEAD(, fht_item) *)b, fht_item_link)
		if (hv == it->hv && id == it->id)
			return it;
	return it; //NULL
}

struct fht *
fht_create(unsigned numEntries, unsigned maxItems) {

	struct fht *ht;
	char pool_name[64];
	int i;

	ht = calloc(1, sizeof(struct fht));
	if (!ht) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	ht->numEntries = numEntries;
	ht->mask = numEntries - 1;

	ht->bucket = calloc(numEntries, sizeof(TAILQ_HEAD(, fht_item)));
	if (!ht->bucket) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < numEntries; i++)
		TAILQ_INIT(&ht->bucket[i]);

	if (rte_lcore_id() == 0)
		g_fht_init_val = (uint32_t)rte_rand();

	sprintf(pool_name, "fht_item-%u", rte_lcore_id());
	ht->mp_item = MPCreate(pool_name, sizeof(struct fht_item), sizeof(struct fht_item) * maxItems);
	if (!ht->mp_item) {
		log_error("Fail to create memory pool for fht\n");
		exit(EXIT_FAILURE);
	}

	return ht;
}

void
fht_destroy(struct fht *ht) {
	MPDestroy(ht->mp_item);
	free(ht->bucket);
	free(ht);
}

int
fht_insert_data(struct fht *ht, struct tcp_four_tuple *tuple, void *data, uint32_t id) {
	
	struct fht_item *it;
	uint64_t hv = __fht_cal_hv(tuple);
	TAILQ_HEAD(, fht_item) *b = __fht_get_bucket(ht, hv);

	it = __fht_find_item(ht, b, hv, id);
	if (it)  {
		/* Already Inserted  */
		return -1;
	}

	it = MPAllocateChunk(ht->mp_item);
	if (!it) {
		log_error("Fail to allocae chunk for fht, increase # of chunks\n");
		exit(EXIT_FAILURE);
	}

	it->data = data;
	it->hv = hv;
	it->id = id;
	//fprintf(stderr, "insert id: %d hv: %d\n", id, hv); //
	TAILQ_INSERT_TAIL(b, it, fht_item_link);

	return 0;
}

int
fht_delete(struct fht *ht, struct tcp_four_tuple *tuple, uint32_t id) {

	struct fht_item *it;
	uint64_t hv = __fht_cal_hv(tuple);
	TAILQ_HEAD(, fht_item) *b = __fht_get_bucket(ht, hv);

	it = __fht_find_item(ht, b, hv, id);
	if (!it)  {
		/* Already Deleted  */
		return -1;
	}

	TAILQ_REMOVE(b, it, fht_item_link);
	MPFreeChunk(ht->mp_item, it);

	return 0;
}

void *
fht_get(struct fht *ht, struct tcp_four_tuple *tuple, uint32_t id) {

	struct fht_item *it;
	uint64_t hv = __fht_cal_hv(tuple);
	TAILQ_HEAD(, fht_item) *b = __fht_get_bucket(ht, hv);

	it = __fht_find_item(ht, b, hv, id);
	if (!it) {
		return NULL;
	}

	return it->data;
}
