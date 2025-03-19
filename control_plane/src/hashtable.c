#include <xxhash.h>
#include <string.h>

#include "hashtable.h"
#include "debug.h"

#define ENABLE_LOCK FALSE

#if ENABLE_LOCK
#define HASHTABLE_LOCK(sl) rte_spinlock_lock((sl))
#define HASHTABLE_UNLOCK(sl) rte_spinlock_unlock((sl))
#define HASHTABLE_LOCK_INIT(sl) rte_spinlock_init((sl))
#else
#define HASHTABLE_LOCK(sl) UNUSED(sl)
#define HASHTABLE_UNLOCK(sl) UNUSED(sl)
#define HASHTABLE_LOCK_INIT(sl) UNUSED(sl)
#endif

struct item_ht_s {
	uint32_t n_entry;
	uint32_t mask;
	item_bucket *b;
#if DBG_HT
	uint32_t *numBucketEntry;
#endif
};

static struct item_ht_s ht;
static rte_spinlock_t *ht_sl;

void
hashtable_create(uint16_t hash_power) 
{
	int i;

	ht.n_entry = (1U << (uint32_t)hash_power);
	ht.mask = ht.n_entry - 1;

	//ht.b = rte_malloc(NULL, sizeof(item_bucket) * ht.n_entry, ht.n_entry);
	ht.b = malloc(sizeof(item_bucket) * ht.n_entry);
	if (!ht.b) {
		rte_exit(EXIT_FAILURE, 
				" Fail to allocate some memory for hash bucket, "
				"rte_errno : %d, (%s)\n",
				rte_errno, rte_strerror(rte_errno));
	}

	for (i = 0; i < ht.n_entry; i++)
		TAILQ_INIT(&ht.b[i]);

	//ht_sl = rte_malloc(NULL, sizeof(rte_spinlock_t) * ht.n_entry, ht.n_entry);
	ht_sl = malloc(sizeof(rte_spinlock_t) * ht.n_entry);
	if (!ht_sl) {
		rte_exit(EXIT_FAILURE,
				"Fail to allocate some memory for hashtable spinlock, "
				"rte_errno : %d, (%s)\n",
				rte_errno, rte_strerror(rte_errno));
	}

	for (i = 0; i < ht.n_entry; i++) {
		HASHTABLE_LOCK_INIT(&ht_sl[i]);
	}

#if DBG_HT
	ht.numBucketEntry = calloc(ht.n_entry, sizeof(int));
	if (!ht.numBucketEntry) {
		perror("Fail to allocate memory for debugging hashtable\n");
		exit(EXIT_FAILURE);
	}
#endif
}

item *
hashtable_get_with_key(void *key, const size_t keylen, uint16_t *st)
{
	item *it;
	item_bucket *b;
	rte_spinlock_t *sl;
	uint32_t bucket_index;
	uint64_t hv;

	hv = CAL_HV(key, keylen);
	bucket_index = hv & ht.mask;
	b = &ht.b[bucket_index];
	sl = &ht_sl[bucket_index];

	HASHTABLE_LOCK(sl);

	TAILQ_FOREACH(it, b, hashLink)
		if (it->sv->hv == hv)
			break;

	if (!it) {
		HASHTABLE_UNLOCK(sl);
		return NULL;
	}

	if (likely(st))
		*st = rte_atomic16_read(&it->state);

	HASHTABLE_UNLOCK(sl);
	return it;
}


item *
hashtable_get_with_hv(uint64_t hv, uint16_t *st)
{
	uint32_t b_idx;
	item_bucket *b;
	rte_spinlock_t *sl;
	item *it;

	b_idx = hv & ht.mask;
	b = &ht.b[b_idx];
	sl = &ht_sl[b_idx];

	HASHTABLE_LOCK(sl);

	TAILQ_FOREACH(it, b, hashLink) {
		if (it->sv->hv == hv)
			break;
	}

	if (!it) {
		HASHTABLE_UNLOCK(sl);
		LOG_ERROR("GET Wrong hv(%lu)\n", hv);
		return NULL;
	}

	if (likely(st))
		*st = rte_atomic16_read(&it->state);
/*
	if (st == ITEM_STATE_AT_DELETE_QUEUE || st == ITEM_STATE_AT_WAIT_QUEUE
			|| st == ITEM_STATE_AT_NOWHERE) {
		rte_spinlock_unlock(sl);
		return NULL;
	}*/

	//item_incr_refcount(it);
	HASHTABLE_UNLOCK(sl);
	return it;
}

void
hashtable_free_item(item *it) 
{
	//item_decr_refcount(it);
}

/* Called in HeatDataplane */
int 
hashtable_put(private_context *ctx, void *key, const size_t keylen, item **ret_it)
{
	uint32_t bucket_index;
	uint64_t hv;
	struct stat f_stat;
	rte_spinlock_t *sl;
	item_bucket *b;
	item *it = NULL;

	hv = CAL_HV(key, keylen);
	bucket_index = hv & ht.mask;
	b = &ht.b[bucket_index];
	sl = &ht_sl[bucket_index];

	HASHTABLE_LOCK(sl);
	TAILQ_FOREACH(it, b, hashLink) {
		if (it->sv->hv == hv) 
			break;
	}

	if (unlikely(it)) {
		/* Update item */
		/* Never occur */
		uint16_t st = rte_atomic16_read(&it->state);
		if (st == ITEM_STATE_AT_L1_CACHE) {
			item_set_state(it, ITEM_STATE_AT_WAIT_QUEUE);
			HASHTABLE_UNLOCK(sl);
			*ret_it = NULL;
			return HASHTABLE_PUT_ENQUEUE_TO_WAIT_QUEUE;
		}

		exit(EXIT_FAILURE);

		free(it->key);
		it->keylen = keylen;
		it->key = strndup(key, keylen);
		if (!it->key) {
			TAILQ_REMOVE(b, it, hashLink);
			*ret_it = NULL;
			HASHTABLE_UNLOCK(sl);
			return HASHTABLE_PUT_FAIL;
		}

		stat(key, &f_stat);

		it->sv->sz = f_stat.st_size;

		GET_CUR_MS(it->vv->ts_ms);
		it->vv->n_requests = 0;
		rte_atomic32_clear(&it->vv->refcount);
		it->vv->prio = 0;

	} else {
		/* Put new item */
		it = item_mp_get(ctx->itmp);
		if (!it) {
			*ret_it = NULL;
			HASHTABLE_UNLOCK(sl);
			return HASHTABLE_PUT_FAIL;
		}

		it->keylen = keylen;
		it->key = strndup(key, keylen);
		if (!it->key) {
			*ret_it = NULL;
			item_mp_free(ctx->itmp, it);
			HASHTABLE_UNLOCK(sl);
			return HASHTABLE_PUT_FAIL;
		}

		stat(key, &f_stat);

		it->sv->hv = hv;
		it->sv->sz = f_stat.st_size;

		GET_CUR_MS(it->vv->ts_ms);

		it->bucket = b;
		it->ctx = ctx;
		it->numBlocks = -1;

		if (ret_it)
			*ret_it = it;

		TAILQ_INSERT_TAIL(b, it, hashLink);

#if DBG_HT
		ht.numBucketEntry[bucket_index]++;
#endif
	}
	HASHTABLE_UNLOCK(sl);

	return HASHTABLE_PUT_SUCCESS;
}

void 
hashtable_destroy(void)
{
	int i;
	for (i=0; i < ht.n_entry; i++) {
		HASHTABLE_UNLOCK(&ht_sl[i]);
	}
	rte_free(ht_sl);
	rte_free(ht.b);

	LOG_INFO("Complete to destroy hashtable\n");
}

void
hashtable_show_bucket_size(void) {
	int i, numFill = 0;
	
	for (i = 0; i < ht.n_entry; i++) {
		if (ht.numBucketEntry[i] > 0)
			numFill++;
	}
	fprintf(stderr, "Total bucket : %d, Filled bucket : %d\n", ht.n_entry, numFill);
}
