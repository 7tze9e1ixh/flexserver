#include <math.h>
#include "core.h"
#include "hyperbolic.h"
#include "debug.h"

#include <rte_random.h>
#include <rte_atomic.h>

#define DUMP_HYPERBOLIC_CACHE_LOG FALSE

typedef struct hyperbolic_cache_s {
	size_t n_items;
	size_t sample_size;
	item **set;
	item *root;
	rte_spinlock_t sl;
	char name[256];
} hyperbolic_cache;

static size_t RandomlySample(hyperbolic_cache *hc);
static void CalculatePrioForOffloading(item *it, uint32_t cur_ts);
static void CalculatePrioForEviction(item *it, uint32_t cur_ts);
static void QuickSort(item **set, int left, int right);
static void SortSampledSet(hyperbolic_cache *hc, int sample_size);

static void CompleteBinTreeInsert(hyperbolic_cache *hc, item *it);
static void CompleteBinTreeDelete(hyperbolic_cache *hc, item *it);
static item *CompleteBinTreeSearchItem(hyperbolic_cache *hc, const size_t pos);

static item *HyperbolicCacheGetOffloadingCandidate(hyperbolic_cache *hc);
static item *HyperbolicCacheGetEvictionCandidate(hyperbolic_cache *hc);

//static void CompleteBinTreeInorderTraversal(hyperbolic_cache *hc, item *it, void (*cb_complete_bin_tree)(void *arg));
//static void ShowItemUrlAndHV(void *arg);

static item sentinel;
static bool is_prng_set = false;
#if 0
static void
ShowItemUrlAndHV(void *arg) {
	item *it = (item *)arg;
	fprintf(stderr, "Object url=%s, hv=%lu\n", it->key, it->sv->hv);
}

static void
CompleteBinTreeInorderTraversal(hyperbolic_cache *hc, item *it, void (*cb_complete_bin_tree)(void *arg)) 
{
	if (it && it != &sentinel) {
		CompleteBinTreeInorderTraversal(hc, it->left, cb_complete_bin_tree);
		if (cb_complete_bin_tree)
			cb_complete_bin_tree(it);
		CompleteBinTreeInorderTraversal(hc, it->right, cb_complete_bin_tree);
	}
}
#endif

inline static size_t
RandomlySample(hyperbolic_cache *hc)
{
	size_t i, sample_size;

	sample_size = RTE_MIN(hc->sample_size, hc->n_items);

	for (i = 0; i < sample_size; i++) {
		size_t pos = rte_rand() % hc->n_items + 1;
		hc->set[i] = CompleteBinTreeSearchItem(hc, pos);
	}
	return sample_size;
}

inline static void
CalculatePrioForOffloading(item *it, uint32_t cur_ts)
{
	double prio;
	if (it->vv->ts_ms == cur_ts) /* already calculated */
		return;
	prio = (1 - HYPERBOLIC_OMEGA) * (double)(it->vv->n_requests) /
		((it->sv->sz >> 10) * (cur_ts - it->vv->ts_ms)) + HYPERBOLIC_OMEGA * it->vv->prio;
	it->vv->prio = prio;
	it->vv->ts_ms = cur_ts;
}

inline static void
CalculatePrioForEviction(item *it, uint32_t cur_ts) 
{
	double prio;
	if (it->vv->ts_ms == cur_ts)
		return;
	prio = (double)it->vv->n_requests / ((it->sv->sz >> 10) * (cur_ts - it->vv->ts_ms));
	it->vv->prio = prio;
	it->vv->ts_ms = cur_ts;
}

inline static void
SortSampledSet(hyperbolic_cache *hc, int sample_size) 
{
	QuickSort(hc->set, 0, sample_size - 1);
}

/* Sort to ascending orer */
inline static void
QuickSort(item **set, int left, int right)
{
	int mid, i, j;
	double pivot;

	if (left >= right) return;

	mid = (left + right) / 2;
	i = left;
	j = right;

	pivot = set[mid]->vv->prio;

	while(i <= j)
	{
		item *temp;
		while (set[i]->vv->prio < pivot && i < right)
			i++;
		while (set[j]->vv->prio > pivot && j > left)
			j--;
		if (i <= j) {
			temp = set[i];
			set[i] = set[j];
			set[j] = temp;
			i++;
			j--;
		}
	}
	QuickSort(set, left, j);
	QuickSort(set, i, right);
}

inline static void
CompleteBinTreeInsert(hyperbolic_cache *hc, item *it) 
{
	if (!hc->root) {
		hc->root = it;
		it->parent = &sentinel;
	} else {
		int i;
		size_t pos = hc->n_items + 1;
		size_t num_edges = log2(pos);
		item *ptr = hc->root;

		for (i = num_edges - 1; i > 0; i--) 
			ptr = (pos & (1LU << i)) ? ptr->right : ptr->left;
		if (pos & 1LU) {
			ptr->right = it;
		} else {
			ptr->left = it;
		}
		it->parent = ptr;
	}
	it->left = &sentinel;
	it->right = &sentinel;
	hc->n_items++;
}

inline static void
CompleteBinTreeDelete(hyperbolic_cache *hc, item *it)
{
	item *s;
	s = CompleteBinTreeSearchItem(hc, hc->n_items);
	if( s == NULL ) return; // 

	if (it == hc->root) {
		if (s == it) { /* Only one node is in the tree */
			assert(hc->n_items == 1);
			hc->root = NULL;
		} else {
			if (s->parent->left == s) {
				s->parent->left = &sentinel;
			} else {
				s->parent->right = &sentinel;
			}

			hc->root = s;
			s->left = it->left;
			s->right = it->right;
			s->parent = &sentinel;

			s->left->parent = s;
			s->right->parent = s;
		}
	} else {
		if (s == it) {
			if (it->parent->left == it) {
				it->parent->left = &sentinel;
			} else {
				it->parent->right = &sentinel;
			}
		} else {
			if (s->parent->left == s) {
				s->parent->left = &sentinel;
			} else {
				s->parent->right = &sentinel;
			}

			if (it->parent->left == it) {
				it->parent->left = s;
			} else {
				it->parent->right = s;
			}

			s->left = it->left;
			s->right = it->right;
			s->parent = it->parent;
			s->left->parent = s;
			s->right->parent = s;
		}
	}

	it->left = NULL;
	it->right = NULL;
	it->parent = NULL;
	hc->n_items--;
}

inline static item *
CompleteBinTreeSearchItem(hyperbolic_cache *hc, const size_t pos)
{
	int num_edges; 
	item *ptr = hc->root;

	if (pos > hc->n_items) {
		return NULL;
	}

	if (pos == 1)
		return ptr;
	
	num_edges = log2(pos) - 1;
	for (; num_edges >= 0; num_edges--) {
		ptr = (pos & (1LU << num_edges)) ? ptr->right : ptr->left;
	}

	return ptr;
}

/* DISK ---> L2_CACHE */
inline static item *
HyperbolicCacheGetOffloadingCandidate(hyperbolic_cache *hc)
{
	size_t i, sample_size;
	uint32_t cur_ms;

	/* Random Sampling */
	sample_size = RandomlySample(hc);
	GET_CUR_MS(cur_ms);

	/* Calculate priority */
	for (i = 0; i < sample_size; i++)
		CalculatePrioForOffloading(hc->set[i], cur_ms);

	/* Sort the items by the priorities which were calculated */
	SortSampledSet(hc, sample_size);
#if DUMP_HYPERBOLIC_CACHE_LOG
	int j;
	DUMP_LOG("\n== Get Offloading Candidate ===================\n");
	for (j = 0; j < sample_size; j++) {
		uint32_t r_cnt;
		r_cnt = item_get_refcount(hc->set[j]);
		DUMP_LOG("hv=%lu, sz=%u, "
					"n=%u, t=%u, "
					"r_cnt=%u, prio=%lf\n",
					hc->set[j]->sv->hv, hc->set[j]->sv->sz,
					hc->set[j]->vv->n_requests, hc->set[j]->vv->ts_ms,
					r_cnt, hc->set[j]->vv->prio);
	}
#endif
	CompleteBinTreeDelete(hc, hc->set[sample_size -1]);
	item_set_state(hc->set[sample_size - 1], ITEM_STATE_WAITING_FOR_L2_OPTIM_CACHE);
#if DUMP_HYPERBOLIC_CACHE_LOG
	DUMP_LOG("Select to be offloaded object(hv=%lu)\n", 
			hc->set[sample_size - 1]->sv->hv);
#endif

	return hc->set[sample_size - 1];
}
/* Eviction occurs only at L1_CACHE and L2_CACHE 
 * L1_CACHE ---> L2_CACHE
 * L2_CACHE ---> L1_CACHE
 * */
inline static item *
HyperbolicCacheGetEvictionCandidate(hyperbolic_cache *hc)
{
	size_t i, sample_size;
	uint32_t cur_ms;
	item *ec;
	uint16_t st;
	uint32_t refcount;

	while (1) {
		sample_size = RandomlySample(hc);
		
		GET_CUR_MS(cur_ms);

		for (i = 0; i < sample_size; i++) 
			CalculatePrioForEviction(hc->set[i], cur_ms);

		SortSampledSet(hc, sample_size);
#if DUMP_HYPERBOLIC_CACHE_LOG
		int j;
		DUMP_LOG("\n== Get Eviction Candidate ===================\n");
		for (j = 0; j < sample_size; j++) {
			uint32_t r_cnt;
			r_cnt = item_get_refcount(hc->set[j]);
			DUMP_LOG("hv=%lu, sz=%u, "
					"n=%u, t=%u, "
					"r_cnt=%u, prio=%lf\n",
					hc->set[j]->sv->hv, hc->set[j]->sv->sz,
					hc->set[j]->vv->n_requests, hc->set[j]->vv->ts_ms,
					r_cnt, hc->set[j]->vv->prio);
		}
#endif

		for (i = 0; i < sample_size; i++) {
			ec = hc->set[i];
			st = rte_atomic16_read(&ec->state);
			if (st == ITEM_STATE_AT_L1_CACHE || st == ITEM_STATE_AT_L2_CACHE) {
				item_set_state(ec, ITEM_STATE_AT_NOWHERE);
				CompleteBinTreeDelete(hc, ec);
				do {
					refcount = item_get_refcount(ec);
					usleep(MSEC_TO_USEC(MAX_EVICTION_BACKOFF_TIME));
				} while(refcount > 0);
#if DUMP_HYPERBOLIC_CACHE_LOG
				DUMP_LOG("Select to be evicted object(hv=%lu)\n", ec->sv->hv);
#endif
				return ec;
			}
		}
	}

	return NULL;
}

/* For L2 offloading candidate 
 * L2_CACHE ---> L1_CACHE
 * */
inline static item *
HCGetOCAtControlPlane(hyperbolic_cache *hc)
{
	size_t i, sample_size;
	uint32_t cur_ms;
	item *ec;
	uint16_t st;
	uint32_t refcount;

	while (1) {
		sample_size = RandomlySample(hc);
		
		GET_CUR_MS(cur_ms);

		for (i = 0; i < sample_size; i++) 
			CalculatePrioForEviction(hc->set[i], cur_ms);

		SortSampledSet(hc, sample_size);
#if DUMP_HYPERBOLIC_CACHE_LOG
		int j;
		DUMP_LOG("\n== Get Eviction Candidate ===================\n");
		for (j = sample_size - 1; j j >= 0; j--) {
			uint32_t r_cnt;
			r_cnt = item_get_refcount(hc->set[j]);
			DUMP_LOG("hv=%lu, sz=%u, "
					"n=%u, t=%u, "
					"r_cnt=%u, prio=%lf\n",
					hc->set[j]->sv->hv, hc->set[j]->sv->sz,
					hc->set[j]->vv->n_requests, hc->set[j]->vv->ts_ms,
					r_cnt, hc->set[j]->vv->prio);
		}
#endif

		for (i = sample_size - 1; i >= 0; i--) {
			ec = hc->set[i];
			st = rte_atomic16_read(&ec->state);
			if (st == ITEM_STATE_AT_L2_CACHE) {
				item_set_state(ec, ITEM_STATE_WAITING_FOR_L1_OPTIM_CACHE);
				CompleteBinTreeDelete(hc, ec);
				do {
					refcount = item_get_refcount(ec);
					usleep(MSEC_TO_USEC(MAX_EVICTION_BACKOFF_TIME));
				} while(refcount > 0);
#if DUMP_HYPERBOLIC_CACHE_LOG
				DUMP_LOG("Select to be evicted object(hv=%lu)\n", ec->sv->hv);
#endif
				return ec;
			}
		}
	}

	LOG_ERROR("No items\n");

	return NULL;
}

item *
hyperbolic_get_oc_for_control_plane(void *cache) {
	item *it;
	hyperbolic_cache *hc = (hyperbolic_cache *)cache;
	rte_spinlock_lock(&hc->sl);
	it = HCGetOCAtControlPlane(cache);
	DBG_TRACE("(%s) OC (url=%s, hv=%lu)\n", hc->name, it->key, it->sv->hv);
	rte_spinlock_unlock(&hc->sl);
	return it;
}


void *
hyperbolic_cache_setup(const char *name, void *arg)
{
	hyperbolic_cache *hc;

	hc = calloc(1, sizeof(hyperbolic_cache));
	if (!hc) {
		rte_exit(EXIT_FAILURE,
				"Failed dto allocate some memory of hyperbolic cache"
				"errno=%d (%s)\n",
				rte_errno, rte_strerror(rte_errno));
	}

	if (!is_prng_set) {
		rte_srand(time(NULL));
		is_prng_set = true;
	}

	hc->root = NULL;
	hc->sample_size = *(uint32_t *)arg;

	hc->set = calloc(hc->sample_size, sizeof(item *));
	if (!hc->set) {
		rte_exit(EXIT_FAILURE,
				"Failed to allocate some memory of hyperbolic cache"
				"errno : %d, %s\n",
				rte_errno, rte_strerror(rte_errno));
	}

	strcpy(hc->name, name);

	rte_spinlock_init(&hc->sl);

	return hc;
}

void 
hyperbolic_cache_insert(void *cache, item *it)
{
	hyperbolic_cache *hc = (hyperbolic_cache *)cache;
	rte_spinlock_lock(&hc->sl);
	CompleteBinTreeInsert(hc, it);
	DBG_TRACE("(%s) Insert item (url=%s, hv=%lu, refcnt)\n", hc->name, it->key, it->sv->hv);
	rte_spinlock_unlock(&hc->sl);
}

void
hyperbolic_cache_delete(void *cache, item *it)
{
	hyperbolic_cache *hc = (hyperbolic_cache *)cache;
	rte_spinlock_lock(&hc->sl);
	CompleteBinTreeDelete(hc, it);
	DBG_TRACE("(%s) Delete item (url=%s, hv=%lu)\n", hc->name, it->key, it->sv->hv);
	rte_spinlock_unlock(&hc->sl);
}

item *
hyperbolic_cache_offloading_candidate(void *cache) 
{
	item *it;
	hyperbolic_cache *hc = (hyperbolic_cache *)cache;
	rte_spinlock_lock(&hc->sl);
	it = HyperbolicCacheGetOffloadingCandidate(hc);
	DBG_TRACE("(%s) OC (url=%s, hv=%lu)\n", hc->name, it->key, it->sv->hv);
	rte_spinlock_unlock(&hc->sl);
	return it;
}

item *
hyperbolic_cache_eviction_candidate(void *cache)
{
	item *it;
	hyperbolic_cache *hc = (hyperbolic_cache *)cache;
	rte_spinlock_lock(&hc->sl);
	it = HyperbolicCacheGetEvictionCandidate(hc);
	DBG_TRACE("(%s) EC (url=%s, hv=%lu)\n", hc->name, it->key, it->sv->hv);
	rte_spinlock_unlock(&hc->sl);
	return it;
}

void
hyperbolic_cache_access_item(void *cache, item *it) 
{
	uint16_t st;
	UNUSED(cache); // it is for lfu, I used this parameter to unify the function format.
	st = rte_atomic16_read(&it->state);
	if (st == ITEM_STATE_AT_L1_CACHE || st == ITEM_STATE_AT_L2_CACHE) {
		item_incr_refcount(it);
		it->vv->n_requests++;
	} else if (st == ITEM_STATE_AT_DISK || st == ITEM_STATE_AT_NOWHERE) {
		it->vv->n_requests++;
	} else {
		//log_warning("Item(hv=%lu) is in a wrong state %u\n", it->sv->hv, st);
	}
}

void
hyperbolic_cache_free_item(void *cache, item *it)
{
	uint16_t st;
	UNUSED(cache); // it is for lfu, I used this parameter to unify the function format.
	st = rte_atomic16_read(&it->state);
	if (st == ITEM_STATE_AT_L1_CACHE || st == ITEM_STATE_AT_NOWHERE 
			|| st == ITEM_STATE_AT_L2_CACHE || st == ITEM_STATE_WAITING_FOR_L1_OPTIM_CACHE) {
		/* st : ITEM_STATE_AT_NOWHERE : Wait for Eviction */
		item_decr_refcount(it);
	} else {
		LOG_ERROR("Fail to synchronize reference count for item (hv=%lu, url=%s, state=%u)\n",
				it->sv->hv, it->key, st);
	    exit(EXIT_FAILURE);
	}
}

void 
hyperbolic_cache_destroy(void *cache)
{
	hyperbolic_cache *hc = (hyperbolic_cache *)cache;
	free(hc->set);
	free(cache);
}

void hyperbolic_show_all(void *cache) {
	hyperbolic_cache *hc = (hyperbolic_cache *)cache;
	rte_spinlock_lock(&hc->sl);
	fprintf(stdout, "# of items : %lu\n", hc->n_items);
//	CompleteBinTreeInorderTraversal(hc, hc->root, ShowItemUrlAndHV);
	rte_spinlock_unlock(&hc->sl);
}
