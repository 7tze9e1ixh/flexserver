#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "lfu.h"
#include "rb_tree.h"

typedef struct lfu_cache_s {
	rb_tree *rbt;
	pthread_spinlock_t sl;
} lfu_cache;

static bool lfu_cmp(item *x, item *y);
static uint64_t lfu_key(item *x);

inline static bool 
lfu_cmp(item *x, item *y) {
	return x->vv->n_requests < y->vv->n_requests;
}

inline static uint64_t 
lfu_key(item *x) {
	return x->vv->n_requests;
}

void *
lfu_cache_setup(void *arg) 
{
	lfu_cache *lc;

	lc =  calloc(1, sizeof(lfu_cache));
	if (!lc) {
		perror("Fail to allocate memroy for lfu_cache");
		return NULL;
	}

	lc->rbt = rb_tree_create(lfu_cmp, lfu_key);
	if (!lc->rbt) {
		perror("Fail to create rb tree");
		return NULL;
	}

	pthread_spin_init(&lc->sl, PTHREAD_PROCESS_PRIVATE);

	return lc;
}

void 
lfu_cache_insert(void *cache, item *it)
{
	lfu_cache *cl = (lfu_cache *)cache;
	pthread_spin_lock(&cl->sl);
	rb_tree_insert(cl->rbt, it);
	pthread_spin_unlock(&cl->sl);
}

void 
lfu_cache_delete(void *cache, item *it)
{
	lfu_cache *cl = (lfu_cache *)cache;
	pthread_spin_lock(&cl->sl);
	rb_tree_delete(cl->rbt, it);
	pthread_spin_unlock(&cl->sl);
}

item *
lfu_cache_offloading_candidate(void *cache)
{
	lfu_cache *cl = (lfu_cache *)cache;
	item *it;
	pthread_spin_lock(&cl->sl);
	it = rb_tree_get_maximum(cl->rbt);
	pthread_spin_unlock(&cl->sl);
	return it;
}

item *
lfu_cache_eviction_candidate(void *cache)
{
	lfu_cache *cl = (lfu_cache *)cache;
	item *it;
	pthread_spin_lock(&cl->sl);
	it = rb_tree_get_minimum(cl->rbt);
	pthread_spin_unlock(&cl->sl);
	return it;
}

void
lfu_cache_destroy(void *cache) 
{
	lfu_cache *cl = (lfu_cache *)cache;
	pthread_spin_destroy(&cl->sl);
	rb_tree_destroy(cl->rbt);
	free(cl);
}

void
lfu_cache_access_item(void *cache, item *it)
{
	lfu_cache *cl = (lfu_cache *)cache;
	pthread_spin_lock(&cl->sl);
	rb_tree_delete(cl, it);
	rb_tree_insert(cl, it);
	pthread_spin_unlock(&cl->sl);
}
