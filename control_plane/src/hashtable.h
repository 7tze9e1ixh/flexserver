#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

#include "core.h"
#include "item.h"

#define DBG_HT TRUE

#define HASHTABLE_PUT_SUCCESS                0
#define HASHTABLE_PUT_ENQUEUE_TO_WAIT_QUEUE	-1
#define HASHTABLE_PUT_FAIL                  -2

typedef struct item_bucket_s item_bucket;
TAILQ_HEAD(item_bucket_s, item_s);
void hashtable_create(uint16_t hash_power);
item *hashtable_get_with_key(void *key, const size_t keylen, uint16_t *st);
item *hashtable_get_with_hv(uint64_t hv, uint16_t *st);
int hashtable_put(private_context *ctx, void *key, const size_t keylen, item **ret_it);
void hashtable_free_item(item *it);
void hashtable_destroy(void);
void hashtable_show_bucket_size(void);
#endif
