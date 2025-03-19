#ifndef __ITEM_H__
#define __ITEM_H__

#include <stdint.h>
#include <stddef.h>
#include <sys/queue.h>
#include <rte_atomic.h>
#include <stdbool.h>

#define ITEM_STATE_AT_NOWHERE	                        (uint8_t)0
#define ITEM_STATE_AT_DISK		                        (uint8_t)1
#define ITEM_STATE_AT_L1_CACHE							(uint8_t)2
#define ITEM_STATE_AT_WAIT_QUEUE						(uint8_t)3
#define ITEM_STATE_AT_DELETE_QUEUE                      (uint8_t)4
#define ITEM_STATE_WAITING_FOR_L2_OPTIM_CACHE			(uint8_t)5
#define ITEM_STATE_WAITING_FOR_EVICTION                 (uint8_t)6
#define ITEM_STATE_WAITING_FOR_L1_OPTIM_CACHE			(uint8_t)7
#define ITEM_STATE_AT_L2_CACHE							(uint8_t)8

#define MAX_BLOCK_MAP 64 /* 128K * 64 = 8M */

typedef struct varying_value_s varying_value;
typedef struct static_value_s static_value;
typedef struct item_s item;

struct varying_value_s {
	uint32_t n_requests;
	uint32_t ts_ms;
	rte_atomic32_t refcount;
	double prio;
};

struct static_value_s {
	uint64_t hv;
	uint32_t sz;
};

struct item_s {
	rte_atomic16_t state;
	varying_value *vv;
	static_value *sv;

	/* For Set or LFU */
	item *left;
	item *right;
	item *parent;
	uint8_t color : 1,
			reserved : 7;
#if (HOST_LRU || NIC_LRU)
	TAILQ_ENTRY(item_s) lruqLink;
#endif
	char *key;        /* file path */
	size_t keylen;    /* file path length */

	void *bucket;    /* Hashtable bucket that the item is included */
	void *ctx;

	TAILQ_ENTRY(item_s) hashLink;
	TAILQ_ENTRY(item_s) queueLink;
#if SUPPORT_DASH
	void *v;	/* video */
	uint16_t segSeq;
	TAILQ_ENTRY(item_s) segLink;
#endif

	int numBlocks;
	void *block_map[MAX_BLOCK_MAP];
	uint64_t ts;
#if _CHECK_DUP
	uint8_t offload_proc;
	uint8_t evict_proc;
	uint16_t num_cmd;
#endif
};

void item_set_state(item *it, uint16_t desired);
extern void item_incr_refcount(item *it);
extern void item_decr_refcount(item *it);
uint64_t item_get_hv(item *it);
uint64_t item_get_nb_requests(item *it);
bool item_cmp_hv(item *x, item *y);

#define item_get_refcount(_it) rte_atomic32_read(&_it->vv->refcount)

#endif
