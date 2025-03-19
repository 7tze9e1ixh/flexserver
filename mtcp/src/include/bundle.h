#ifndef __BUNDLE_H__
#define __BUNDLE_H__

#include <stdint.h>
#include <pthread.h>

#define MAX_VEC_SIZE 32

typedef struct vector {
	void *value[MAX_VEC_SIZE];
	struct vector *next;
	uint32_t numValues;
} vector;

typedef struct bundle {
	uint32_t numVecs;
	uint32_t numFilled;
	//vector **vecMap;
	vector *vecPtr;
	vector *unfilled_vector;
	vector *free_list;
	vector *filled_list_head;
	vector *filled_list_tail;
	pthread_spinlock_t sl;
} bundle;

typedef struct bundle_return {
	vector *ret_head;
	vector *ret_tail;
	uint32_t numVecs;
} bundle_return;

bundle *
bundle_create(uint32_t numVecs);

void
bundle_destroy(bundle *b);

int
bundle_add_value(bundle *b, void *value);

void
bundle_get_filled_vectors(bundle *b, bundle_return *br);

void
bundle_get_unfilled_vectors(bundle *b, bundle_return *br);

void
bundle_free_vectors(bundle *b, bundle_return *br);

#endif
