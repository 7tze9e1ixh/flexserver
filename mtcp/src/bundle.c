#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "bundle.h"

#define DBG_BUNDLE 0

#if DBG_BUNDLE
#define TRACE_BUNDLE(f, ...) fprintf(stderr, "(%10s:%4d) " f, __func__, __LINE__, ##__VA_ARGS__)
#else
#define TRACE_BUNDLE(f, ...) (void)0
#endif

bundle *
bundle_create(uint32_t numVecs) {

	uint32_t i;
	bundle *b;
	b = calloc(1, sizeof(bundle));
	if (!b) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	b->numVecs = numVecs;
	b->vecPtr = calloc(numVecs, sizeof(vector));
	if (!b->vecPtr) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}
#if 0
	b->vecMap = calloc(numVecs, sizeof(vector *));
	if (!b->vecMap) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}
#endif

	b->free_list = &b->vecPtr[0];

	for (i = 0; i < numVecs - 1; i++) 
		b->vecPtr[i].next = &b->vecPtr[i+1];

	pthread_spin_init(&b->sl, PTHREAD_PROCESS_PRIVATE);

	return b;
}

void
bundle_destroy(bundle *b) {
	pthread_spin_destroy(&b->sl);
	free(b->vecPtr);
	//free(b->vecMap);
	free(b);
}

/* Need Lock */
inline static vector *
__alloc_new_vec(bundle *b) {
	vector *v;
	v = b->free_list;
	b->free_list = v->next;
	v->numValues = 0;
	v->next = NULL;
	return v;
}

int
bundle_add_value(bundle *b, void *value) {

	vector *v;
	pthread_spin_lock(&b->sl);
	if (!b->unfilled_vector) {
		//assert(!b->unfilled_vector);
		v = __alloc_new_vec(b);
		if (!v) {
			pthread_spin_unlock(&b->sl);
			return -1;
		}
		v->value[v->numValues++] = value;
		b->unfilled_vector = v;

		TRACE_BUNDLE("vector %p numValues:%u value:%u\n", v, v->numValues, *(uint32_t *)value);

	} else {
		v = b->unfilled_vector;
		v->value[v->numValues++] = value;
		if (v->numValues == MAX_VEC_SIZE) {

			if (!b->filled_list_head && !b->filled_list_tail) {
				b->filled_list_head = v;
				b->filled_list_tail = v;
			} else {
				b->filled_list_tail->next = v;
				b->filled_list_tail = v;
			}
			b->numFilled++;
			b->unfilled_vector = NULL;
			TRACE_BUNDLE("vector %p is full, numFilled:%u\n", v, b->numFilled);
		}
	}
	pthread_spin_unlock(&b->sl);
	return 0;
}

void
bundle_get_filled_vectors(bundle *b, bundle_return *br) {

	pthread_spin_lock(&b->sl);

	if (b->numFilled == 0) {
		br->numVecs = 0;
		pthread_spin_unlock(&b->sl);
		return;
	}

	br->ret_head = b->filled_list_head;
	br->ret_tail = b->filled_list_tail;
	br->numVecs = b->numFilled;

	b->filled_list_head = NULL;
	b->filled_list_tail = NULL;
	b->numFilled = 0;

	pthread_spin_unlock(&b->sl);
}

void
bundle_get_unfilled_vectors(bundle *b, bundle_return *br) {

	pthread_spin_lock(&b->sl);

	if (!b->unfilled_vector) {
		br->numVecs = 0;
		pthread_spin_unlock(&b->sl);
		return;
	}

	br->ret_head = b->unfilled_vector;
	br->ret_tail = b->unfilled_vector;
	br->numVecs = 1;
	b->unfilled_vector = NULL;
	pthread_spin_unlock(&b->sl);
}

void
bundle_free_vectors(bundle *b, bundle_return *br) {

	pthread_spin_lock(&b->sl);

	if (br->numVecs == 0) {
		pthread_spin_unlock(&b->sl);
		return;
	}

	if (br->numVecs == 1) {
		br->ret_head->next = b->free_list;
		b->free_list = br->ret_head;
	} else {
		br->ret_tail->next = b->free_list;
		b->free_list = br->ret_head;
	}

	pthread_spin_unlock(&b->sl);
}

/*
#define NUM_TEST_VALUE 1024
#define NUM_ADDS 311
#define NUM_ITERS 2

int
main(void) {
	int i, cnt, numIters = 0;
	bundle *b;
	vector *v;
	uint32_t value[NUM_TEST_VALUE];
	bundle_return br;

	cnt = 0;
	for (i = 0; i < NUM_TEST_VALUE; i++) {
		value[i] = i;
	}

	b = bundle_create(512);

retry:
	for (i = 0; i < NUM_ADDS; i++)
		bundle_add_value(b, &value[i]);

	bundle_get_filled_vectors(b, &br);

	for (v = br.ret_head; v; v = v->next) {
		for (i = 0; i < MAX_VEC_SIZE; i++) {
			uint32_t *ret = (uint32_t *)v->value[i];
			printf("ret:%d, cnt:%d\n", *ret, cnt);
			cnt = (cnt + 1) % NUM_ADDS;
		}
	}

	bundle_free_vectors(b, &br);

	printf("-----------------------------\n");

	bundle_get_unfilled_vectors(b, &br);

	for (v = br.ret_head; v; v = v->next) {
		for (i = 0; i < v->numValues; i++) {
			uint32_t *ret = (uint32_t *)v->value[i];
			printf("ret:%d, cnt:%d\n", *ret, cnt);
			cnt = (cnt + 1) % NUM_ADDS;
		}
	}

	bundle_free_vectors(b, &br);

	
	numIters++;
	if (numIters < NUM_ITERS) {
		goto retry;
	}

}*/
