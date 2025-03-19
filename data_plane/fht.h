#ifndef __FHT_H__
#define __FHT_H__

#include <stdint.h>

typedef struct fht fht;

struct tcp_four_tuple {
	uint32_t srcAddr;
	uint32_t dstAddr;
	uint16_t sport;
	uint16_t dport;
};

struct fht *
fht_create(unsigned numEntries, unsigned maxItems);

void
fht_destroy(struct fht *ht);

int
fht_insert_data(struct fht *ht, struct tcp_four_tuple *tuple, void *data, uint32_t id);

int
fht_delete(struct fht *ht, struct tcp_four_tuple *tuple, uint32_t id);

void *
fht_get(struct fht *ht, struct tcp_four_tuple *tuple, uint32_t id);

#endif
