#ifndef __CHUNK_HASHTABLE_H__
#define __CHUNK_HASHTABLE_H__

#include "dataplane.h"
#include "blk.h"

typedef struct chnk_ht_s chnk_ht;

chnk_ht *chnk_ht_create(void);
int chnk_ht_insert(chnk_ht *cht, uint64_t hv, uint16_t c_seq, uint8_t *data, size_t chnk_sz);
int chnk_ht_delete(chnk_ht *cht, uint64_t hv);
extern int chnk_ht_get_blk(chnk_ht *cht, uint64_t o_hv, off_t o_off, blk **ret_blk, off_t *ret_off);
int chnk_ht_direct_insert(chnk_ht *cht, uint64_t hv, char *path);
void chnk_ht_teardown(chnk_ht *cht);

#endif
