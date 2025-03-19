#ifndef __GENERAL_DATA_BUFFER_H__
#define __GENERAL_DATA_BUFFER_H__

#include <pthread.h>
#include <sys/queue.h>
#include "mtcp.h"
#include "memory_mgt.h"

typedef struct general_data_buffer {
	void *data;
	SLIST_ENTRY(general_data_buffer) gdb_link;
} general_data_buffer;

typedef struct general_data_buffer_pool {
	uint32_t buf_size;
	mem_pool_t mp;
	general_data_buffer *gdb_ptr;
	uint32_t num_buf;
	pthread_spinlock_t gdb_sl;
	SLIST_HEAD(, general_data_buffer) free_list;
} general_data_buffer_pool;

void
general_data_buffer_pool_create(mtcp_manager_t mtcp, uint32_t buf_size, uint32_t num_buf);

extern general_data_buffer *
general_data_buffer_alloc(mtcp_manager_t mtcp);

extern void
general_data_buffer_free(mtcp_manager_t mtcp, general_data_buffer *b);

extern uint32_t 
general_data_buffer_get_buf_size(mtcp_manager_t mtcp);

void
general_data_buffer_destroy(mtcp_manager_t mtcp);

#endif /* __GENERAL_DATA_BUFFER_H__ */

