#include <stdlib.h>
#include <stdio.h>

#include "general_data_buffer.h"
#include "debug.h"

general_data_buffer_pool *g_general_data_buffer_pool[MAX_CPUS] = {NULL};

void
general_data_buffer_pool_create(mtcp_manager_t mtcp, uint32_t buf_size, uint32_t num_buf) {

	char tmpbuf[256];
	uint32_t i;
	general_data_buffer_pool *pool;

	pool = calloc(1, sizeof(general_data_buffer_pool));
	if (!pool) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	pool->buf_size = buf_size;

	sprintf(tmpbuf, "gdb-pool-%d", mtcp->ctx->cpu);
	pool->mp = MPCreate(tmpbuf, buf_size, (uint64_t)buf_size * num_buf);
	if (!pool->mp) {
		TRACE_ERROR("MPCreate()\n");
		exit(EXIT_FAILURE);
	}
	pthread_spin_init(&pool->gdb_sl, PTHREAD_PROCESS_PRIVATE);

	pool->gdb_ptr = calloc(num_buf, sizeof(general_data_buffer));
	if (!pool->gdb_ptr) {
		TRACE_ERROR("calloc()\n");
		exit(EXIT_FAILURE);
	}

	SLIST_INIT(&pool->free_list);
	for (i = 0; i < num_buf; i++) 
		SLIST_INSERT_HEAD(&pool->free_list, &pool->gdb_ptr[i], gdb_link);

	g_general_data_buffer_pool[mtcp->ctx->cpu] = pool;
}

inline general_data_buffer *
general_data_buffer_alloc(mtcp_manager_t mtcp) {

	general_data_buffer *gdb;
	general_data_buffer_pool *pool = g_general_data_buffer_pool[mtcp->ctx->cpu];

	pthread_spin_lock(&pool->gdb_sl);
	gdb = SLIST_FIRST(&pool->free_list);
	SLIST_REMOVE_HEAD(&pool->free_list, gdb_link);
	pthread_spin_unlock(&pool->gdb_sl);

	gdb->data = MPAllocateChunk(pool->mp);

	return gdb;
}

inline void
general_data_buffer_free(mtcp_manager_t mtcp, general_data_buffer *b) {

	general_data_buffer_pool *pool = g_general_data_buffer_pool[mtcp->ctx->cpu];

	MPFreeChunk(pool->mp, b->data);

	pthread_spin_lock(&pool->gdb_sl);
	SLIST_INSERT_HEAD(&pool->free_list, b, gdb_link);
	pthread_spin_unlock(&pool->gdb_sl);
}

inline uint32_t 
general_data_buffer_get_buf_size(mtcp_manager_t mtcp) {
	general_data_buffer_pool *pool = g_general_data_buffer_pool[mtcp->ctx->cpu];
	return pool->buf_size;
}

void
general_data_buffer_destroy(mtcp_manager_t mtcp) {

	general_data_buffer_pool *pool = g_general_data_buffer_pool[mtcp->ctx->cpu];
	pthread_spin_destroy(&pool->gdb_sl);
	free(pool->gdb_ptr);
	MPDestroy(pool->mp);
}
