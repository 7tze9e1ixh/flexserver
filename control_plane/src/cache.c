#include <rte_spinlock.h>

#include "core.h"
#include "cache.h"
#if (HOST_HYPERBOLIC || NIC_HYPERBOLIC)
#include "cache/hyperbolic.h"
#elif (HOST_LFU || NIC_LFU)
#include "cache/lfu.h"
#else
#include "cache/lru.h"
#endif
#include "debug.h"
#include "config.h"

struct cache_ctrl {
	size_t cache_mem_sz;
	uint32_t nb_free_blks;
	uint32_t tot_nb_blks;
	rte_spinlock_t sl;
	size_t blk_dat_sz;
};

static struct cache_ctrl ctrl;

cache_method *
cache_create(void *arg, enum cache_type ct, void **cache) 
{

	cache_method *cm;

	cm = calloc(1, sizeof(cache_method));
	if (!cm) {
		rte_exit(EXIT_FAILURE,
				"Fail to allocate some memory to cache_method, "
				"rte_errno : %d, %s\n", rte_errno, rte_strerror(rte_errno));
	}

	if (ct == AT_DISK) {
		//strcpy(cm->name, "Disk");
#if HOST_HYPERBOLIC 
		uint32_t sample_size = HYPERBOLIC_SAMPLE_SIZE;
		*cache = hyperbolic_cache_setup("DISK", &sample_size);
		cm->insert = hyperbolic_cache_insert;
		cm->delete = hyperbolic_cache_delete;
		cm->get_oc = hyperbolic_cache_offloading_candidate;
		cm->get_ec = NULL;
		cm->access = hyperbolic_cache_access_item;
		cm->free = hyperbolic_cache_free_item;
		cm->show_all = hyperbolic_show_all;
#elif HOST_LFU
		*cache = lfu_cache_setup(arg);
		cm->insert = lfu_cache_insert;
		cm->delete = lfu_cache_delete;
		cm->get_oc = lfu_cache_offloading_candidate;
		cm->get_ec = NULL;
#else
		*cache = lru_cache_setup(arg);
		cm->insert = lru_cache_insert;
		cm->delete = lru_cache_delete;
		cm->get_oc = lru_cache_offloading_candidate;
		cm->get_ec = NULL;;
#endif
	} else if (ct == NIC_CACHE) {
		//strcpy(cm->name, "L1 Cache");
#if NIC_HYPERBOLIC
		uint32_t sample_size = HYPERBOLIC_SAMPLE_SIZE;
		*cache = hyperbolic_cache_setup("L1_CACHE", &sample_size);
		cm->insert = hyperbolic_cache_insert;
		cm->delete = hyperbolic_cache_delete;
		cm->get_oc = NULL;
		cm->get_ec = hyperbolic_cache_eviction_candidate;
		cm->access = hyperbolic_cache_access_item;
		cm->free = hyperbolic_cache_free_item;
		cm->show_all = hyperbolic_show_all;
#elif NIC_LFU
		*cache = lfu_cache_setup(arg);
		cm->insert = lfu_cache_insert;
		cm->delete = lfu_cache_delete;
		cm->get_oc = NULL;
		cm->get_ec = lfu_cache_eviction_candidate;
#else
		*cache = lru_cache_setup(arg);
		cm->insert = lru_cache_insert;
		cm->delete = lru_cache_delete;
		cm->get_oc = NULL;
		cm->get_ec = lru_cache_eviction_candidate;
#endif
	} else if (ct == HOST_CACHE) {
		//strcpy(cm->name, "L2 Cache");
#if NIC_HYPERBOLIC
		uint32_t sample_size = HYPERBOLIC_SAMPLE_SIZE;
		*cache = hyperbolic_cache_setup("L2_CACHE", &sample_size);
		cm->insert = hyperbolic_cache_insert;
		cm->delete = hyperbolic_cache_delete;
		cm->get_oc = hyperbolic_get_oc_for_control_plane;
		cm->get_ec = hyperbolic_cache_eviction_candidate;
		cm->access = hyperbolic_cache_access_item;
		cm->free = hyperbolic_cache_free_item;
		cm->show_all = hyperbolic_show_all;
#elif NIC_LFU
        *cache = lfu_cache_setup(arg);
        cm->insert = lfu_cache_insert;
        cm->delete = lfu_cache_delete;
        cm->get_oc = lfu_cache_offloading_candidate;
        cm->get_ec = lfu_cache_eviction_candidate;
#else
        *cache = lru_cache_setup(arg);
        cm->insert = lru_cache_insert;
        cm->delete = lru_cache_delete;
        cm->get_oc = lru_cache_offloading_candidate;
        cm->get_ec = lru_cache_eviction_candidate;
#endif
	} else {
		rte_exit(EXIT_FAILURE, "Wrong cache type : %d\n", (int)ct);
	}
	return cm;
}

void
cache_destroy(void *cache) 
{
#if (HOST_HYPERBOLIC || NIC_HYPERBOLIC)
	hyperbolic_cache_destroy(cache);
#elif (HOST_LFU || NIC_LFU)
	lfu_cache_destroy(cache);
#else
	lru_cache_delete(cache);
#endif
}

struct blk_meta_s {
	void *b_next;
	uint16_t b_seq;
	rte_iova_t b_iova;
} __rte_packed;

void
cache_ctrl_setup(void) 
{
	ctrl.blk_dat_sz = DATAPLANE_BLOCK_SIZE;
	ctrl.cache_mem_sz = (size_t)CP_CONFIG.max_nic_mem_size;
	ctrl.nb_free_blks = ctrl.cache_mem_sz / (DATAPLANE_BLOCK_SIZE + sizeof(struct blk_meta_s));
	ctrl.tot_nb_blks = ctrl.nb_free_blks;
	rte_spinlock_init(&ctrl.sl);

	LOG_INFO("Configuration of SmartNIC Memory Block\n");
	LOG_INFO("---------------------------------------------\n");
	LOG_INFO("Total Block Size : %lu\n", ctrl.cache_mem_sz);
	LOG_INFO("Single Block Size : %lu\n", ctrl.blk_dat_sz);
	LOG_INFO("Total number of block : %u\n", ctrl.tot_nb_blks);
	LOG_INFO("Total Enable Data Size : %.2f\n", (float)ctrl.nb_free_blks * ctrl.blk_dat_sz / (1024 * 1024));
	LOG_INFO("---------------------------------------------\n");
}

int
cache_ctrl_consume_blocks(item *it)
{
	uint32_t nb_blks;

	rte_spinlock_lock(&ctrl.sl);
	nb_blks = (it->sv->sz + ctrl.blk_dat_sz - 1) / ctrl.blk_dat_sz; // Ceiling integer division (it->sv->sz / ctrl.blk_dat_sz)

	if (nb_blks > ctrl.nb_free_blks) {
		rte_spinlock_unlock(&ctrl.sl);
		return -1;
	}

	ctrl.nb_free_blks -= nb_blks;
	assert((int)ctrl.nb_free_blks >= 0);
	rte_spinlock_unlock(&ctrl.sl);

	PRINT_BLOCK_STATUS("Consume %u blocks, remain : %u\n", 
			nb_blks, (uint32_t)ctrl.nb_free_blks);

	return 0;
}

void
cache_ctrl_free_blocks(item *it)
{
	uint32_t nb_blks;

	rte_spinlock_lock(&ctrl.sl);
	nb_blks = (it->sv->sz + ctrl.blk_dat_sz - 1) / ctrl.blk_dat_sz;
	ctrl.nb_free_blks += nb_blks;
	assert((int)ctrl.nb_free_blks <= (int)ctrl.tot_nb_blks);
	rte_spinlock_unlock(&ctrl.sl);

	PRINT_BLOCK_STATUS("Free %u blocks, remain : %u\n",
			nb_blks, (uint32_t)ctrl.nb_free_blks);
}

void
cache_ctrl_teardown(void)
{
	rte_spinlock_unlock(&ctrl.sl);
}

inline uint32_t 
cache_ctrl_get_free_blocks(void) {
	uint32_t nb_free_blks;
	rte_spinlock_lock(&ctrl.sl);
	nb_free_blks = ctrl.nb_free_blks;
	rte_spinlock_unlock(&ctrl.sl);
	return nb_free_blks;
}
