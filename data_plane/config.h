#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdint.h>
#include <rte_ether.h>

/* CONFIG for Dataplane*/

struct d_config {
	/* Memory Configuration */
	double tot_cache_mem_sz;
	size_t max_nb_items;
	int hash_power;

	int ncpus;

	int dpdk_argc;
	char **dpdk_argv;

	struct rte_ether_addr host_mac_addr;
};

extern struct d_config d_CONFIG;

void config_parse(char *cfg_file_path);
void config_free(void);

#endif
