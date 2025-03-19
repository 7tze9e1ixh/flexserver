#ifndef __CONFIG_H__
#define __CONFIG_H__
#include <stdint.h>
#include <rte_ether.h>
#include "core.h"

#define MAX_NB_DIR_PATH 128

typedef struct control_plane_config {
	uint16_t ncpus;
	uint16_t lcore_id[MAX_NB_CPUS];
	uint64_t max_nb_items;
	double max_nic_mem_size;
	uint64_t nb_reqs_thresh;
	uint64_t nb_offloads;
	uint16_t hashpower;

	char *dir_path[MAX_NB_DIR_PATH];
	uint16_t nb_dir_path;

	struct rte_ether_addr dpu_mac_addr;
	struct rte_ether_addr host_mac_addr;

	uint64_t l2cache_size;

	bool enable;

} control_plane_config;

void config_parse(char *conf_path);
void config_free(void);

extern control_plane_config CP_CONFIG;
#endif
