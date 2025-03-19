#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_cfgfile.h>

#include "config.h"

#define CFG_SEC_DATAPLANE "DATAPLANE_CONFIGURATION"
#define CFG_SEC_DPDK "DPDK_CONFIGURATION"
#define CFG_SEC_HOST_MAC_ADDR "MAC_ADDR"

#define CFG_SEC_ENT_CACHE_MEM_SIZE	"total cache memory size (GB)"
#define CFG_SEC_ENT_MAX_NUMBER_OF_ITEMS "max number of items"
#define CFG_SEC_ENT_HASHPOWER "hash power"

#define CFG_SEC_ENT_NUM_CORES "total number of cores"
#define CFG_SEC_ENT_NUM_CORES_INDEX 2

#define CFG_SEC_ENT_HOST_MAC_ADDR "host mac address"

#define DPDK_ARGC 7
#define DPDK_ARGV_MAX_LEN 256

struct d_config d_CONFIG;

static void config_init(void);

static void
config_init(void) 
{
	int i;
	d_CONFIG.dpdk_argc = DPDK_ARGC;
	d_CONFIG.dpdk_argv = calloc(DPDK_ARGC, sizeof(char *));
	if (!d_CONFIG.dpdk_argv) {
		rte_exit(EXIT_FAILURE,
				"Fail to allocate memory for dpdk_argv, "
				"errno=%d (%s)\n", errno, strerror(errno));
	}

	for (i = 0; i < DPDK_ARGC; i++) {
		d_CONFIG.dpdk_argv[i] = malloc(DPDK_ARGV_MAX_LEN);
		if (!d_CONFIG.dpdk_argv[i]) {
			rte_exit(EXIT_FAILURE,
					"Fail to allocate memory for dpdk argv conf, "
					"errno=%d (%s)\n", errno, strerror(errno));
		}
	}
	strcpy(d_CONFIG.dpdk_argv[0], "");
	strcpy(d_CONFIG.dpdk_argv[1], "-l"); //argv[2] will be filled in config_parse
	strcpy(d_CONFIG.dpdk_argv[3], "--iova-mode");
	strcpy(d_CONFIG.dpdk_argv[4], "va"); // --iova-mode <pa|va>
	strcpy(d_CONFIG.dpdk_argv[5], "-a");
	strcpy(d_CONFIG.dpdk_argv[6], "03:00.0");
}

#define ENT_BUF_SZ 256

const char *
_get_entry(struct rte_cfgfile *cfg, const char *section, const char *entry_name)
{
	const char *entry;
	entry = rte_cfgfile_get_entry(cfg, section, entry_name);
	if (!entry) {
		rte_exit(EXIT_FAILURE, "Fail to parse entry %s\n", entry_name);
	}
	return entry;
}

void
config_parse(char cfg_file_path[]) {

	const char *entry;
	struct rte_cfgfile *f_cfg;
	char ent_buf[ENT_BUF_SZ];
	char *p, *saveptr;
	int i;

	config_init();

	f_cfg = rte_cfgfile_load(cfg_file_path, CFG_FLAG_EMPTY_VALUES);
	if (!f_cfg) {
		rte_exit(EXIT_FAILURE,
				"Fail to open configuration file %s, "
				"errno=%d (%s)\n",
				cfg_file_path, rte_errno, rte_strerror(rte_errno));
	}

	entry = _get_entry(f_cfg, CFG_SEC_DATAPLANE, CFG_SEC_ENT_CACHE_MEM_SIZE);
	d_CONFIG.tot_cache_mem_sz = strtod(entry, NULL) * 1024 * 1024 * 1024;

	entry = _get_entry(f_cfg, CFG_SEC_DATAPLANE, CFG_SEC_ENT_MAX_NUMBER_OF_ITEMS);
	d_CONFIG.max_nb_items = strtol(entry, NULL, 10);

	entry = _get_entry(f_cfg, CFG_SEC_DATAPLANE, CFG_SEC_ENT_HASHPOWER);
	d_CONFIG.hash_power = strtol(entry, NULL, 10);

	entry = _get_entry(f_cfg, CFG_SEC_DPDK, CFG_SEC_ENT_NUM_CORES);
	d_CONFIG.ncpus = strtol(entry, NULL, 10);

	if (d_CONFIG.ncpus > 1) {
		sprintf(d_CONFIG.dpdk_argv[CFG_SEC_ENT_NUM_CORES_INDEX], "0-%d", d_CONFIG.ncpus - 1);
	} else {
		sprintf(d_CONFIG.dpdk_argv[CFG_SEC_ENT_NUM_CORES_INDEX], "%d", d_CONFIG.ncpus - 1);
	}

	entry = _get_entry(f_cfg, CFG_SEC_HOST_MAC_ADDR, CFG_SEC_ENT_HOST_MAC_ADDR);
	memcpy(ent_buf, entry, ENT_BUF_SZ);

	p = strtok_r(ent_buf, ":", &saveptr);
	d_CONFIG.host_mac_addr.addr_bytes[0] = (uint8_t)strtol(p, NULL, 16);

	for (i = 1; i < RTE_ETHER_ADDR_LEN; i++) {
		p = strtok_r(NULL, ":", &saveptr);
		if (!p) {
			rte_exit(EXIT_FAILURE,
					"Format of %s must be xx:xx:xx:xx:xx:xx\n", CFG_SEC_ENT_HOST_MAC_ADDR);
		}
		d_CONFIG.host_mac_addr.addr_bytes[i] = (uint8_t)strtol(p, NULL, 16);
	}

	if (rte_cfgfile_close(f_cfg) < 0) {
		rte_exit(EXIT_FAILURE,
				"Fail to close configuration file \n");
	}
}

void 
config_free(void)
{
	int i;
	for (i = 1; i < d_CONFIG.dpdk_argc; i++)
		free(d_CONFIG.dpdk_argv[i]);
	free(d_CONFIG.dpdk_argv);
}
