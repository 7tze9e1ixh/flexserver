#include "config.h"

#define CONTROL_PLANE_CONFIGURATION "CONTROL_PLANE_CONFIGURATION"
#define DIRECTORY_PATH "DIRECTORY PATH"

control_plane_config CP_CONFIG = {
	.dir_path = {NULL},
};

const static char *control_plane_configuration[] = {
	"number of cpus",	// 0	
	"max nic cache memory size(GB)", // 1
	"max number of itmes", // 2 
	"number of requests to optimize cache", // 3
	"number of offloaded items", // 4
	"lcore id", // 5
	"dpu mac address", // 6
	"host mac address",
	"l2cache size"
};
const static char dir_path[] = "dir_path";

static int ParseLcoreId(const char *entry);
static int ParseDPUMacAddress(const char *entry);
static int ParseHostMacAddress(const char *entry);
static int ParseDirPath(const char *entry);

static int 
ParseLcoreId(const char *entry) {
	int i;
	char tmpbuf[512];
	char *p, *saveptr;

	strcpy(tmpbuf, entry);

	p = strtok_r(tmpbuf, ",", &saveptr);
	CP_CONFIG.lcore_id[0] = (uint16_t)TO_DECIMAL(p);

	for (i = 1; i < CP_CONFIG.ncpus; i++) {
		p = strtok_r(NULL, ":", &saveptr);
		if (!p) return -1;
		CP_CONFIG.lcore_id[i] = (uint16_t)TO_DECIMAL(p);
	}

	return 0;
}

static int
ParseDPUMacAddress(const char *entry) {
	char tmpbuf[512];
	char *p, *saveptr;
	int i;

	strcpy(tmpbuf, entry);

	p = strtok_r(tmpbuf, ":", &saveptr);
	CP_CONFIG.dpu_mac_addr.addr_bytes[0] = (uint8_t)TO_HEXADECIMAL(p);

	for (i=1; i < RTE_ETHER_ADDR_LEN; i++) {
		p = strtok_r(NULL, ":", &saveptr);
		if (!p) return -1;

		CP_CONFIG.dpu_mac_addr.addr_bytes[i] = (uint8_t)TO_HEXADECIMAL(p);
	}

	return 0;
}

static int
ParseHostMacAddress(const char *entry) {
	char tmpbuf[512];
	char *p, *saveptr;
	int i;

	strcpy(tmpbuf, entry);

	p = strtok_r(tmpbuf, ":", &saveptr);
	CP_CONFIG.host_mac_addr.addr_bytes[0] = (uint8_t)TO_HEXADECIMAL(p);

	for (i=1; i < RTE_ETHER_ADDR_LEN; i++) {
		p = strtok_r(NULL, ":", &saveptr);
		if (!p) return -1;

		CP_CONFIG.host_mac_addr.addr_bytes[i] = (uint8_t)TO_HEXADECIMAL(p);
	}

	return 0;

}

static int
ParseDirPath(const char *entry) {
	
	char tmpbuf[512];
	char *p, *saveptr;

	strcpy(tmpbuf, entry);
	p = strtok_r(tmpbuf, ",", &saveptr);
	CP_CONFIG.nb_dir_path = 0;

	while (p) {
		CP_CONFIG.dir_path[CP_CONFIG.nb_dir_path++] = strdup(p);
		p = strtok_r(NULL, ",", &saveptr);
	}

	return 0;
}

void
config_parse(char *conf_path) {
	const char *entry, *error_entry = NULL;
	int nb_entries, entry_index, ret;
	struct rte_cfgfile *cfgfile;

	cfgfile = rte_cfgfile_load(conf_path, CFG_FLAG_EMPTY_VALUES);
	if (!cfgfile) {
		rte_exit(EXIT_FAILURE,
				"Fail to load configuration file "
				"errno=%d (%s)\n",
				rte_errno, rte_strerror(rte_errno));
	}

	nb_entries = sizeof(control_plane_configuration) / sizeof(char *);

	for (entry_index = 0; entry_index < nb_entries; entry_index++) {
		entry = rte_cfgfile_get_entry(cfgfile, CONTROL_PLANE_CONFIGURATION, 
				control_plane_configuration[entry_index]);
		if (!entry) {
			error_entry = control_plane_configuration[entry_index];
			goto error;
		}

		switch(entry_index) {
			case 0 :
				CP_CONFIG.ncpus = (uint16_t)TO_DECIMAL(entry);
				break;
			case 1 :
				CP_CONFIG.max_nic_mem_size = TO_GB(TO_REAL_NUMBER(entry));
				break;
			case 2 : 
				CP_CONFIG.max_nb_items = (uint64_t)TO_DECIMAL(entry);
				break;
			case 3 :
				CP_CONFIG.nb_reqs_thresh = TO_DECIMAL(entry);
				break;
			case 4 :
				CP_CONFIG.nb_offloads = TO_DECIMAL(entry);
				break;
			case 5 :
				ret = ParseLcoreId(entry);
				if (ret < 0) goto error;
				break;
			case 6 : 
				ret = ParseDPUMacAddress(entry);
				if (ret < 0) goto error;
				break;
			case 7 :
				ret = ParseHostMacAddress(entry);
				if (ret < 0) goto error;
				break;
			case 8 :
				CP_CONFIG.l2cache_size = TO_GB(TO_REAL_NUMBER(entry));
				break;
			default :
				rte_exit(EXIT_FAILURE, 
						"Wrong entry (index=%d)\n", entry_index);
		}
	}

	entry = rte_cfgfile_get_entry(cfgfile, DIRECTORY_PATH, dir_path);
	if (!entry) {
		error_entry = dir_path;
		goto error;
	}

	ret = ParseDirPath(entry);
	if (ret < 0) {
		error_entry = dir_path;
		goto error;
	}

	if (CP_CONFIG.max_nic_mem_size == 0 && CP_CONFIG.l2cache_size == 0) {
		CP_CONFIG.enable = false;
	} else {
		CP_CONFIG.enable = true;
	}

	return;

error :
	rte_exit(EXIT_FAILURE, 
			"Fail to parse \"%15s\"\n", error_entry);
}

void
config_free(void) {
	/* TODO */
}
