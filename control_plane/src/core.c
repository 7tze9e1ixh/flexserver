#include "control_plane.h"
#include "core.h"
#include "config.h"
#include "item.h"
#include "item_mp.h"
#include "cache.h"
#include "hashtable.h"
#include "debug.h"
#include "net.h"
#include "item_queue.h"

#define DBG_CORE FALSE

#if DBG_CORE
#define TRACE_CORE(f, ...) fprintf(stderr, "(%10s:%4d) " f, __func__, __LINE__, ##__VA_ARGS__)
#else
#define TRACE_CORE(f, ...) UNUSED(0)
#endif

/* static value */
static private_context *g_private_context[MAX_NB_CPUS] = {NULL};
static optim_cache_context *g_oc_ctx[MAX_NB_CPUS] = {NULL};
_Atomic int64_t g_tot_reqs = 0;

static cache_method *cm_dataplane = NULL; /* Cache manager for offloaded object 
											 (Layer 1 cache) */
static cache_method *cm_control_plane = NULL;  /* Cache manager for object at control_plane block 
											  (Layer 2 cache)  */
static cache_method *cm_disk = NULL; /* Cache manager for objects at disk
											   (for offloading candidate) */
static void *dataplane = NULL;
static void *control_plane = NULL;
static void *disk = NULL;
static rte_atomic32_t g_nb_optim_cache_tasks;
static bool run_optim_cache = true;
static pthread_mutex_t mutex_optim_cache = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_optim_cache = PTHREAD_COND_INITIALIZER;
static bool is_ready = false;
static bool mtcp_master_thread_ready = false;

bool g_active_l1_cache = true;
bool g_active_l2_cache = true;
uint32_t g_jhash_initval;
uint32_t g_crc_hash_initval;

bool heat_dataplane = false;

#if DBG_SINGLE_CLIENT
static item *g_it_prev = NULL;
#endif

#if OFFLOADING_EVICTION_TEST
/* Test whether the offloading & eviction work well or not */
static void *OffloadingEvictionTestThread(void *opaque);
#define RUN_OFFLOADING_EVICTION_TEST(_test_it) do {\
	int _ret;\
	pthread_t _test_thread;\
	_ret = pthread_create(&_test_thread, NULL, OffloadingEvictionTestThread, (_test_it));\
	if (_ret < 0) {\
		LOG_ERROR("Fail to create OffloadingEvictionTestThread\n");\
		exit(EXIT_FAILURE);\
	}\
	pthread_join(_test_thread, NULL);\
	LOG_INFO("Complete Offloading-Eviction Test\n");\
} while(0)
#else
#define RUN_OFFLOADING_EVICTION_TEST(_test_it) UNUSED(0)
#endif

const static char *o_suffix[] = {
	".html",
	".m4s",
};

/* static function */
static bool CheckSuffix(const char filename[]);
static void HeatDataplane(void);
static optim_cache_context *CreateOptimCachePrivateContext(uint16_t core_index);
static void DestroyOptimCachePrivateContext(optim_cache_context *oc_ctx);
static void EvictItems(optim_cache_context *oc_ctx);
static void OffloadItems(optim_cache_context *oc_ctx);
static void SignalToOptimCache(void);

#if SET_CORE_AFFINITY
static int OptimCache(void *opaque);
#else
static void *OptimCache(void *opaque);
#endif

#define CONTROL_PLANE_CONFIG_PATH "config/control_plane.cfg"
#define MASTER_CORE_INDEX 0

#define SHOW_STATISTICS FALSE

#if SHOW_STATISTICS
static bool showStatWait = true;

#define STATS_PERIOD 1

struct control_plane_stats g_stats = {0};

static void *
ShowStatistics(void *arg) {

	//struct control_plane_stats stats_prev = {0};

	while(showStatWait) {

		usleep(SEC_TO_USEC(STATS_PERIOD));
#ifdef _CHECK_DUP
		printf("num_offload:%4lu(dup:%4lu,pkts#:%4lu,lat:%4.2fs), "
				"num_evict:%4lu(dup:%4lu,pkts#:%4lu, lat:%4.2fs)\n",
				g_stats.num_offloads, g_stats.num_offload_dups,
				g_stats.num_offload_pkts, 
				(float)(g_stats.sum_offload_lat) / g_stats.num_offload_pkts / 1000000,
				g_stats.num_evicts, g_stats.num_evict_dups, 
				g_stats.num_evict_pkts, 
				(float)(g_stats.sum_evict_lat) / g_stats.num_evict_pkts / 1000000);

		//memcpy(&stats_prev, &g_stats, sizeof(struct control_plane_stats));
#endif
	}

	return NULL;
}
#endif /* SHOW_STATISTICS */

static bool
CheckSuffix(const char filename[]) {
	int nb_o_suffix, i, ret;
	char *suffix;
	nb_o_suffix = sizeof(o_suffix) / sizeof(char *);

	suffix = strchr(filename, '.');
	if (!suffix)
		return false;

	for (i = 0; i < nb_o_suffix; i++) {
		ret = strncmp(suffix, o_suffix[i], sizeof(o_suffix[i]) - 1);
		if (ret == 0)
			return true;
	}

	return false;
}

#if OFFLOADING_EVICTION_TEST
static void *
OffloadingEvictionTestThread(void *opaque) {
	uint32_t nb_blks_before_eviction, nb_blks_after_eviction;
	uint32_t count = 0;
	struct optim_cache_context *oc_ctx = g_oc_ctx[MASTER_CORE_INDEX];
	item *test_it = (item *)opaque;

	TEST_BACKOFF_SLEEP();

	LOG_INFO("Run Offloading-Eviction Test...");

	while (count < MAX_TEST_COUNT) {
		nb_blks_before_eviction = cache_ctrl_get_free_blocks();
		fprintf(stderr, "[Before Eviction] \n"
				"Total Number of Free Blocks = %u\n "
				"Required Number of Offloading Candidate = %u\n "
				"Timestamp(ms) = %u\n "
				"# of reqs = %u\n",
				nb_blks_before_eviction,
				GET_NB_BLK(test_it->sv->sz),
				test_it->vv->ts_ms,
				test_it->vv->n_requests);


		cm_dataplane->delete(dataplane, test_it);
		rb_tree_insert(oc_ctx->ec_wait, test_it);

		EvictItems(oc_ctx);
		TEST_BACKOFF_SLEEP();

		item_enqueue(oc_ctx->ocq, test_it);
		OffloadItems(oc_ctx);

		nb_blks_after_eviction = cache_ctrl_get_free_blocks();

		fprintf(stderr, "[After Eviction] \n"
				"Total Number of Free Blocks = %u\n "
				"Required Number of Offloading Candidate = %u\n "
				"Timestamp(ms) = %u\n "
				"# of reqs = %u\n",
				nb_blks_after_eviction,
				GET_NB_BLK(test_it->sv->sz),
				test_it->vv->ts_ms,
				test_it->vv->n_requests);
		/* Check DPU memory consistency at host */
		assert(nb_blks_before_eviction == nb_blks_after_eviction);
		count++;
	}

	return NULL;
}
#endif
/*
 * return -1 : Not enough block i
 *	      >0 : Number of used block 
 * */
static int
GeneratePayloadBlock(optim_cache_context *ctx, item *it) {

	int numBlocks = 0;
	int fd;
	size_t toRead;
	ssize_t numRead;
	//off_t offset = 0;
	int i;
	block *b = NULL, *prev = NULL;

	assert(it->numBlocks == -1);
	numBlocks = GET_NB_BLK(it->sv->sz);
	if (numBlocks > ctx->bp->numFree)  {
		//LOG_ERROR("Not enough block, # of free : %lu\n", ctx->bp->numFree);
		return -1;
	}

	fd = open(it->key, O_RDONLY);
	if (fd < 0 && errno != EAGAIN) {
		LOG_ERROR("Fail to open %s for control plane cache blokc "
				"errno=%d (%s)\n", it->key, errno, strerror(errno));
		exit(EXIT_FAILURE);
	} 

	assert(numBlocks <= MAX_IOV);

	toRead = it->sv->sz;

	for (i = 0; i < numBlocks; i++) {
		b = block_alloc(ctx->bp);
		assert(b);
		ctx->iov[i].iov_base = b->data;
		ctx->iov[i].iov_len = RTE_MIN(ctx->bp->blockSize,
				toRead - i * ctx->bp->blockSize);

		it->block_map[i] = b;
		b->meta.seq = i;

		if (prev)
			prev->meta.next = b;
		prev = b;
	}

	numRead = readv(fd, ctx->iov, numBlocks);
	assert(numRead == it->sv->sz);

	b->meta.next = NULL;
	it->numBlocks = numBlocks;

	close(fd);

	return numBlocks;
}

static void
FreePayloadBlock(optim_cache_context *ctx, item *it) {

	int i;
	assert(it->numBlocks >= 1);
	for (i = 0 ; i < it->numBlocks; i++) 
		block_free(ctx->bp, it->block_map[i]);

	it->numBlocks = -1;
}

static void
HeatDataplane(void) {
	int i, ret;
	DIR *dir;
	struct dirent *ent;
	char path_buf[512];
	uint32_t nb_required_blks;
	optim_cache_context *oc_ctx;
	int numOffload = 0, numL2Cached = 0, numAtDisk = 0;

	for (i = 0; i < (int)CP_CONFIG.nb_dir_path; i++) {
		dir = opendir(CP_CONFIG.dir_path[i]);

		if (!dir) {
			LOG_ERROR("Fail to open directory(%s) errno=%d (%s)\n", 
					CP_CONFIG.dir_path[i], errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		item *ret_it;
		int core_index, path_len;
		private_context *ctx;

		while ((ent = readdir(dir))) {
			if (!CheckSuffix(ent->d_name)) // read only .html or .m4s
				continue;

			path_len = sprintf(path_buf, "%s/%s", CP_CONFIG.dir_path[i], ent->d_name);
			if (path_len < 0) {
				perror("Fail to generate absolute path for object");
				exit(EXIT_FAILURE);
			}

#if SET_CORE_AFFINITY
			core_index = CAL_HV(path_buf, path_len) % CP_CONFIG.ncpus;
#else
			core_index = 0;
#endif
			ctx = g_private_context[core_index];

			ret = hashtable_put(ctx, path_buf, path_len, &ret_it);
			if (ret < 0) {
				LOG_ERROR("Fail to insert object at hashtable, %d\n", ret);
				exit(EXIT_FAILURE);
			}
			oc_ctx = g_oc_ctx[core_index];
			nb_required_blks = GET_NB_BLK(ret_it->sv->sz);
#if DBG_INACTIVE
			map_item[map_size++] = ret_it;
#endif
			
			if (nb_required_blks <= cache_ctrl_get_free_blocks()) {
				cache_ctrl_consume_blocks(ret_it);
				GET_CUR_US(ret_it->ts);
				rb_tree_insert(oc_ctx->oc_wait, ret_it);
				numOffload++;
				//LOG_INFO("%s\n", ret_it->key);
				if (numOffload % 1000 == 0)
					LOG_INFO("%dth item is at l1-cache\n", numOffload);
			} else {
				ret = GeneratePayloadBlock(oc_ctx, ret_it);
				if (ret > 0) {
					item_set_state(ret_it, ITEM_STATE_AT_L2_CACHE);
					cm_control_plane->insert(control_plane, ret_it);
					numL2Cached++;

					if (numL2Cached % 10000 == 0)
						LOG_INFO("%dth item is l2-cached\n", numL2Cached);

					if (numL2Cached == 1)
						printf("At L2_CACHE : %s\n", ret_it->key);

				} else {
					item_set_state(ret_it, ITEM_STATE_AT_DISK);
					cm_disk->insert(disk, ret_it);
					numAtDisk++;

					if (numAtDisk % 100000 == 0)
						LOG_INFO("%dth item is at disk\n", numAtDisk);
					if (numAtDisk == 1) 
						printf("At DISK : %s\n", ret_it->key);
				}
			}

#if DUMP_OBJ_URL_AND_HV
			fprintf(obj_fp, "url:%s, hv:%lu\n", ret_it->key, ret_it->sv->hv);
#endif
			RUN_OFFLOADING_EVICTION_TEST(ret_it);
		}
		closedir(dir);
	}
	OffloadItems(oc_ctx);
	LOG_INFO("HEAT DATAPLANE Completes, At L1-Cache : %d, At L2-Cache : %d, At Disk : %d\n", 
			numOffload, numL2Cached, numAtDisk);
#if DBG_HT
	hashtable_show_bucket_size();
#endif

#if DBG_REF_CNT
#if DUMP_OBJ_URL_AND_HV
	fclose(obj_fp);
#endif
#endif

#if DBG_CACHE
	DBG_TRACE("L1 Cache -------------------\n");
	cm_dataplane->show_all(dataplane);
	DBG_TRACE("L2 Cache -------------------\n");
	cm_control_plane->show_all(control_plane);
	DBG_TRACE("Disk -----------------------\n");
	cm_disk->show_all(disk);
#endif

#if _CHECK_DUP
	g_stats.sum_evict_lat = g_stats.sum_offload_lat = g_stats.num_offload_pkts = 0;
#endif
}

static optim_cache_context *
CreateOptimCachePrivateContext(uint16_t core_index) {

	optim_cache_context *oc_ctx;

	oc_ctx = malloc(sizeof(optim_cache_context));
	if (!oc_ctx) {
		perror("Fail to allocate memory for optim_cache_context");
		return NULL;
	}

	oc_ctx->ec_wait = rb_tree_create(item_cmp_hv, item_get_hv);
	if (!oc_ctx->ec_wait) 
		return NULL;

	oc_ctx->oc_wait = rb_tree_create(item_cmp_hv, item_get_hv);
	if (!oc_ctx->oc_wait)
		return NULL;

	oc_ctx->pktmbuf_pool = rte_pktmbuf_pool_create("Offload-pktmbuf-pool",
			NB_MBUFS, RTE_CACHE_LINE_SIZE, 0, PKTMBUF_SIZE, rte_socket_id());
	if (!oc_ctx->pktmbuf_pool) {
		LOG_ERROR("Fail to create pktmbuf_pool for offload\n");
		return NULL;
	}

	oc_ctx->ocq = item_queue_create();
	if (!oc_ctx->ocq)
		return NULL;

	oc_ctx->koq = item_queue_create();
	if (!oc_ctx->koq) 
		return NULL;

	oc_ctx->orq = malloc(sizeof(offload_reply_queue));
	if (!oc_ctx->orq) {
		return NULL;
	}
	pthread_mutex_init(&oc_ctx->orq->mutex, NULL);
	pthread_cond_init(&oc_ctx->orq->cond, NULL);
	oc_ctx->orq->len = 0;
	oc_ctx->orq->proc = false;

	oc_ctx->erq = malloc(sizeof(eviction_reply_queue));
	if (!oc_ctx->erq) {
		return NULL;
	}
	pthread_mutex_init(&oc_ctx->erq->mutex, NULL);
	pthread_cond_init(&oc_ctx->erq->cond, NULL);
	oc_ctx->erq->len = 0;
	oc_ctx->erq->proc = false;

	oc_ctx->rehv = calloc(1, sizeof(struct rx_e_hv));
	if (!oc_ctx->rehv)
		return NULL;

	oc_ctx->compl_ohv = calloc(1, sizeof(struct rx_e_hv));
	if (!oc_ctx->compl_ohv) 
		return NULL;

	oc_ctx->tpq = malloc(sizeof(struct tx_pkt_queue));
	if (!oc_ctx->tpq) 
		return NULL;
	//rte_spinlock_init(&oc_ctx->tpq->sl);
	oc_ctx->tpq->len = 0;
	pthread_mutex_init(&oc_ctx->tpq->mutex, NULL);
	//pthread_cond_init(&oc_ctx->tpq->cond, NULL);

	oc_ctx->core_index = core_index;

	oc_ctx->bp = block_create_pool(core_index, CP_CONFIG.l2cache_size);
	if (!oc_ctx->bp) 
		return NULL;
		

	return oc_ctx;
}

static void
DestroyOptimCachePrivateContext(optim_cache_context *oc_ctx) {

	pthread_mutex_destroy(&oc_ctx->tpq->mutex);
	free(oc_ctx->tpq);

	free(oc_ctx->rehv);

	pthread_cond_destroy(&oc_ctx->erq->cond);
	pthread_mutex_destroy(&oc_ctx->erq->mutex);
	free(oc_ctx->erq);

	pthread_cond_destroy(&oc_ctx->orq->cond);
	pthread_mutex_destroy(&oc_ctx->orq->mutex);
	free(oc_ctx->orq);

	rte_mempool_free(oc_ctx->pktmbuf_pool);

	rb_tree_destroy(oc_ctx->oc_wait);
	free(oc_ctx->compl_ohv);

	rb_tree_destroy(oc_ctx->ec_wait);

	block_pool_destroy(oc_ctx->bp);

	item_queue_destroy(oc_ctx->koq);

	free(oc_ctx);
}

inline static void 
EvictItems(optim_cache_context *oc_ctx) {

	int i;
	if (rb_tree_is_empty(oc_ctx->ec_wait))
		return;

	net_send_eviction_message(oc_ctx);
	for (i = 0; i < oc_ctx->rehv->len; i++) {
		uint16_t state;
		item *it; 
		it = hashtable_get_with_hv(oc_ctx->rehv->e_hv[i], &state);

		//LOG_INFO("Evict object (hv=%lu, url=%s)\n", it->sv->hv, it->key);
		assert(it);
		assert(state == ITEM_STATE_AT_NOWHERE);

		GET_CUR_MS(it->vv->ts_ms);
		it->vv->n_requests = 0;
#if DBG_REF_CNT
		uint32_t r_cnt = rte_atomic32_read(&it->vv->refcount);
		assert(r_cnt == 0);
#endif

		TRACE_CORE("%s\n", it->key);

		/* Move object to L2 Cache */
		/* 1. Free L1_CACHE memory block
		 * 2. Change State
		 * 3. Register to cache manager 
		 * */
//		cm_control_plane->insert(control_plane, it);
		
		if (g_active_l1_cache && !g_active_l2_cache) {
			item_set_state(it, ITEM_STATE_AT_DISK);
			cm_disk->insert(disk, it);
		}

		cache_ctrl_free_blocks(it);
		assert(cache_ctrl_get_free_blocks() >= GET_NB_BLK(it->sv->sz));
		//LOG_INFO("Evict object (hv=%lu, url=%s)\n", it->sv->hv, it->key);
	}

	oc_ctx->rehv->len = 0;
}

inline static void
OffloadItems(optim_cache_context *oc_ctx) {

	item *oc;
	int i;
	net_send_offloading_message(oc_ctx);
	uint64_t cur_ms;
	GET_CUR_MS(cur_ms); //

	for (i = 0; i < oc_ctx->compl_ohv->len; i++) {
		uint16_t state;
		oc = hashtable_get_with_hv(oc_ctx->compl_ohv->e_hv[i], &state);
		assert(oc);
		item_set_state(oc, ITEM_STATE_AT_L1_CACHE);
		//GET_CUR_MS(oc->vv->ts_ms);
		oc->vv->ts_ms = cur_ms; //
		cm_dataplane->insert(dataplane, oc);

		TRACE_CORE("%s\n", oc->key);
		
		if (heat_dataplane)
			cache_ctrl_consume_blocks(oc);
	}
	oc_ctx->compl_ohv->len = 0;
}

static void
__only_L1_CACHE(optim_cache_context *oc_ctx) {

	item *oc, *ec;	
	size_t sum_oc_size = 0;
	int num_ocs = 0, num_ec_blks, num_blks, num_ecs = 0;

	while (num_ocs < CP_CONFIG.nb_offloads) {
		oc = cm_disk->get_oc(disk);
		GET_CUR_US(oc->ts);
		item_set_state(oc, ITEM_STATE_WAITING_FOR_L1_OPTIM_CACHE);
		rb_tree_insert(oc_ctx->oc_wait, oc);
		sum_oc_size += oc->sv->sz;
		num_ocs++;
#if _CHECK_DUP
		oc->evict_proc = 0;
		oc->offload_proc = 0;
		oc->num_cmd = 0;
#endif
	}
#ifdef _CHECK_DUP
		g_stats.num_offloads += num_ocs;
#endif

	num_blks = GET_NB_BLK(sum_oc_size) - cache_ctrl_get_free_blocks();

	while (num_blks > 0) {
		ec = cm_dataplane->get_ec(dataplane);
		GET_CUR_US(ec->ts);
		num_ec_blks= GET_NB_BLK(ec->sv->sz);
		num_blks -= num_ec_blks;
		rb_tree_insert(oc_ctx->ec_wait, ec);
		num_ecs++;
#if _CHECK_DUP
		ec->evict_proc = 0;
		ec->offload_proc = 0;
		ec->num_cmd = 0;
#endif
	}
#ifdef _CHECK_DUP
	g_stats.num_evicts += num_ecs;
#endif

	EvictItems(oc_ctx);
	OffloadItems(oc_ctx);
}

static void
__only_L2_CACHE(optim_cache_context *oc_ctx) {

	item *oc, *ec;
	size_t sum_oc_size = 0;
	int num_ocs = 0, num_ec_blks, num_blks;

	while (num_ocs < CP_CONFIG.nb_offloads) {
		oc = cm_disk->get_oc(disk);
		item_enqueue(oc_ctx->ocq, oc);
		sum_oc_size += oc->sv->sz;
		num_ocs++;
	}

	num_blks = GET_NB_BLK(sum_oc_size) - oc_ctx->bp->numFree;

	while (num_blks > 0) {

		ec = cm_control_plane->get_ec(control_plane);
		num_ec_blks = GET_NB_BLK(ec->sv->sz);
		num_blks -= num_ec_blks;

		FreePayloadBlock(oc_ctx, ec);
		item_set_state(ec, ITEM_STATE_AT_DISK);
		GET_CUR_MS(ec->vv->ts_ms);
		ec->vv->n_requests = 0;

		cm_disk->insert(disk, ec);
	}

	while ((oc = item_dequeue(oc_ctx->ocq))) {

		assert(GeneratePayloadBlock(oc_ctx, oc) > 0);
		item_set_state(oc, ITEM_STATE_AT_L2_CACHE);
		oc->vv->n_requests = 0;
		GET_CUR_MS(oc->vv->ts_ms);

		cm_control_plane->insert(control_plane, oc);
	}

#if DBG_CORE
	TRACE_CORE("L2_CACHE's");
	cm_control_plane->show_all(control_plane);
	TRACE_CORE("DISK's");
	cm_disk->show_all(disk);
#endif

	sleep(1);
}

static void
__both_L1_and_L2_CACHE(optim_cache_context *oc_ctx) {

	item *oc, *ec;
	size_t sum_oc_size = 0;
	int num_ocs = 0, num_ec_blks, num_blks, num_l2_blks = 0;

	while (num_ocs < CP_CONFIG.nb_offloads) {
		oc = cm_control_plane->get_oc(control_plane);
		GET_CUR_US(oc->ts);
		rb_tree_insert(oc_ctx->oc_wait, oc);
		sum_oc_size += oc->sv->sz;
		num_ocs++;
		FreePayloadBlock(oc_ctx, oc);
	}

	num_blks = GET_NB_BLK(sum_oc_size) - cache_ctrl_get_free_blocks();

	while (num_blks > 0) {
		ec = cm_dataplane->get_ec(dataplane);
		GET_CUR_US(ec->ts);
		num_ec_blks = GET_NB_BLK(ec->sv->sz);
		num_blks -= num_ec_blks;
		rb_tree_insert(oc_ctx->ec_wait, ec);
		item_enqueue(oc_ctx->koq, ec);
		num_l2_blks += num_ec_blks;
	}

	EvictItems(oc_ctx);
	OffloadItems(oc_ctx);

	sum_oc_size = 0;
	num_ocs = 0;

	while (num_ocs < CP_CONFIG.nb_offloads * NUM_L2_CACHE_OFFLOADS_SCALE) {
		oc = cm_disk->get_oc(disk);
		item_enqueue(oc_ctx->ocq, oc);
		sum_oc_size += oc->sv->sz;
		num_ocs++;
	}

	num_blks = GET_NB_BLK(sum_oc_size) - oc_ctx->bp->numFree + num_l2_blks;

	while (num_blks > 0) {
		ec = cm_control_plane->get_ec(control_plane);
		num_ec_blks = GET_NB_BLK(ec->sv->sz);

		num_blks -= num_ec_blks; 

		FreePayloadBlock(oc_ctx, ec);
		item_set_state(ec, ITEM_STATE_AT_DISK);
		GET_CUR_MS(ec->vv->ts_ms);
		ec->vv->n_requests = 0;

		cm_disk->insert(disk, ec);
	}

	while ((oc = item_dequeue(oc_ctx->koq))) {
		assert(GeneratePayloadBlock(oc_ctx, oc) > 0);
		item_set_state(oc, ITEM_STATE_AT_L2_CACHE);
		oc->vv->n_requests = 0;
		GET_CUR_MS(oc->vv->ts_ms);
		cm_control_plane->insert(control_plane, oc);
	}

	while ((oc = item_dequeue(oc_ctx->ocq))) {
		assert(GeneratePayloadBlock(oc_ctx, oc) > 0);
		oc->vv->n_requests = 0;
		GET_CUR_US(oc->vv->ts_ms);
		item_set_state(oc, ITEM_STATE_AT_L2_CACHE);
		cm_control_plane->insert(control_plane, oc);
	}
}

#if !SET_CORE_AFFINITY
inline static void
__set_thread_core_affinity(int cpu) {
	cpu_set_t cpuset;
	int rc;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);

	rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
	if (rc < 0) {
		fprintf(stderr, "Fail to set thread cpu affinity (%s)\n", strerror(rc));
		exit(EXIT_FAILURE);
	}
}
#endif


#if SET_CORE_AFFINITY
static int
OptimCache(void *opaque) {
#else
static void *
OptimCache(void *opaque) {
#endif

#if SET_CORE_AFFINITY
	uint16_t core_index = *(uint16_t *)opaque;
#else
	uint16_t core_index = 0;
#endif
	uint32_t num_optims;
	
	optim_cache_context *oc_ctx;
	oc_ctx = CreateOptimCachePrivateContext(core_index);
	if (!oc_ctx) {
		perror("Fail to create optim_cache_context");
		exit(EXIT_FAILURE);
	}

	LOG_INFO("Completes to create OptimCache private context\n");

	g_oc_ctx[core_index] = oc_ctx;
	is_ready = true;

#if !SET_CORE_AFFINITY
	__set_thread_core_affinity(0);
#endif

	while (run_optim_cache) {

		pthread_mutex_lock(&mutex_optim_cache);

		num_optims = rte_atomic32_read(&g_nb_optim_cache_tasks);
		if (num_optims <= 0)
			pthread_cond_wait(&cond_optim_cache, &mutex_optim_cache);

		if (g_active_l1_cache && !g_active_l2_cache) {
			__only_L1_CACHE(oc_ctx);
		} else if (!g_active_l1_cache && g_active_l2_cache) {
			__only_L2_CACHE(oc_ctx);
		} else {
			__both_L1_and_L2_CACHE(oc_ctx);
		}

		rte_atomic32_dec(&g_nb_optim_cache_tasks);
		pthread_mutex_unlock(&mutex_optim_cache);
	}

	DestroyOptimCachePrivateContext(oc_ctx);

	return 0;
}

inline static void
SignalToOptimCache(void) {
#if RUN_CACHE_OPTIMIZATION
	if (CP_CONFIG.enable) {
		rte_atomic32_inc(&g_nb_optim_cache_tasks);
		pthread_cond_signal(&cond_optim_cache);
	}
#endif
}

#define HASHPOWER 22

void 
control_plane_setup(void) {
	/* Global Setup */
	int i;
	static uint16_t g_core_index[MAX_NB_CPUS] = {0};

#if DEBUG
	debug_setup();
#endif
	config_parse(CONTROL_PLANE_CONFIG_PATH);
	cache_ctrl_setup();
	hashtable_create(HASHPOWER);

	g_jhash_initval = (uint32_t)rte_rand();
	g_crc_hash_initval = (uint32_t)rte_rand();

	for (i = 0; i < CP_CONFIG.ncpus; i++) {
		g_private_context[i] = malloc(sizeof(private_context));
		if (!g_private_context[i]) {
			perror("Fail to allocate memory for private_context");
			exit(EXIT_FAILURE);
		}
		g_private_context[i]->lcore_id = CP_CONFIG.lcore_id[i];
		g_private_context[i]->core_index = i;
		g_private_context[i]->itmp = item_mp_create(CP_CONFIG.max_nb_items, CP_CONFIG.lcore_id[i]);
	}

	cm_dataplane = cache_create(NULL, NIC_CACHE, &dataplane);
	cm_control_plane = cache_create(NULL, HOST_CACHE, &control_plane);
	cm_disk = cache_create(NULL, AT_DISK, &disk);

	if (CP_CONFIG.max_nic_mem_size <= 0) 
		g_active_l1_cache = false;

	if (CP_CONFIG.l2cache_size <= 0)
		g_active_l2_cache = false;

	//rte_atomic32_init(&nb_tot_requests);

	for (i = 0; i < CP_CONFIG.ncpus; i++) {
		int ret = -1;
		g_core_index[i] = i;
#if SET_CORE_AFFINITY
		ret = rte_eal_remote_launch(OptimCache, &g_core_index[i], (unsigned)CP_CONFIG.lcore_id[i]);
#else
		pthread_t optimCacheThread;
		UNUSED(g_core_index);
		ret = pthread_create(&optimCacheThread, NULL, OptimCache, NULL);
#endif
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"Fail to launch OptimCache (%s)\n", rte_strerror(rte_errno));
		}
	}

	do {
		usleep(1000);
	} while(!is_ready);

#if SHOW_STATISTICS
	pthread_t statThread;
	if (pthread_create(&statThread, NULL, ShowStatistics, NULL) != 0) {
		perror("fail to create ShowStatistics thread");
		exit(EXIT_FAILURE);
	}
#endif
}

int
control_plane_get_obj_hv(int core_index, char *url, size_t url_len, 
		uint64_t *obj_hv, uint32_t *obj_sz, void **block_map, int *numBlocks) {

	item *it = NULL;
	//private_context *ctx;
	uint16_t state;
	int64_t num_reqs;
	const int64_t inc = 1;

	if (unlikely(!url)) {
		LOG_ERROR("Wrong argument, url=%p\n", url);
		return -1;
	}

#if ALWAYS_READ_FROM_DISK
	return -1;
#endif

	num_reqs = __atomic_add_fetch(&g_tot_reqs, inc, __ATOMIC_RELAXED);
	if (core_index == MASTER_CORE_INDEX && num_reqs > CP_CONFIG.nb_reqs_thresh) {
		num_reqs = __atomic_sub_fetch(&g_tot_reqs, CP_CONFIG.nb_reqs_thresh, __ATOMIC_RELAXED);
		if (num_reqs < 0) {
			__atomic_add_fetch(&g_tot_reqs, CP_CONFIG.nb_reqs_thresh, __ATOMIC_RELAXED);
			//LOG_INFO("g_tot_reqs:%ld\n", g_tot_reqs);
		} else {
			SignalToOptimCache();
			//LOG_INFO("g_tot_reqs:%ld\n", g_tot_reqs);
		}
		DBG_TRACE("Signal to OptimCache thread\n");
	}

	//ctx = g_private_context[core_index];
	it = hashtable_get_with_key(url, url_len, &state);
	if (!it) {
		//LOG_ERROR("[NO_OBJECT] Object(url=%s) does not exist\n", url);
		return -1;
	}

	if ((state != ITEM_STATE_AT_L1_CACHE) && (state != ITEM_STATE_AT_L2_CACHE)) {
		DBG_TRACE("Request obj at Disk (url=%s, hv=%lu) state=%u\n",
				it->key, it->sv->hv, state);
		cm_disk->access(disk, it);
#if _CHECK_CONTROL_PLANE_ACCESS_LATENCY
		LOG_INFO("Get %lu\n", it->sv->hv);
		*obj_hv = it->sv->hv;
#endif
		return -1;
	}
#if 0
	nb_cur_requests = rte_atomic32_add_return(&nb_tot_requests, 1);
	if (core_index == MASTER_CORE_INDEX && nb_cur_requests > CP_CONFIG.nb_reqs_thresh) {
		DBG_TRACE("Signal to OptimCache thread\n");
		SignalToOptimCache();
	//	SHOW_HIT_RATIO();
		rte_atomic32_sub(&nb_tot_requests, CP_CONFIG.nb_reqs_thresh);
	}
#endif

	if (state == ITEM_STATE_AT_L2_CACHE) {
		cm_control_plane->access(control_plane, it);
		DBG_TRACE("Request obj at L2_CACHE(ref_cnt=%u) (url=%s, hv=%lu, state=%u)\n", 
				it->vv->refcount.cnt, it->key, it->sv->hv, state);
		*obj_hv = it->sv->hv;
		*obj_sz = it->sv->sz;
		*block_map = it->block_map;
		*numBlocks = it->numBlocks;
		return 0;
	}

	cm_dataplane->access(dataplane, it);
	DBG_TRACE("Request obj at L1_CACHE(ref_cnt=%u) (url=%s, hv=%lu, state=%u)\n", 
			it->vv->refcount.cnt, it->key, it->sv->hv, state);
	*obj_hv = it->sv->hv;
	*obj_sz = it->sv->sz;
	*block_map = NULL;
	*numBlocks = -1;

#if DBG_SINGLE_CLIENT
	assert(!g_it_prev);
	g_it_prev = it;
#endif

	LOG_GET_REQUEST("[SUCCESS] Successfully get object(url=%s), obj_hv=%lu\n", url, obj_hv);

	return 0;
}

inline int
control_plane_free_obj_by_hv(int core_index, uint64_t hv) {

	item *it;
	//private_context *ctx;
	uint16_t state;
		
	//ctx = g_private_context[core_index];

	it = hashtable_get_with_hv(hv, &state);
	if (unlikely(!it)) {
		LOG_ERROR("[NO_OBJECT] Object(hv=%lu) does not exist\n", hv);
		return -1;
	}
#ifdef  _CHECK_CONTROL_PLANE_ACCESS_LATENCY
	if (state == ITEM_STATE_AT_DISK) {
		LOG_INFO("Free %lu\n", hv);
		return 0;
	}
#endif

	cm_dataplane->free(dataplane, it);

	LOG_FREE_REQUEST("[SUCCESS] Object(hv=%lu) is successfully freed\n", hv);
#if DBG_SINGLE_CLIENT
	assert(g_it_prev == it);
	g_it_prev = NULL;
#endif

	return 0;
}
#define DBG_ENQUEUE_REPLY FALSE

inline void
control_plane_enqueue_reply(int core_index, void *pktbuf, uint32_t cur_ts) {

	optim_cache_context *oc_ctx;
	struct rte_ether_hdr *ethh;
	uint16_t ether_type;
#if DBG_ENQUEUE_REPLY
	struct timespec ts_prev, ts_now;
#else
	UNUSED(cur_ts);
#endif

	oc_ctx = g_oc_ctx[core_index];

	ethh = (struct rte_ether_hdr *)pktbuf;
	ether_type = rte_be_to_cpu_16(ethh->ether_type);
#if DBG_ENQUEUE_REPLY
	clock_gettime(CLOCK_REALTIME, &ts_prev);
#endif

	if (ether_type == ETYPE_PAYLOAD_OFFLOAD) {
		struct direct_read_header *drh = (struct direct_read_header *)(ethh + 1);
		pthread_mutex_lock(&oc_ctx->orq->mutex);
		oc_ctx->orq->q[oc_ctx->orq->len].hv = drh->hv;
		oc_ctx->orq->ts[oc_ctx->orq->len] = drh->ts;
//		LOG_INFO("hv=%lu, ts:%lu len:%lu\n", drh->hv, drh->ts, oc_ctx->orq->len);
		oc_ctx->orq->len++;

#if DBG_ENQUEUE_REPLY
		clock_gettime(CLOCK_REALTIME, &ts_now);
		DUMP_LOG("ENQUEUE TO ORQ  : %lus %luus, erq_len=%lu, orq_len=%lu, ts=%u\n", 
			ts_now.tv_sec - ts_prev.tv_sec, NSEC_TO_USEC(ts_now.tv_nsec - ts_prev.tv_nsec),
			oc_ctx->erq->len, oc_ctx->orq->len, cur_ts);
#endif
		pthread_mutex_unlock(&oc_ctx->orq->mutex);
	} else if (ether_type == ETYPE_EVICTION){
		uint64_t *e_hv;
		pthread_mutex_lock(&oc_ctx->erq->mutex);
		e_hv = (uint64_t *)(ethh + 1);
		//TRACE_CORE("[BEFORE_ENQUEUE] pktbuf=%p, hv=%lu, qlen=%lu\n", pktbuf, *e_hv, oc_ctx->erq->len);
		oc_ctx->erq->e_hv[oc_ctx->erq->len] = *e_hv;
		oc_ctx->erq->ts[oc_ctx->erq->len] = *(e_hv + 1);
//		LOG_INFO("hv=%lu, ts:%lu len:%lu\n", *e_hv, *(e_hv + 1), oc_ctx->erq->len);

		oc_ctx->erq->len++;

//		LOG_INFO("[AFTER_ENQUEUE] pktbuf=%p, hv=%lu, qlen=%lu\n", pktbuf, *e_hv, oc_ctx->erq->len);
#if DBG_ENQUEUE_REPLY
		DUMP_LOG("s_addr=%x:%x:%x:%x:%x:%x d_addr=%x:%x:%x:%x:%x:%x, e_hv=%lu ts=%u\n",
				ethh->s_addr.addr_bytes[0], ethh->s_addr.addr_bytes[1], 
				ethh->s_addr.addr_bytes[2], ethh->s_addr.addr_bytes[3],
				ethh->s_addr.addr_bytes[4], ethh->s_addr.addr_bytes[5],
				ethh->d_addr.addr_bytes[0], ethh->d_addr.addr_bytes[1],
				ethh->d_addr.addr_bytes[2], ethh->d_addr.addr_bytes[3],
				ethh->d_addr.addr_bytes[4], ethh->d_addr.addr_bytes[5],
				e_hv, cur_ts);
		clock_gettime(CLOCK_REALTIME, &ts_now);
		DUMP_LOG("ENQUEUE TO ERQ : %lus %luus, erq_len=%lu, orq_len=%lu ts=%u\n", 
			ts_now.tv_sec - ts_prev.tv_sec, NSEC_TO_USEC(ts_now.tv_nsec - ts_prev.tv_nsec),
			oc_ctx->erq->len, oc_ctx->orq->len, cur_ts);
#endif
		pthread_mutex_unlock(&oc_ctx->erq->mutex);
	}

}

inline void 
control_plane_flush_message(int core_index, uint16_t portid, uint16_t qid) {

	optim_cache_context *oc_ctx;
	oc_ctx = g_oc_ctx[core_index];
	net_flush_tx_pkts(oc_ctx, portid, qid);
}

void 
control_plane_teardown(void) {
	/* TODO */
}

inline int
control_plane_get_nb_cpus(void) {
	return CP_CONFIG.ncpus;
}

void
control_plane_heat_dataplane(void) {
	do {
		usleep(1000);
	} while(!mtcp_master_thread_ready);

#if !ALWAYS_READ_FROM_DISK
	HeatDataplane();
#endif
	heat_dataplane = true;
	DUMP_LOG("Complete Heat Dataplane!!!\n");
}

void 
control_plane_wait_for_heat_dataplane(void) {
	do {
		usleep(10000);
	} while (!heat_dataplane);
}

void 
control_plane_mtcp_master_thread_ready(void) {
	mtcp_master_thread_ready = true;
	LOG_INFO("MTCP Master Thread is Ready\n");
}

inline void
control_plane_signal_to_replyq(int core_index) {

	optim_cache_context *oc_ctx;
	oc_ctx = g_oc_ctx[core_index];

	if (unlikely(oc_ctx->erq->len > 0 && !oc_ctx->erq->proc)) {
		if (rb_tree_nb_nodes(oc_ctx->ec_wait) <= oc_ctx->erq->len)
			pthread_cond_signal(&oc_ctx->erq->cond);
	} 
	if (unlikely(oc_ctx->orq->len > 0 && !oc_ctx->orq->proc)) {
		if (heat_dataplane && rb_tree_nb_nodes(oc_ctx->oc_wait) <= oc_ctx->orq->len)
			pthread_cond_signal(&oc_ctx->orq->cond);
	}
}
