#include <stdlib.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <rte_lcore.h>
#include <rte_errno.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>

#include "chnk_ht.h"
#include "config.h"
#include "dataplane.h"
#include "debug.h"
#include "dpdk_io.h"

#define DBG_CHNK_HT TRUE
#if DBG_CHNK_HT
#define trace_chnk_ht(f, ...) fprintf(stderr, "(%10s:%4d)" f, __func__, __LINE__, __VA_ARGS__)
#else
#define trace_chnk_ht(f, ...) (void)0
#endif

#define ENABLE_BLK_MAPPER TRUE
#if ENABLE_BLK_MAPPER
#define DEFAULT_BLK_MAPPER_SIZE 256
#define INFLATING_MULTIPLIER 1.5f
#define GET_INFLATED_MAPPER_SIZE(sz) (uint16_t)((float)sz * INFLATING_MULTIPLIER)
#endif

TAILQ_HEAD(chunk_list, chunk_s);

typedef struct chunk_s {
	uint64_t hv;
	blk *b;
	rte_spinlock_t sl;
#if ENABLE_BLK_MAPPER
	blk **blk_mapper;
	uint16_t blk_mapper_size;
#endif
	size_t nb_blks;
	TAILQ_ENTRY(chunk_s) chunk_link;
} chunk;

#define INIT_CHUNK(_chnk, _hv) do {\
	(_chnk)->hv = (_hv);\
	(_chnk)->b = NULL;\
	(_chnk)->blk_mapper = NULL;\
	(_chnk)->nb_blks = 0;\
	rte_spinlock_init(&_chnk->sl);\
} while(0)

#define LOCK_CHUNK(_chnk) rte_spinlock_lock(&_chnk->sl)
#define UNLOCK_CHUNK(_chnk) rte_spinlock_unlock(&_chnk->sl)

struct chnk_ht_s {
	uint32_t mask;
	uint32_t numObjs;
	struct chunk_list *tbl;
	struct rte_mempool *chnk_mp;
	blk_pool *bp;
	rte_spinlock_t *sl;
};

#define GET_TBL_IDX(_ht, _hv) ((_hv) & (_ht)->mask)
#define LOCK_TBL_ENT(_ht, _idx) rte_spinlock_lock(&(_ht)->sl[(_idx)])
#define UNLOCK_TBL_ENT(_ht, _idx) rte_spinlock_unlock(&(_ht)->sl[(_idx)])
#define IS_TBL_ENT_LOCKED(_ht, _idx) rte_spinlock_is_locked(&(_ht)->sl[(_idx)])

static void clear_all_blks(blk_pool *bp, blk *b);
#if ENABLE_BLK_MAPPER
static void InsertBlkToMapper(chunk *chnk, blk *b);
#endif

#if DEBUG_PAYLOAD_CONSISTENCY
#include <sys/stat.h>
void check_payload(chnk_ht *cht, char *f_path, uint64_t hv);
#endif

#if ENABLE_DIRECT_DATA_READ
static struct iovec g_iovec[MAX_CPUS][MAX_IOV];
#endif

#if ENABLE_BLK_MAPPER
inline static void
InsertBlkToMapper(chunk *chnk, blk *b)
{
	if (!chnk->blk_mapper) {
		chnk->blk_mapper_size = DEFAULT_BLK_MAPPER_SIZE;
		chnk->blk_mapper = malloc(sizeof(blk *) * chnk->blk_mapper_size);
		if (!chnk->blk_mapper) {
			log_error("Fail to allocate memory for blk_mapper, modify your configuration\n");
			exit(EXIT_FAILURE);
		}
	} else if (b->meta.b_seq >= chnk->blk_mapper_size) {
		chnk->blk_mapper_size = GET_INFLATED_MAPPER_SIZE(chnk->blk_mapper_size);
		chnk->blk_mapper = realloc(chnk->blk_mapper, chnk->blk_mapper_size);
		if (!chnk->blk_mapper) {
			log_error("Fail to reallocate memory for blk_mapper, modify yout configuration\n");
			exit(EXIT_FAILURE);
		}
	} 
	chnk->blk_mapper[b->meta.b_seq] = b;
}
#endif

inline static void
clear_all_blks(blk_pool *bp, blk *b)
{
	blk *p_next;
	blk *walk = b;

	while (walk) {
		p_next = walk->meta.b_next;
		blk_free(bp, walk);
		walk = p_next;
	}
}

#if DEBUG_PAYLOAD_CONSISTENCY
static uint8_t f_buf[BLOCK_SIZE];
void
check_payload(chnk_ht *cht, char *f_path, uint64_t o_hv)
{
	size_t b_dat_sz, nb_rd;
	int retval, f_fd, f_off, f_sz;
	struct stat f_stat;
	blk *walk = NULL;
	off_t b_off;

	f_fd = open(f_path, O_RDONLY);
	if (f_fd < 0 && errno != EAGAIN) {
		rte_exit(EXIT_FAILURE,
				"(%10s:%4d) Fail to open file %s "
				"errno=%d (%s)\n",
				__FILE__, __LINE__, f_path, errno, strerror(errno));
	}

	f_off = 0;
	stat(f_path, &f_stat);
	f_sz = f_stat.st_size;
	b_dat_sz = blk_get_dat_sz(cht->bp);

	if (chnk_ht_get(cht, o_hv, 0, &walk, NULL) < 0) {
		rte_exit(EXIT_FAILURE, "Fail to offload, no entry in chnk_ht\n");
	}

	for (; f_sz > 0; f_sz -= b_dat_sz, f_off += b_dat_sz) {
		b_off = 0;
		lseek(f_fd, f_off, SEEK_SET);
		do {
			nb_rd = read(f_fd, f_buf + b_off, CACHE_BLOCK_SIZE - b_off);
			b_off += nb_rd;

			retval = memcmp(f_buf, walk->data, !walk->meta.b_next ? f_sz : b_dat_sz);
			if (retval != 0) {
				rte_exit(EXIT_FAILURE, "Payload Sanity Check Fail!!!\n");
			}

			walk = walk->meta.b_next;

			if ((b_off == CACHE_BLOCK_SIZE && f_sz >= b_dat_sz) ||
					(b_off == f_sz && (walk->meta.b_next == NULL)))
				break;

		} while((nb_rd < 0 && errno == EAGAIN));
	}

	//log_info("Object (hv=%lu) is successfully offloaded\n", o_hv);

	close(f_fd);
}
#endif

chnk_ht *
chnk_ht_create(void)
{
	size_t sz, nb_ents;;
	int i;
	chnk_ht *cht;

	cht = calloc(1, sizeof(chnk_ht));
	if (!cht) {
		rte_exit(EXIT_FAILURE,
				"Fail to allocate memory for chunk hashtable "
				"errno=%d (%s)\n", errno, strerror(errno));
	}
	cht->mask = (1U << d_CONFIG.hash_power) - 1;

	nb_ents = 1U << d_CONFIG.hash_power;

	cht->tbl = calloc(nb_ents, sizeof(struct chunk_list));
	if (!cht->tbl) {
		rte_exit(EXIT_FAILURE,
				"Fail to create table, "
				"errno=%d (%s)\n", errno, strerror(errno));
	}

	for (i = 0; i < nb_ents; i++)
		TAILQ_INIT(&cht->tbl[i]);

	cht->sl = calloc(nb_ents, sizeof(rte_spinlock_t));
	if (!cht->sl) {
		rte_exit(EXIT_FAILURE,
				"Fail to allocate memory for spinlock, "
				"errno=%d (%s)\n", errno, strerror(errno));
	}

	for (i = 0; i < nb_ents; i++) 
		rte_spinlock_init(&cht->sl[i]);

	sz = RTE_ALIGN_CEIL(sizeof(chunk), RTE_CACHE_LINE_MIN_SIZE);
	cht->chnk_mp = rte_mempool_create("chunk-pool", d_CONFIG.max_nb_items, sz, 0,
			0, NULL, NULL, NULL, NULL, rte_socket_id(), MEMPOOL_F_NO_SPREAD);
	if (!cht->chnk_mp) {
		rte_exit(EXIT_FAILURE,
				"Fail to create memory pool, rte_errno=%d (%s)\n", 
				rte_errno, rte_strerror(rte_errno));
	}

	cht->bp = blk_setup();

	return cht;
}

#define GET_BLK_SEQ(_cseq) ((_cseq) / CHUNK_PER_BLOCK)
#define CHUNK_SEQ_MASK (CHUNK_PER_BLOCK - 1)
#define GET_CHNK_OFF_IN_BLK(_cseq) (((_cseq) & CHUNK_SEQ_MASK) * OFFLOAD_CHUNK_SIZE)

#if ENABLE_DIRECT_DATA_READ
int
chnk_ht_direct_insert(chnk_ht *cht, uint64_t hv, char *path) {

	int32_t fd, i;
	ssize_t ret;
	size_t toRead;
	chunk *pchunk;
	blk *new, *prev;
	uint16_t numIOV; 
	uint32_t lcore_id = rte_lcore_id();
	uint32_t t_idx = GET_TBL_IDX(cht, hv);
	struct iovec *iov = g_iovec[lcore_id];

	LOCK_TBL_ENT(cht, t_idx);
	TAILQ_FOREACH(pchunk, &cht->tbl[t_idx], chunk_link) 
		if (pchunk->hv == hv)
			break;

	if (unlikely(pchunk)) {
		//log_info("hv:%lu is already offloaded\n", hv);
		UNLOCK_TBL_ENT(cht, t_idx);
		return -1;
	}  
	
	ret = rte_mempool_get(cht->chnk_mp, (void **)&pchunk);
	UNLOCK_TBL_ENT(cht, t_idx);

	if (ret < 0) {
		log_error("Increase # of chunks of hashtable\n");
		exit(EXIT_FAILURE);
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		log_error("Fail to open file %s(%lu), %s\n", path, hv, strerror(errno));
		return -1;
		//exit(EXIT_FAILURE);
	}

	toRead = lseek(fd, 0, SEEK_END);
	numIOV = (toRead + CACHE_BLOCK_SIZE - 1) / CACHE_BLOCK_SIZE;
	prev = NULL;

	INIT_CHUNK(pchunk, hv);

	for (i = 0; i < numIOV; i++) {
		new = blk_alloc(cht->bp);
		if (unlikely(!new)) {
			log_error("Fail to synchronize states between host and nic\n");
			exit(EXIT_FAILURE);
		}

		if (!pchunk->b)
			pchunk->b = new;
		new->meta.b_seq = i;
#if ENABLE_BLK_MAPPER
		InsertBlkToMapper(pchunk, new);
#endif
		if (prev)
			prev->meta.b_next = new;
		prev = new;
		iov[i].iov_base = new->data;
		iov[i].iov_len = CACHE_BLOCK_SIZE;
	}

	ret = preadv(fd, iov, numIOV, 0);
	if (unlikely(ret != toRead)) {
		log_error("Fail to read file, ret=%ld\n", ret);
		exit(EXIT_FAILURE);
	}

	LOCK_TBL_ENT(cht, t_idx);
	TAILQ_INSERT_TAIL(&cht->tbl[t_idx], pchunk, chunk_link);
	UNLOCK_TBL_ENT(cht, t_idx);
	cht->numObjs++;

	close(fd);

	return 0;
}
#else
void
chnk_ht_direct_insert(chnk_ht *cht, uint64_t hv, char *path) {
	UNUSED(cht);
	UNUSED(hv);
	UNUSED(path);
}
#endif /* ENABLE_DIRECT_DATA_READ */

int
chnk_ht_insert(chnk_ht *cht, uint64_t hv, uint16_t c_seq, uint8_t *data, size_t chnk_sz)
{
	int retval, b_seq;
	blk *walk, *new;
	chunk *p_chnk = NULL;
	off_t b_off;
	uint32_t t_idx = GET_TBL_IDX(cht, hv);

	assert(data);
	assert(chnk_sz > 0);

	/* Lock hashtable entry */
	LOCK_TBL_ENT(cht, t_idx);
	TAILQ_FOREACH(p_chnk, &cht->tbl[t_idx], chunk_link)
		if (p_chnk->hv == hv)
			break;

	if (!p_chnk) {
		retval = rte_mempool_get(cht->chnk_mp, (void **)&p_chnk);
		if (unlikely(retval < 0)) {
			UNLOCK_TBL_ENT(cht, t_idx);
			return -1;
		}
		INIT_CHUNK(p_chnk, hv);
		TAILQ_INSERT_TAIL(&cht->tbl[t_idx], p_chnk, chunk_link);
	}

	/* Unlock hashtable entry */
	UNLOCK_TBL_ENT(cht, t_idx);

	/* Lock chunk for concurrent accessing by multi-thread */
	LOCK_CHUNK(p_chnk);

	b_off = GET_CHNK_OFF_IN_BLK(c_seq);
	b_seq = GET_BLK_SEQ(c_seq);
	walk = p_chnk->b;
	if (!walk) {
		new = blk_alloc(cht->bp);
		if (unlikely(!new)) {
			/* This case will never occur */
			rte_exit(EXIT_FAILURE,
					"(%10s:%4d) Fail to synchronize states between host and nic ...\n)",
					__func__, __LINE__);
		}
		p_chnk->nb_blks++;
		p_chnk->b = new;
		new->meta.b_seq = b_seq;
#if ENABLE_BLK_MAPPER
		InsertBlkToMapper(p_chnk, new);
#endif
		rte_memcpy(new->data + b_off, data, chnk_sz);
		UNLOCK_CHUNK(p_chnk);
		return 0;
	}

	for (; walk->meta.b_next; walk = walk->meta.b_next) {
		if (b_seq == walk->meta.b_seq) {
			rte_memcpy(walk->data + b_off, data, chnk_sz);
			UNLOCK_CHUNK(p_chnk);
			return 0;

		} else if (walk->meta.b_seq < b_seq && walk->meta.b_next->meta.b_seq > b_seq) {
			new = blk_alloc(cht->bp);
			if (unlikely(!new)) {
				/* Configurtaion fail */
				rte_exit(EXIT_FAILURE, 
						"(%10s:%4d) Fail to synchronize states between host and nic ...\n", 
						__func__, __LINE__);
			}
			p_chnk->nb_blks++;
			new->meta.b_seq = b_seq;
			new->meta.b_next = walk->meta.b_next;
			walk->meta.b_next = new;
#if ENABLE_BLK_MAPPER
			InsertBlkToMapper(p_chnk, new);
#endif
			rte_memcpy(new->data + b_off, data, chnk_sz);
			UNLOCK_CHUNK(p_chnk);
			return 0;
		} 
	}

	if (b_seq == walk->meta.b_seq) {
		rte_memcpy(walk->data + b_off, data, chnk_sz);
	} else {
		new = blk_alloc(cht->bp);
		if (unlikely(!new)) { 
			rte_exit(EXIT_FAILURE, 
					"(%10s:%4d) Fail to synchronize states between host and nic ...\n", 
					__func__, __LINE__);
		}

		p_chnk->nb_blks++;
		walk->meta.b_next = new;
		new->meta.b_seq = b_seq;
#if ENABLE_BLK_MAPPER
		InsertBlkToMapper(p_chnk, new);
#endif
		rte_memcpy(new->data + b_off, data, chnk_sz);
	}

#if SHOW_STATUS
	size_t nb_tots, nb_free, nb_used;
	blk_get_status(cht->bp, &nb_tots, &nb_free, &nb_used);
	fprintf(stderr, "INSERT obj(%lu), TOT_BLKS=%lu, FREE_BLKS=%lu, USED_BLKS=%lu\n",
			hv, nb_tots, nb_free, nb_used);
#endif
	UNLOCK_CHUNK(p_chnk);

	return 0;
}

int
chnk_ht_delete(chnk_ht *cht, uint64_t hv)
{
	chunk *p_chnk;
	uint32_t t_idx = GET_TBL_IDX(cht, hv);

	LOCK_TBL_ENT(cht, t_idx);
	TAILQ_FOREACH(p_chnk, &cht->tbl[t_idx], chunk_link) {
		if (p_chnk->hv == hv)
			break;
	}

	if (!p_chnk) {
		//log_error("No pchnk at chnk_ht (hv=%lu)\n", hv);
		UNLOCK_TBL_ENT(cht, t_idx);
		return -1;
	}

	//log_error("Evict object %lu\n", hv);

	TAILQ_REMOVE(&cht->tbl[t_idx], p_chnk, chunk_link);

	if (p_chnk->b) {
		LOCK_CHUNK(p_chnk);
		clear_all_blks(cht->bp, p_chnk->b);
		UNLOCK_CHUNK(p_chnk);
	}

#if ENABLE_BLK_MAPPER
	free(p_chnk->blk_mapper);
#endif
	rte_mempool_put(cht->chnk_mp, p_chnk);

#if 0
	size_t nb_tots, nb_free, nb_used;
	blk_get_status(cht->bp, &nb_tots, &nb_free, &nb_used);
	fprintf(stderr, "Free obj(%lu), TOT_BLKS=%lu, FREE_BLKS=%lu, USED_BLKS=%lu\n",
			hv, nb_tots, nb_free, nb_used);
#endif

	UNLOCK_TBL_ENT(cht, t_idx);

	cht->numObjs--;

	return 0;
}

__rte_always_inline __rte_hot int
chnk_ht_get_blk(chnk_ht *cht, uint64_t o_hv, off_t o_off, blk **ret_blk, off_t *ret_off) 
{
	chunk *c_walk;
	blk *b_walk;
	uint32_t t_idx = GET_TBL_IDX(cht, o_hv);
	size_t blk_dat_sz = blk_get_dat_sz(cht->bp);

#if DEBUG_CHNK_HT
	off_t orig_off = o_off;
	size_t blk_seq = 0;
#endif

	LOCK_TBL_ENT(cht, t_idx);

	TAILQ_FOREACH(c_walk, &cht->tbl[t_idx], chunk_link) {
		if (c_walk->hv == o_hv)
			break;
	}

	UNLOCK_TBL_ENT(cht, t_idx);

	if (!c_walk)
		return -1;

#if ENABLE_BLK_MAPPER
	uint16_t b_seq = o_off / blk_dat_sz;
	b_walk = c_walk->blk_mapper[b_seq];
	assert(b_walk->meta.b_seq == b_seq);
	*ret_off = o_off - blk_dat_sz * b_seq;
#else
	b_walk = c_walk->b;
	while (o_off >= blk_dat_sz && b_walk) {
		o_off -= blk_dat_sz;
		b_walk = b_walk->meta.b_next;
#if DEBUG_CHNK_HT
		blk_seq++;
#endif
	}
#endif

	if (!b_walk) {
		*ret_blk = NULL;
		return -1;
	}

	*ret_blk = b_walk;
#if DEBUG_CHNK_HT
	log_chnk_ht("Request(hv=%lu, off=%lu) tot_nb_blks=%lu, blk_seq=%lu(%u) o_off=%lu\n",
			o_hv, orig_off, c_walk->nb_blks, blk_seq, b_walk->meta.b_seq, o_off);
#endif

	return 0;
}

void
chnk_ht_teardown(chnk_ht *cht)
{
	rte_mempool_free(cht->chnk_mp);
	blk_destroy(cht->bp);
	free(cht->tbl);
	free(cht->sl);
	free(cht);
}
