#include "net.h"
#include "config.h"
#include "hashtable.h"
#include "debug.h"

#define DBG_NET FALSE
#if DBG_NET
#define trace_net(f, ...) fprintf(stderr, "(%10s:%4d)" f, __func__, __LINE__, __VA_ARGS__)
#else
#define trace_net(f, ...) (void)0
#endif

#define EVICTION_META_HEADER 0x000f
#define OFFLOAD_META_HEADER 0x00ff

extern bool heat_dataplane;

struct eviction_meta_hdr {
	uint64_t e_hv;
	uint64_t ts;
} __rte_packed;

struct offload_meta_hdr {
	uint64_t c_hv;
	uint32_t c_sz;
	uint16_t c_seq;
	uint64_t c_off;
	uint8_t data[];
} __rte_packed;

/* Use RB Tree */
void
GenerateEvictionPacket(optim_cache_context *oc_ctx, item *ec) {

	struct rte_mbuf *m;
	struct rte_ether_hdr *ethh;
	struct eviction_meta_hdr *emh;

	if (unlikely(oc_ctx->tpq->len == PKT_QUEUE_SIZE)) /* This case will never occur */
		return;

	m = rte_pktmbuf_alloc(oc_ctx->pktmbuf_pool);
	if (!m) {
		rte_exit(EXIT_FAILURE,
				"Fail to allocate mbuf, errno=%d (%s)\n",
				rte_errno, rte_strerror(rte_errno));
	}

	m->pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct eviction_meta_hdr);
	m->data_len = m->pkt_len;
	m->nb_segs = 1;
	m->next = NULL;

	oc_ctx->tpq->mq[oc_ctx->tpq->len] = m;
	oc_ctx->tpq->len++;

	ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	rte_memcpy(&ethh->dst_addr, &CP_CONFIG.dpu_mac_addr, sizeof(struct rte_ether_addr));
#if ENABLE_CMD_LOAD_BALANCING
	int i;
	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
		ethh->src_addr.addr_bytes[i] = rte_rand();
	}
	ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
#else
	rte_memcpy(&ethh->src_addr, &CP_CONFIG.host_mac_addr, sizeof(struct rte_ether_addr));
	ethh->ether_type = rte_cpu_to_be_16(ETYPE_EVICTION);
#endif

	emh = (struct eviction_meta_hdr *)(ethh + 1);
	emh->e_hv = ec->sv->hv;
	emh->ts = ec->ts;
#ifdef _CHECK_DUP
	g_stats.num_evict_pkts++;
	ec->num_cmd++;
#endif

	//LOG_INFO("url:%s, hv:%lu\n", ec->key, ec->sv->hv);
}

void
GenerateOffloadPacket(optim_cache_context *oc_ctx, item *oc) {

	struct rte_mbuf *m;
	struct rte_ether_hdr *ethh;
	struct direct_read_header *drh;

	if (unlikely(oc_ctx->tpq->len == PKT_QUEUE_SIZE)) /* Never occurs */
		return;

	m = rte_pktmbuf_alloc(oc_ctx->pktmbuf_pool);
	if (unlikely(!m)) {
		rte_exit(EXIT_FAILURE,
				"Fail to allocate mbuf, errno=%d (%s)\n",
				rte_errno, rte_strerror(rte_errno));
	}

	m->pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct direct_read_header) + oc->keylen + 1;
	m->data_len = m->pkt_len;
	m->nb_segs = 1;
	m->next = NULL;

	ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	rte_memcpy(&ethh->dst_addr, &CP_CONFIG.dpu_mac_addr, sizeof(struct rte_ether_addr));
#if ENABLE_CMD_LOAD_BALANCING
	int i;
	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
		ethh->src_addr.addr_bytes[i] = rte_rand();
	}
	ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
#else
	rte_memcpy(&ethh->src_addr, &CP_CONFIG.host_mac_addr, sizeof(struct rte_ether_addr));
	ethh->ether_type = rte_cpu_to_be_16(ETYPE_PAYLOAD_OFFLOAD);
#endif
	drh = (struct direct_read_header *)(ethh + 1);
	strncpy(drh->path, oc->key, oc->keylen);
	drh->hv = oc->sv->hv;
	drh->ts = oc->ts;

	assert((int64_t)oc_ctx->tpq->len >= 0);
	oc_ctx->tpq->mq[oc_ctx->tpq->len] = m;
	oc_ctx->tpq->len++;
#ifdef _CHECK_DUP
	g_stats.num_offload_pkts++;
	oc->num_cmd++;
#endif

	//LOG_INFO("url:%s, hv:%lu\n", oc->key, oc->sv->hv);
}

inline static void
ProcessEvictionReplyQueue(optim_cache_context *oc_ctx) {

	int i;
	size_t rehv_len = 0;
	for (i = 0; i < oc_ctx->erq->len; i++) {
		uint16_t state;
		item *it = hashtable_get_with_hv(oc_ctx->erq->e_hv[i], &state);

		 /*LOG_INFO("state:%u, hv:%lu, url:%s, %p, ts:%lu, ts_org:%lu\n", 
				state, oc_ctx->erq->e_hv[i], it->key, it, oc_ctx->erq->ts[i], it->ts);*/

		if (!it)	
			continue;

		if (it->ts != oc_ctx->erq->ts[i]) {
#ifdef _CHECK_DUP
			g_stats.num_evict_dups++;
#endif
			continue;
		}

#if _CHECK_DUP
		uint64_t ts_now = __us_now();
		g_stats.sum_evict_lat += (ts_now - oc_ctx->erq->ts[i]);
#endif

		if (g_active_l1_cache && !g_active_l2_cache && state == ITEM_STATE_AT_DISK) {
#ifdef _CHECK_DUP
			g_stats.num_evict_dups++;
#endif
			continue;
		}

		if (state == ITEM_STATE_AT_L2_CACHE) {
#ifdef _CHECK_DUP
			g_stats.num_evict_dups++;
#endif
			assert(it->left && it->right && it->parent);
			continue;
		}

		if (state == ITEM_STATE_AT_NOWHERE && 
				!it->left && !it->right && !it->parent) {/* Already deleted at rb_tree */
#ifdef _CHECK_DUP
			g_stats.num_evict_dups++;
#endif
			continue;
		}

		rb_tree_delete(oc_ctx->ec_wait, it);
#ifdef _CHECK_DUP
		it->evict_proc = 1;
#endif

		oc_ctx->rehv->e_hv[rehv_len + oc_ctx->rehv->len] = oc_ctx->erq->e_hv[i];
		rehv_len++;
	}

	oc_ctx->erq->len = 0;
	oc_ctx->rehv->len += rehv_len;
}

inline void 
net_send_eviction_message(optim_cache_context *oc_ctx) {

	/* Send all evition message */
	uint64_t ms_sent, ms_recv;

	pthread_mutex_lock(&oc_ctx->tpq->mutex);
	rb_tree_inorder_traversal(oc_ctx->ec_wait, GenerateEvictionPacket, oc_ctx);
	pthread_mutex_unlock(&oc_ctx->tpq->mutex);

	GET_CUR_MS(ms_sent);
	while (true) {
		struct timespec ts;
		pthread_mutex_lock(&oc_ctx->erq->mutex);
		//pthread_cond_wait(&oc_ctx->erq->cond, &oc_ctx->erq->mutex);
		clock_gettime(CLOCK_REALTIME, &ts);
		//ts.tv_nsec += MSEC_TO_NSEC(MAX_EVICTION_BACKOFF_TIME);
		ts.tv_sec += MAX_EVICTION_BACKOFF_TIME;
		pthread_cond_timedwait(&oc_ctx->erq->cond, &oc_ctx->erq->mutex, &ts);
		oc_ctx->erq->proc = true;

		ProcessEvictionReplyQueue(oc_ctx);
		if (rb_tree_is_empty(oc_ctx->ec_wait)) {
			oc_ctx->erq->proc = false;
			pthread_mutex_unlock(&oc_ctx->erq->mutex);
			break;
		}

		GET_CUR_MS(ms_recv); 
		if (ms_recv - ms_sent < SEC_TO_MSEC(MAX_EVICTION_BACKOFF_TIME)) {
			usleep(MSEC_TO_USEC(EVICTION_BACKOFF_TIME));
			oc_ctx->erq->proc = false;
			pthread_mutex_unlock(&oc_ctx->erq->mutex);
			continue;
		}
		GET_CUR_MS(ms_sent);
		pthread_mutex_lock(&oc_ctx->tpq->mutex);
		rb_tree_inorder_traversal(oc_ctx->ec_wait, GenerateEvictionPacket, oc_ctx);
		pthread_mutex_unlock(&oc_ctx->tpq->mutex);

		oc_ctx->erq->proc = false;

		pthread_mutex_unlock(&oc_ctx->erq->mutex);
	}
}

static void 
__gen_off_pkt(optim_cache_context *oc_ctx, item *oc) {
	GenerateOffloadPacket(oc_ctx, oc);
}

static void 
ProcessOffloadReplyQueue(optim_cache_context *oc_ctx) {

	item *it;
	uint16_t state;
	int i, count = 0;
	
	for (i = 0; i < oc_ctx->orq->len; i++) {
		it = hashtable_get_with_hv(oc_ctx->orq->q[i].hv, &state);
		if (!it) {
			LOG_ERROR("item does not exit, hv=%lu\n", oc_ctx->orq->q[i].hv);
			printf("no it\n");
			continue;
		}

		if (it->ts != oc_ctx->orq->ts[i]) {
#ifdef _CHECK_DUP
			g_stats.num_offload_dups++;
#endif
			printf("diff ts\n");
			continue;
		}

#ifdef _CHECK_DUP
		uint64_t ts_now;
		ts_now = __us_now();
		g_stats.sum_offload_lat += (ts_now - oc_ctx->orq->ts[i]);
#endif

		if (state == ITEM_STATE_AT_L1_CACHE) {
			//assert(it->left && it->right && it->parent);
#ifdef _CHECK_DUP
			g_stats.num_offload_dups++;
#endif
			printf("state at L1 cache\n");
			continue;
		}

		if (state == ITEM_STATE_AT_NOWHERE &&
				!it->left && !it->right && !it->parent) {/* Already deleted at rb_tree*/
#ifdef _CHECK_DUP
			g_stats.num_offload_dups++;
#endif
			printf("already deleted\n");
			continue;
		}

		rb_tree_delete(oc_ctx->oc_wait, it);
#ifdef _CHECK_DUP
		it->offload_proc = 1;
#endif

		if (g_active_l1_cache && !g_active_l2_cache) 
			item_set_state(it, ITEM_STATE_AT_L1_CACHE);

		if (g_active_l1_cache && g_active_l2_cache)
			item_set_state(it, ITEM_STATE_AT_L1_CACHE);

		oc_ctx->compl_ohv->e_hv[count + oc_ctx->compl_ohv->len] = oc_ctx->orq->q[i].hv;
		count++;

		trace_net("Process item, hv=%lu\n", oc_ctx->orq->q[i].hv);
	}

	oc_ctx->orq->len = 0;
	oc_ctx->compl_ohv->len += count;
}

inline void
net_send_offloading_message(optim_cache_context *oc_ctx) {

	uint64_t ms_sent, ms_recv;

	pthread_mutex_lock(&oc_ctx->tpq->mutex);
	rb_tree_inorder_traversal(oc_ctx->oc_wait, __gen_off_pkt, oc_ctx);
	pthread_mutex_unlock(&oc_ctx->tpq->mutex);

	GET_CUR_MS(ms_sent);
	while(1) {
		struct timespec ts;
		pthread_mutex_lock(&oc_ctx->orq->mutex);
		clock_gettime(CLOCK_REALTIME, &ts);

		if (heat_dataplane) 
			ts.tv_sec += MAX_OFFLOADING_BACKOFF_TIME;
		else 
			ts.tv_sec += MAX_OFFLOADING_BACKOFF_TIME;
		pthread_cond_timedwait(&oc_ctx->orq->cond, &oc_ctx->orq->mutex, &ts);
		oc_ctx->orq->proc = true;
		ProcessOffloadReplyQueue(oc_ctx);
		if (rb_tree_is_empty(oc_ctx->oc_wait)) {
			oc_ctx->orq->proc = false;
			pthread_mutex_unlock(&oc_ctx->orq->mutex);
			break;
		}

		GET_CUR_MS(ms_recv);
		if (ms_recv - ms_sent < SEC_TO_MSEC(MAX_OFFLOADING_BACKOFF_TIME)) {
			usleep(MSEC_TO_USEC(OFFLOADING_BACKOFF_TIME));
			oc_ctx->orq->proc = false;
			goto retry;
		}

		GET_CUR_MS(ms_sent);
		pthread_mutex_lock(&oc_ctx->tpq->mutex);
		rb_tree_inorder_traversal(oc_ctx->oc_wait, __gen_off_pkt, oc_ctx);
		pthread_mutex_unlock(&oc_ctx->tpq->mutex);
retry :
		pthread_mutex_unlock(&oc_ctx->orq->mutex);
	}

}

inline void
net_flush_tx_pkts(optim_cache_context *oc_ctx, uint16_t portid, uint16_t qid) {

	int ret;
	uint16_t nb_pkts = oc_ctx->tpq->len;

	if (nb_pkts > 0) {
		struct rte_mbuf **tx_pkts;
#ifdef _CHECK_LOCK_LAT
		uint64_t us_now = __us_now();
#endif
		ret = pthread_mutex_trylock(&oc_ctx->tpq->mutex);
		if (ret == EBUSY)	
			return;
#ifdef _CHECK_LOCK_LAT
		g_stats.num_mtx++;
		g_stats.sum_mtx_lat += (__us_now() - us_now);
#endif
		assert(ret == 0);
		nb_pkts = oc_ctx->tpq->len;
		tx_pkts = oc_ctx->tpq->mq;

		while (nb_pkts > 0) {
			uint16_t toSend = RTE_MIN(NB_TX_THRESHOLD, nb_pkts);
			do {
				ret = rte_eth_tx_burst(portid, qid, tx_pkts, toSend);
				tx_pkts += ret;
				toSend -= ret;
				nb_pkts -= ret;
			} while(toSend > 0);
		}
		oc_ctx->tpq->len = 0;
		pthread_mutex_unlock(&oc_ctx->tpq->mutex);
	} 
}
