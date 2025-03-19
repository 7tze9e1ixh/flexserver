#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <math.h>
#include <stdio.h>

#include <rte_ether.h>
#include <rte_random.h>
#include <rte_jhash.h>
#include <rte_byteorder.h>
#include <rte_branch_prediction.h>
#include <rte_tcp.h>
#include <rte_ip.h>

#include "frd_offload_ctrl.h"
#include "debug.h"
#include "config.h"
#include "tcp_send_buffer.h"
#include "flex_buffer.h"
#include "ip_out.h"
#include "rate_limit.h"
#include "util.h"
#include "meta_offload.h"

static frd_offload_control *g_foc[MAX_CPUS] = {NULL};
static uint32_t g_init_val;

enum foc_msg_type {
	FOC_DISK_READ,
	FOC_FREE,
};

#if FOC_LOG_FRD_OFFLOAD
static void *
__frd_offload_log_thread(void *arg) {

	int i;
	frd_offload_control *foc;

	for (i = 0; i < CONFIG.num_cores; i++) {
		while (!g_foc[i]) {
			usleep(50);
		}
	}

	while (1) {
		for (i = 0; i < CONFIG.num_cores; i++) {
			foc = g_foc[i];
			printf("CPU%d numOffloads:%4u, num_free_bufs:%4d, num_waits:%4u, "
					"t_cache:%4.2lf (gbps), t_frd:%4.2lf (gbps)" 
					"\n",
					i, foc->numOffloads, 
					foc->num_free_bufs,
					foc->numWaits,
					(double)g_nic_throughput.t_cache / (1e9), 
					(double)g_nic_throughput.t_frd / (1e9));
		}
		sleep(1);
	}

	return NULL;
}
#endif

inline static uint32_t
__cal_foc_hv_with_addr(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint32_t id) {
	uint32_t a = rte_be_to_cpu_32(saddr);
	uint32_t b = rte_be_to_cpu_32(daddr);
	uint32_t c = (((uint32_t)rte_be_to_cpu_16(sport) << 16) |
		((uint32_t)rte_be_to_cpu_16(dport))) ^ id;
	return rte_jhash_3words(a, b, c, g_init_val);
}

inline static uint32_t 
__cal_foc_hv(struct foc_tx_state *fts) {
	uint32_t a = rte_be_to_cpu_32(fts->stream->saddr);
	uint32_t b = rte_be_to_cpu_32(fts->stream->daddr);
	uint32_t c = (((uint32_t)rte_be_to_cpu_16(fts->stream->sport) << 16) |
		((uint32_t)rte_be_to_cpu_16(fts->stream->dport))) ^ fts->id;
	return rte_jhash_3words(a, b, c, g_init_val);
}

void
foc_setup(mtcp_manager_t mtcp, uint32_t maxOffloads) {

	frd_offload_control *foc;
	int64_t i;

	foc = calloc(1, sizeof(frd_offload_control));
	if (!foc) goto err_calloc;

	g_foc[mtcp->ctx->cpu] = foc;

	if (mtcp->ctx->cpu == 0) {
		g_init_val = (uint32_t)rte_rand();
#if FOC_LOG_FRD_OFFLOAD
		pthread_t frd_log_thread;
		if (pthread_create(&frd_log_thread, NULL, __frd_offload_log_thread, NULL) != 0) {
			TRACE_ERROR("pthread_create()\n");
			exit(EXIT_FAILURE);
		}
#endif
	}

	foc->numEntries = FOC_NUM_ENTRIES;
	foc->mask = FOC_NUM_ENTRIES - 1;
#if FOC_STATIC_THRESH
	foc->thresh = maxOffloads;
#endif
	foc->num_free_bufs = FOC_NUM_FREE_BUFS / CONFIG.num_cores;
	foc->fts_entry = calloc(FOC_NUM_ENTRIES, sizeof(TAILQ_HEAD(, foc_tx_state)));
	if (!foc->fts_entry) goto err_calloc;
	for (i = 0; i < FOC_NUM_ENTRIES; i++)
		TAILQ_INIT(&foc->fts_entry[i]);

	//TAILQ_INIT(&foc->wait_list);
	TAILQ_INIT(&foc->foc_tx_state_wait_list);
	TAILQ_INIT(&foc->foc_tx_state_free_list);
	TAILQ_INIT(&foc->foc_tx_state_offload_list);

	foc->foc_tx_state_ptr = calloc(maxOffloads * 4, sizeof(struct foc_tx_state));
	if (!foc->foc_tx_state_ptr) goto err_calloc;

	for (i = 0; i < maxOffloads * 4; i++) {
		foc->foc_tx_state_ptr[i].id = i;
		TAILQ_INSERT_TAIL(&foc->foc_tx_state_free_list, 
				&foc->foc_tx_state_ptr[i], foc_wait_link);
	}

	pthread_spin_init(&foc->foc_sl, PTHREAD_PROCESS_PRIVATE);

	int count = 0;
	while (1) {
		if (g_foc[count])
			count++;
		if (count == CONFIG.num_cores)
			break;
		usleep(10);
	}
	return;

err_calloc :
	perror("calloc()");
	exit(EXIT_FAILURE);
}

void
foc_destroy(mtcp_manager_t mtcp) {
	frd_offload_control *foc;
	foc = g_foc[mtcp->ctx->cpu];
	free(foc->fts_entry);
	free(foc);
}

inline static void
__transmit_message(mtcp_manager_t mtcp, char *path, 
		struct foc_tx_state *fts, uint32_t cur_ts) {

	struct rte_tcp_hdr *tcph;
	struct frd_offload_hdr *foh;
	uint16_t path_len = path ? strlen(path) : 0;
	struct tcp_stream *stream = fts->stream;

#if ENABLE_META_BATCH
	enum meta_offload_type meta_offload_type;
	uint16_t tcplen;

	if (fts->state == FOC_STATE_DISK_READ) {
		meta_offload_type = META_OFFLOAD_FRD_SETUP;
		tcplen = sizeof(struct rte_tcp_hdr) + sizeof(struct frd_offload_hdr) + path_len + 1;
	} else {
		meta_offload_type = META_OFFLOAD_FRD_TEARDOWN;
		tcplen = sizeof(struct rte_tcp_hdr) + sizeof(struct frd_offload_hdr);
	}

	tcph = (struct rte_tcp_hdr *)meta_offload_generate_ipv4_packet(mtcp->mo, stream, tcplen, 
			meta_offload_type, cur_ts);
#else
	tcph = (struct rte_tcp_hdr *)IPDPUNotify(mtcp, fts->stream, 
			sizeof(struct rte_tcp_hdr) + sizeof(struct frd_offload_hdr) + 
			path_len + 1, fts->state);
#endif

	bzero(tcph, sizeof(struct rte_tcp_hdr));
	tcph->src_port = stream->sport;
	tcph->dst_port = stream->dport;
	fts->ts_sent = cur_ts;

	foh = (struct frd_offload_hdr *)(tcph + 1);
	foh->toSend = 0;
	foh->offset = 0;
	foh->id = fts->id;
	foh->path_len = path_len;

	if (path)
		strncpy(foh->path, path, path_len + 1);
}

int
foc_setup_offload(mtcp_manager_t mtcp, char *url, size_t file_length,
		tcp_stream *stream, uint32_t cur_ts) {

	frd_offload_control *foc;
	struct foc_tx_state *fts;
	int16_t num_bufs, remain;
	uint32_t numOffloads;
	const uint32_t value = 1;

	foc = g_foc[mtcp->ctx->cpu];

	numOffloads = __atomic_add_fetch(&foc->numOffloads, value, __ATOMIC_RELAXED);
	if (foc->thresh < numOffloads) {
		__atomic_sub_fetch(&foc->numOffloads, value, __ATOMIC_RELAXED);
		return -1;
	}

	num_bufs = get_howmany(file_length, FOC_BUF_SIZE);

	remain = __atomic_sub_fetch(&foc->num_free_bufs, num_bufs, __ATOMIC_RELAXED);
	if (remain < 0) {
		__atomic_add_fetch(&foc->num_free_bufs, num_bufs, __ATOMIC_RELAXED);
		return -1;
	}

	pthread_spin_lock(&foc->foc_sl);
	fts = TAILQ_FIRST(&foc->foc_tx_state_free_list);
	TAILQ_REMOVE(&foc->foc_tx_state_free_list, fts, foc_wait_link);
	pthread_spin_unlock(&foc->foc_sl);

	fts->mtcp = mtcp;
	fts->stream = stream;
	fts->file_length = file_length;
	fts->state = FOC_STATE_DISK_READ;
	strcpy(fts->path_name, url);

	pthread_spin_lock(&foc->foc_sl);
	TAILQ_INSERT_TAIL(&foc->foc_tx_state_offload_list, fts, foc_wait_link);
	foc->offload_list_len++;
	TRACE_FRD_OFFLOAD_CTRL("Offload %s, file_length:%lu, stream:%p numWaits:%u, cur_ts:%u\n",
			url, file_length, stream, foc->numWaits, cur_ts);;

	pthread_spin_unlock(&foc->foc_sl);
#if 0
	TAILQ_INSERT_TAIL(&foc->entry[entry_index], stream, foc_ht_link);
	TAILQ_INSERT_TAIL(&foc->wait_list, stream, foc_wait_link);
	__transmit_message(mtcp, url, stream, cur_ts);
	foc->numWaits++;
#endif

	return 0;
}

void
foc_teardown_offload(struct foc_tx_state *fts, uint32_t cur_ts) {

	uint32_t hv, entry_index;
	frd_offload_control *foc;
	const uint32_t value = 1;
	mtcp_manager_t mtcp = fts->mtcp;

	foc = g_foc[mtcp->ctx->cpu];
	hv = __cal_foc_hv(fts);
	entry_index = hv & foc->mask;

	fts->state = FOC_STATE_FREE;
	TAILQ_INSERT_TAIL(&foc->foc_tx_state_wait_list, fts, foc_wait_link);
	TAILQ_INSERT_TAIL(&foc->fts_entry[entry_index], fts, foc_ht_link);
	foc->numWaits++;

	__atomic_sub_fetch(&foc->numOffloads, value, __ATOMIC_RELAXED);

	//fts->stream->sndvar->sndbuf->fts = NULL;

	__transmit_message(mtcp, NULL, fts, cur_ts);

	TRACE_FRD_OFFLOAD_CTRL("Teardown %s, stream:%p, cur_ts:%u\n",
			fts->path_name, fts->stream, cur_ts);
}

inline static bool
__check_timeout(struct foc_tx_state *fts, uint32_t cur_ts) {

	if (!fts)
		return false;
	
	uint32_t diff = cur_ts - fts->ts_sent; //it can consider underflow when cur_ts < ts_sent
	return diff >= FOC_TIMEOUT;
}

void
foc_transmit(mtcp_manager_t mtcp, uint32_t cur_ts) {

	//tcp_stream *stream;
	frd_offload_control *foc;
	struct foc_tx_state *fts;
	uint32_t offload_list_len, i, entry_index;
	foc = g_foc[mtcp->ctx->cpu];

	pthread_spin_lock(&foc->foc_sl);
	offload_list_len = foc->offload_list_len;
	pthread_spin_unlock(&foc->foc_sl);

	for (i = 0; i < offload_list_len; i++) {
		pthread_spin_lock(&foc->foc_sl);
		fts = TAILQ_FIRST(&foc->foc_tx_state_offload_list);
		TAILQ_REMOVE(&foc->foc_tx_state_offload_list, fts, foc_wait_link);
		foc->offload_list_len--;
		pthread_spin_unlock(&foc->foc_sl);
#if 0
		stream->foc_hv = CAL_FOC_HV(stream->saddr, stream->daddr, stream->sport, stream->dport);
		stream->foc_state = FOC_STATE_DISK_READ;
#endif
		fts->hv = __cal_foc_hv(fts);
		entry_index = fts->hv & foc->mask;
		//entry_index = stream->foc_hv & foc->mask;

		TAILQ_INSERT_TAIL(&foc->fts_entry[entry_index], fts, foc_ht_link);
		TAILQ_INSERT_TAIL(&foc->foc_tx_state_wait_list, fts, foc_wait_link);
		__transmit_message(mtcp, fts->path_name, fts, cur_ts);
		foc->numWaits++;

		TRACE_FRD_OFFLOAD_CTRL("fts:%p, numWaits:%u\n", fts, foc->numWaits);
	}
#if 1
	while (foc->numWaits > 0) {
		fts = TAILQ_FIRST(&foc->foc_tx_state_wait_list);
		TAILQ_REMOVE(&foc->foc_tx_state_wait_list, fts, foc_wait_link);

		//TRACE_FRD_OFFLOAD_CTRL("stream:%p, numWaits:%u\n", stream, foc->numWaits);

		if (__check_timeout(fts, cur_ts)) {
			if (fts->state == FOC_STATE_DISK_READ)
				__transmit_message(mtcp, fts->path_name, fts, cur_ts);
			else if (fts->state == FOC_STATE_FREE)
				__transmit_message(mtcp, NULL, fts, cur_ts);
			TAILQ_INSERT_TAIL(&foc->foc_tx_state_wait_list, fts, foc_wait_link);
		} else {
			TAILQ_INSERT_TAIL(&foc->foc_tx_state_wait_list, fts, foc_wait_link);
			break;
		} 
	}
#endif
}

#define FRD_OFFLOAD_ON_PROCEEDING 0x10
#define FRD_OFFLOAD_COMPLETE 0x20
#define FRD_OFFLOAD_ALREADY_FREED 0x30

inline static int
__foc_proc_reply(mtcp_manager_t mtcp, struct rte_ipv4_hdr *iph, uint32_t cur_ts) {

	//tcp_stream *stream;
	uint32_t hv, entry_index;
	struct tcp_send_buffer *buf;
	struct foc_tx_state *fts;
	frd_offload_control *foc = g_foc[mtcp->ctx->cpu];
	//struct rte_ipv4_hdr *iph = in_iph;
	struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)(iph + 1);
	struct frd_offload_hdr *foh = (struct frd_offload_hdr *)(tcph + 1);
	hv = __cal_foc_hv_with_addr(iph->dst_addr, iph->src_addr, 
			tcph->dst_port, tcph->src_port, foh->id);
	entry_index = hv & foc->mask;
	TAILQ_FOREACH(fts, &foc->fts_entry[entry_index], foc_ht_link)
		if (fts->hv == hv && fts->id == foh->id)
			break;
	if (!fts)
		return 0;

	TAILQ_REMOVE(&foc->foc_tx_state_wait_list, fts, foc_wait_link);

	foc->numWaits--;

	if (fts->state == FOC_STATE_DISK_READ) {
		if (iph->type_of_service == FRD_OFFLOAD_ON_PROCEEDING) {
			TAILQ_INSERT_TAIL(&foc->foc_tx_state_wait_list, fts, foc_wait_link);
			foc->numWaits++;
		} else if (iph->type_of_service == FRD_OFFLOAD_COMPLETE) {
			tcp_stream *stream = fts->stream;

			fts->state = FOC_STATE_ACTIVE;
			buf = stream->sndvar->sndbuf;
			if (!buf) {
				foc_teardown_offload(fts, cur_ts);
				//__clean_up_frd_offload(fts);
				return 0;
			}
			fts->mtcp = mtcp;
#if !ENABLE_FLEX_BUFFER
			fts->head_seq = buf->head_seq + buf->total_buf_size;
			fts->already_sent = 0;
			fts->size = fts->file_length;
			SBUF_LOCK(&stream->sndvar->write_lock);
			buf->fts = fts;
			buf->total_buf_size += fts->file_length;
			SBUF_UNLOCK(&stream->sndvar->write_lock);
#else /* ENABLE_FLEX_BUFFER */
			int32_t ret = flex_buffer_attach_with_lock(mtcp, stream, FRD_OFFLOAD_BUFFER,
					fts, fts->file_length);
			if (ret < 0) {
				TRACE_ERROR("Increase # of flex buffer\n");
				exit(EXIT_FAILURE);
			}
			buf->total_buf_size += fts->file_length;
#endif /* !ENABLE_FLEX_BUFFER */

			if (!(stream->sndvar->on_sendq || stream->sndvar->on_send_list)) {
				SQ_LOCK(&mtcp->ctx->sendq_lock);
				stream->sndvar->on_sendq = TRUE;
				StreamEnqueue(mtcp->sendq, stream);
				SQ_UNLOCK(&mtcp->ctx->sendq_lock);
				mtcp->wakeup_flag = TRUE;
			}
			TAILQ_REMOVE(&foc->fts_entry[entry_index], fts, foc_ht_link);

			TRACE_FRD_OFFLOAD_CTRL("numOffloads:%u, numWaits:%u, id:%u, stream:%p\n",
					foc->numOffloads, foc->numWaits, fts->id, stream);

		} else {
			TRACE_ERROR("Wrong type_of_service option, %x\n", iph->type_of_service);
			exit(EXIT_FAILURE);
		}

	} else if (fts->state == FOC_STATE_FREE) {
		//struct foc_tx_state *fts;
		if (iph->type_of_service == FRD_OFFLOAD_ALREADY_FREED) {

			int16_t num_bufs;
			TAILQ_REMOVE(&foc->fts_entry[entry_index], fts, foc_ht_link);
			pthread_spin_lock(&foc->foc_sl);
			fts->state = FOC_STATE_INACTIVE;
			TAILQ_INSERT_TAIL(&foc->foc_tx_state_free_list, fts, foc_wait_link);

			num_bufs = get_howmany(fts->file_length, FOC_BUF_SIZE);
			__atomic_add_fetch(&foc->num_free_bufs, num_bufs, __ATOMIC_RELAXED);

			TRACE_FRD_OFFLOAD_CTRL("numOffloads:%u, numWaits:%u, id:%u, "
					"num_bufs:%d, num_free_bufs:%d\n",
					foc->numOffloads, foc->numWaits, fts->id,
					num_bufs, foc->num_free_bufs);
			pthread_spin_unlock(&foc->foc_sl);

		} else {
			TRACE_ERROR("Wrong type_of_service, %x\n", iph->type_of_service);
			exit(EXIT_FAILURE);
		}

	} else if (fts->state == FOC_STATE_ACTIVE || fts->state == FOC_STATE_INACTIVE) { 
		TRACE_INFO("The task is already processed\n");
		return 0;
	} else {
		TRACE_ERROR("Wrong foc_state\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

int
foc_proc_reply(mtcp_manager_t mtcp, void *in_iph, uint32_t cur_ts, int len) {

	struct rte_ether_hdr *ethh;
	struct rte_ipv4_hdr *iph;
	uint8_t *pkt;
	const int hlen = sizeof(struct rte_ether_hdr) + 
		sizeof(struct rte_ipv4_hdr) + 
		sizeof(struct rte_tcp_hdr) +
		sizeof(struct frd_offload_hdr);

	pkt = (uint8_t *)in_iph - RTE_ETHER_HDR_LEN;

	for (; len > 0; len -= hlen) {
		ethh = (struct rte_ether_hdr *)pkt;
		iph = (struct rte_ipv4_hdr *)(ethh + 1);

		__foc_proc_reply(mtcp, iph, cur_ts);

		pkt += hlen;
	}

	return 0;
}
