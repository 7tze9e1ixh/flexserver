/* mtcp_sendfile using LINUX API read() for zero-copy transmission */

#include <sys/queue.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>

#include <rte_common.h>
#if ENABLE_FILE_READ_WORKER
#include "frd.h"
#endif

#if ENABLE_ASYNC_FILE_READ
//#include "frd_async.h"
#endif

#include "frd.h"

#include "mtcp_api.h"
#include "tcp_in.h"
#include "tcp_stream.h"
#include "tcp_out.h"
#include "ip_out.h"
#include "eventpoll.h"
#include "pipe.h"
#include "fhash.h"
#include "addr_pool.h"
#include "rss.h"
#include "config.h"
#include "debug.h"
#include "nic_cache.h"

inline static int
ReadFromFile(mtcp_manager_t mtcp, tcp_stream *cur_stream, int in_fd, off_t *offset, size_t count)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	//int sndlen;
	int ret;

	/* allocate send buffer if not exist */
#if !ENABLE_FLEX_BUFFER
	sndlen = RTE_MIN((int)sndvar->snd_wnd, count);
	if (sndlen <= 0) {
			errno = EAGAIN;
			return -1;
	}
#endif

	if (!sndvar->sndbuf) {
		sndvar->sndbuf = SBInit(mtcp->rbm_snd, sndvar->iss + 1);
		if (!sndvar->sndbuf) {
				cur_stream->close_reason = TCP_NO_MEM;
				errno = ENOMEM;
				return -1;
		}
	}
#if ENABLE_FILE_READ_WORKER
	ret = frd_issue_request(mtcp, in_fd, count, *offset, cur_stream);
#endif

	ret = frd_issue_request(mtcp, in_fd, cur_stream);
	if (ret < 0) {
		TRACE_CLOSE_REASON("stream:%p\n", cur_stream);
		return ret;
	}
#if !ENABLE_FLEX_BUFFER
	(void)sndlen;
	sndvar->snd_wnd = sndvar->sndbuf->size - sndvar->sndbuf->len;
	if (ret <= 0) {
		TRACE_ERROR("SBPutFromFile failed. reason: %d (sndlen: %u, len: %u)\n",
						ret, sndlen, sndvar->sndbuf->len);
	}

	if (sndvar->snd_wnd <= 0) {
		TRACE_SNDBUF("%u Sending buffer became full!! snd_wnd: %u\n",
						cur_stream->id, sndvar->snd_wnd);
	}
#endif

	return ret;
}

ssize_t
custom_sendfile(mctx_t mctx, int sockid, int in_fd, off_t *offset, size_t count) {
	mtcp_manager_t mtcp;
	socket_map_t socket;
	tcp_stream *cur_stream;
	struct tcp_send_vars *sndvar;
	int ret;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
		TRACE_API("Socket id %d out of range.\n", sockid);
		errno = EBADF;
		return -1;
	}

	socket = &mtcp->smap[sockid];
	if (socket->socktype == MTCP_SOCK_UNUSED) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = EBADF;
		return -1;
	}

	if (socket->socktype == MTCP_SOCK_PIPE) {
		errno = EPIPE;
		return -1;
	}

	if (socket->socktype != MTCP_SOCK_STREAM) {
		TRACE_API("Not an end socket. id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	cur_stream = socket->stream;
	if (!cur_stream ||
			!(cur_stream->state == TCP_ST_ESTABLISHED ||
			cur_stream->state == TCP_ST_CLOSE_WAIT)) {
		errno = ENOTCONN;
		return -1;
	}

	if (count <= 0) {
		if (socket->opts & MTCP_NONBLOCK) {
			errno = EAGAIN;
			return -1;
		} else {
			return 0;
		}
	}

	sndvar = cur_stream->sndvar;

	SBUF_LOCK(&sndvar->write_lock);
#if BLOCKING_SUPPORT
	if (!(socket->opts & MTCP_NONBLOCK)) {
		while (sndvar->snd_wnd <= 0) {
			TRACE_SNDBUF("Waiting for available sending window...\n");
			if (!cur_stream || cur_stream->state != TCP_ST_ESTABLISHED) {
				SBUF_UNLOCK(&sndvar->write_lock);
				errno = EINTR;
				return -1;
			}
			pthread_cond_wait(&sndvar->write_cond, &sndvar->write_lock);
			TRACE_SNDBUF("Sending buffer became ready! snd_wnd: %u\n",
							sndvar->snd_wnd);
		}
	}
#endif

	ret = ReadFromFile(mtcp, cur_stream, in_fd, offset, count);

	SBUF_UNLOCK(&sndvar->write_lock);

	if (ret == 0 && (socket->opts & MTCP_NONBLOCK)) {
		ret = -1;
		errno = EAGAIN;
	}

#if ENABLE_FLOW_SCEHD
	cur_stream->prio = TCP_STREAM_SEND_PRIO_META;
#endif

	/* if there are remaining sending buffer, generate write event */
#if !ENABLE_FLEX_BUFFER
	if (sndvar->snd_wnd > 0) {
#endif
		if ((socket->epoll & MTCP_EPOLLOUT) && !(socket->epoll & MTCP_EPOLLET)) {
			AddEpollEvent(mtcp->ep, USR_SHADOW_EVENT_QUEUE, socket, MTCP_EPOLLOUT);
#if BLOCKING_SUPPORT
		} else if (!(socket->opts & MTCP_NONBLOCK)) {
			if (!cur_stream->on_snd_br_list) {
				cur_stream->on_snd_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->snd_br_list,
								cur_stream, sndvar->snd_br_link);
				mtcp->snd_br_list_cnt++;
			}
#endif
		}
#if !ENABLE_FLEX_BUFFER
	}
#endif

	TRACE_API("Stream %d: mtcp_write() returning %d\n", cur_stream->id, ret);
	return ret;
}
