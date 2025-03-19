#include <sys/queue.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>

#include "mtcp.h"
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
#include "rate_limit.h"
#include "frd_offload_ctrl.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

/*----------------------------------------------------------------------------*/
static inline int 
mtcp_is_connected(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	if (!cur_stream) {
		TRACE_API("Stream does not exist\n");
		return FALSE;
	}
	if (cur_stream->state != TCP_ST_ESTABLISHED) {
		TRACE_API("Stream %d not ESTABLISHED. state: %s\n", 
				cur_stream->id, TCPStateToString(cur_stream));
		return FALSE;
	}

	return TRUE;
}
/*----------------------------------------------------------------------------*/
inline mtcp_manager_t 
GetMTCPManager(mctx_t mctx)
{
	if (!mctx) {
		errno = EINVAL;
		return NULL;
	}

	if (mctx->cpu < 0 || mctx->cpu >= num_cpus) {
		errno = EINVAL;
		return NULL;
	}

	if (g_mtcp[mctx->cpu]->ctx->done || g_mtcp[mctx->cpu]->ctx->exit) {
		errno = EPERM;
		return NULL;
	}

	return g_mtcp[mctx->cpu];
}
/*----------------------------------------------------------------------------*/
static inline int 
GetSocketError(socket_map_t socket, void *optval, socklen_t *optlen)
{
	tcp_stream *cur_stream;

	if (!socket->stream) {
		errno = EBADF;
		return -1;
	}

	cur_stream = socket->stream;
	if (cur_stream->state == TCP_ST_CLOSED) {
		if (cur_stream->close_reason == TCP_TIMEDOUT || 
				cur_stream->close_reason == TCP_CONN_FAIL || 
				cur_stream->close_reason == TCP_CONN_LOST) {
			*(int *)optval = ETIMEDOUT;
			*optlen = sizeof(int);

			return 0;
		}
	}

	if (cur_stream->state == TCP_ST_CLOSE_WAIT || 
			cur_stream->state == TCP_ST_CLOSED) { 
		if (cur_stream->close_reason == TCP_RESET) {
			*(int *)optval = ECONNRESET;
			*optlen = sizeof(int);

			return 0;
		}
	}

	if (cur_stream->state == TCP_ST_SYN_SENT &&
	    errno == EINPROGRESS) {
		*(int *)optval = errno;
		*optlen = sizeof(int);
		return -1;
	}

	/*
	 * `base case`: If socket sees no so_error, then
	 * this also means close_reason will always be
	 * TCP_NOT_CLOSED. 
	 */
	if (cur_stream->close_reason == TCP_NOT_CLOSED) {
		*(int *)optval = 0;
		*optlen = sizeof(int);		
		
		return 0;
	}

	errno = ENOSYS;
	return -1;
}
/*----------------------------------------------------------------------------*/
int
mtcp_getsockname(mctx_t mctx, int sockid, struct sockaddr *addr,
		 socklen_t *addrlen)
{
	mtcp_manager_t mtcp;
	socket_map_t socket;
	
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

	if (*addrlen <= 0) {
		TRACE_API("Invalid addrlen: %d\n", *addrlen);
		errno = EINVAL;
		return -1;
	}
	
	if (socket->socktype != MTCP_SOCK_LISTENER && 
	    socket->socktype != MTCP_SOCK_STREAM) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	*(struct sockaddr_in *)addr = socket->saddr;
        *addrlen = sizeof(socket->saddr);

	return 0;
}
/*----------------------------------------------------------------------------*/
int
mtcp_getpeername(mctx_t mctx, int sockid, struct sockaddr *addr,
		 socklen_t *addrlen)
{
	mtcp_manager_t mtcp;
	socket_map_t socket;
	struct sockaddr_in *addr_in;
	tcp_stream *stream;

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
	
	if (*addrlen <= 0) {
		TRACE_API("Invalid addrlen: %d\n", *addrlen);
		errno = EINVAL;
		return -1;
	}
	
	if (socket->socktype != MTCP_SOCK_LISTENER && 
	    socket->socktype != MTCP_SOCK_STREAM) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}
	
	stream = socket->stream;
	if (!mtcp_is_connected(mtcp, stream)) {
		errno = ENOTCONN;
		return -1;
	}
	
	addr_in = (struct sockaddr_in *)addr;
        addr_in->sin_family = AF_INET;
        addr_in->sin_port = stream->dport;
        addr_in->sin_addr.s_addr = stream->daddr;
        *addrlen = sizeof(*addr_in);
	
	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_getsockopt(mctx_t mctx, int sockid, int level, 
		int optname, void *optval, socklen_t *optlen)
{
	mtcp_manager_t mtcp;
	socket_map_t socket;

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

	if (socket->socktype != MTCP_SOCK_LISTENER && 
			socket->socktype != MTCP_SOCK_STREAM) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	if (level == SOL_SOCKET) {
		if (optname == SO_ERROR) {
			if (socket->socktype == MTCP_SOCK_STREAM) {
				return GetSocketError(socket, optval, optlen);
			}
		}
	}

	errno = ENOSYS;
	return -1;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_setsockopt(mctx_t mctx, int sockid, int level, 
		int optname, const void *optval, socklen_t optlen)
{
	mtcp_manager_t mtcp;
	socket_map_t socket;

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

	if (socket->socktype != MTCP_SOCK_LISTENER && 
			socket->socktype != MTCP_SOCK_STREAM) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_setsock_nonblock(mctx_t mctx, int sockid)
{
	mtcp_manager_t mtcp;
	
	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
		TRACE_API("Socket id %d out of range.\n", sockid);
		errno = EBADF;
		return -1;
	}

	if (mtcp->smap[sockid].socktype == MTCP_SOCK_UNUSED) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = EBADF;
		return -1;
	}

	mtcp->smap[sockid].opts |= MTCP_NONBLOCK;

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_socket_ioctl(mctx_t mctx, int sockid, int request, void *argp)
{
	mtcp_manager_t mtcp;
	socket_map_t socket;
	
	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
		TRACE_API("Socket id %d out of range.\n", sockid);
		errno = EBADF;
		return -1;
	}

	/* only support stream socket */
	socket = &mtcp->smap[sockid];
	if (socket->socktype != MTCP_SOCK_STREAM &&
	    socket->socktype != MTCP_SOCK_LISTENER) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = EBADF;
		return -1;
	}

	if (!argp) {
		errno = EFAULT;
		return -1;
	}

	if (request == FIONREAD) {
		tcp_stream *cur_stream;
		struct tcp_ring_buffer *rbuf;

		cur_stream = socket->stream;
		if (!cur_stream) {
			errno = EBADF;
			return -1;
		}
		rbuf = cur_stream->rcvvar->rcvbuf;
		if (rbuf) {
		        *(int *)argp = rbuf->merged_len;
		} else {
			*(int *)argp = 0;
		}

	} else if (request == FIONBIO) {
		int32_t arg = *(int32_t *)argp;
		if (arg != 0)
			return mtcp_setsock_nonblock(mctx, sockid);
	} else {
		errno = EINVAL;
		return -1;
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_socket(mctx_t mctx, int domain, int type, int protocol)
{
	mtcp_manager_t mtcp;
	socket_map_t socket;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	if (domain != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (type == SOCK_STREAM) {
		type = (int)MTCP_SOCK_STREAM;
	} else {
		errno = EINVAL;
		return -1;
	}

	socket = AllocateSocket(mctx, type, FALSE);
	if (!socket) {
		errno = ENFILE;
		return -1;
	}

	return socket->id;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_bind(mctx_t mctx, int sockid, 
		const struct sockaddr *addr, socklen_t addrlen)
{
	mtcp_manager_t mtcp;
	struct sockaddr_in *addr_in;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
		TRACE_API("Socket id %d out of range.\n", sockid);
		errno = EBADF;
		return -1;
	}

	if (mtcp->smap[sockid].socktype == MTCP_SOCK_UNUSED) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = EBADF;
		return -1;
	}
	
	if (mtcp->smap[sockid].socktype != MTCP_SOCK_STREAM && 
			mtcp->smap[sockid].socktype != MTCP_SOCK_LISTENER) {
		TRACE_API("Not a stream socket id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	if (!addr) {
		TRACE_API("Socket %d: empty address!\n", sockid);
		errno = EINVAL;
		return -1;
	}

	if (mtcp->smap[sockid].opts & MTCP_ADDR_BIND) {
		TRACE_API("Socket %d: adress already bind for this socket.\n", sockid);
		errno = EINVAL;
		return -1;
	}

	/* we only allow bind() for AF_INET address */
	if (addr->sa_family != AF_INET || addrlen < sizeof(struct sockaddr_in)) {
		TRACE_API("Socket %d: invalid argument!\n", sockid);
		errno = EINVAL;
		return -1;
	}

	/* TODO: validate whether the address is already being used */

	addr_in = (struct sockaddr_in *)addr;
	mtcp->smap[sockid].saddr = *addr_in;
	mtcp->smap[sockid].opts |= MTCP_ADDR_BIND;

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_listen(mctx_t mctx, int sockid, int backlog)
{
	mtcp_manager_t mtcp;
	struct tcp_listener *listener;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
		TRACE_API("Socket id %d out of range.\n", sockid);
		errno = EBADF;
		return -1;
	}

	if (mtcp->smap[sockid].socktype == MTCP_SOCK_UNUSED) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = EBADF;
		return -1;
	}

	if (mtcp->smap[sockid].socktype == MTCP_SOCK_STREAM) {
		mtcp->smap[sockid].socktype = MTCP_SOCK_LISTENER;
	}
	
	if (mtcp->smap[sockid].socktype != MTCP_SOCK_LISTENER) {
		TRACE_API("Not a listening socket. id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	if (backlog <= 0 || backlog > CONFIG.max_concurrency) {
		errno = EINVAL;
		return -1;
	}

	/* check whether we are not already listening on the same port */
	if (ListenerHTSearch(mtcp->listeners, 
			     &mtcp->smap[sockid].saddr.sin_port)) {
		errno = EADDRINUSE;
		return -1;
	}

	listener = (struct tcp_listener *)calloc(1, sizeof(struct tcp_listener));
	if (!listener) {
		/* errno set from the malloc() */
		return -1;
	}

	listener->sockid = sockid;
	listener->backlog = backlog;
	listener->socket = &mtcp->smap[sockid];

	if (pthread_cond_init(&listener->accept_cond, NULL)) {
		/* errno set internally */
		perror("pthread_cond_init of ctx->accept_cond\n");
		free(listener);
		return -1;
	}
	if (pthread_mutex_init(&listener->accept_lock, NULL)) {
		/* errno set internally */
		perror("pthread_mutex_init of ctx->accept_lock\n");
		free(listener);
		return -1;
	}

	listener->acceptq = CreateStreamQueue(backlog);
	if (!listener->acceptq) {
		free(listener);
		errno = ENOMEM;
		return -1;
	}
	
	mtcp->smap[sockid].listener = listener;
	ListenerHTInsert(mtcp->listeners, listener);

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_accept(mctx_t mctx, int sockid, struct sockaddr *addr, socklen_t *addrlen)
{
	mtcp_manager_t mtcp;
	struct tcp_listener *listener;
	socket_map_t socket;
	tcp_stream *accepted = NULL;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
		TRACE_API("Socket id %d out of range.\n", sockid);
		errno = EBADF;
		return -1;
	}

	/* requires listening socket */
	if (mtcp->smap[sockid].socktype != MTCP_SOCK_LISTENER) {
		errno = EINVAL;
		return -1;
	}

	listener = mtcp->smap[sockid].listener;

	/* dequeue from the acceptq without lock first */
	/* if nothing there, acquire lock and cond_wait */
	accepted = StreamDequeue(listener->acceptq);
	if (!accepted) {
		if (listener->socket->opts & MTCP_NONBLOCK) {
			errno = EAGAIN;
			return -1;

		} else {
			pthread_mutex_lock(&listener->accept_lock);
			while ((accepted = StreamDequeue(listener->acceptq)) == NULL) {
				pthread_cond_wait(&listener->accept_cond, &listener->accept_lock);
		
				if (mtcp->ctx->done || mtcp->ctx->exit) {
					pthread_mutex_unlock(&listener->accept_lock);
					errno = EINTR;
					return -1;
				}
			}
			pthread_mutex_unlock(&listener->accept_lock);
		}
	}

	if (!accepted) {
		TRACE_ERROR("[NEVER HAPPEN] Empty accept queue!\n");
	}

	if (!accepted->socket) {
		socket = AllocateSocket(mctx, MTCP_SOCK_STREAM, FALSE);
		if (!socket) {
			TRACE_ERROR("Failed to create new socket!\n");
			/* TODO: destroy the stream */
			errno = ENFILE;
			return -1;
		}
		socket->stream = accepted;
		accepted->socket = socket;

		/* set socket parameters */
		socket->saddr.sin_family = AF_INET;
		socket->saddr.sin_port = accepted->dport;
		socket->saddr.sin_addr.s_addr = accepted->daddr;
	}

	if (!(listener->socket->epoll & MTCP_EPOLLET) &&
	    !StreamQueueIsEmpty(listener->acceptq))
		AddEpollEvent(mtcp->ep, 
			      USR_SHADOW_EVENT_QUEUE,
			      listener->socket, MTCP_EPOLLIN);

	TRACE_API("Stream %d accepted.\n", accepted->id);

	if (addr && addrlen) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = accepted->dport;
		addr_in->sin_addr.s_addr = accepted->daddr;
		*addrlen = sizeof(struct sockaddr_in);
	}

	return accepted->socket->id;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_init_rss(mctx_t mctx, in_addr_t saddr_base, int num_addr, 
		in_addr_t daddr, in_addr_t dport)
{
	mtcp_manager_t mtcp;
	addr_pool_t ap;
	uint8_t is_external;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		errno = EACCES;
		return -1;
	}

	if (mtcp->ap) {
		TRACE_DBG("Destroying already exsiting address pool.\n"
		          "Are you calling mtcp_init_rss() multiple times?\n");
		DestroyAddressPool(mtcp->ap);
		mtcp->ap = NULL;
	}

	if (saddr_base == INADDR_ANY) {
		int nif_out, eidx;

		/* for the INADDR_ANY, find the output interface for the destination
		   and set the saddr_base as the ip address of the output interface */
		nif_out = GetOutputInterface(daddr, &is_external);
		if (nif_out < 0) {
			errno = EINVAL;
			TRACE_DBG("Could not determine nif idx!\n");
			return -1;
		}
		eidx = CONFIG.nif_to_eidx[nif_out];
		saddr_base = CONFIG.eths[eidx].ip_addr;
	}

	ap = CreateAddressPoolPerCore(mctx->cpu, num_cpus, 
			saddr_base, num_addr, daddr, dport);
	if (!ap) {
		errno = ENOMEM;
		return -1;
	}

	mtcp->ap = ap;
	UNUSED(is_external);
	
	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_connect(mctx_t mctx, int sockid, 
		const struct sockaddr *addr, socklen_t addrlen)
{
	mtcp_manager_t mtcp;
	socket_map_t socket;
	tcp_stream *cur_stream;
	struct sockaddr_in *addr_in;
	in_addr_t dip;
	in_port_t dport;
	int is_dyn_bound = FALSE;
	int ret, nif;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
		TRACE_API("Socket id %d out of range.\n", sockid);
		errno = EBADF;
		return -1;
	}

	if (mtcp->smap[sockid].socktype == MTCP_SOCK_UNUSED) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = EBADF;
		return -1;
	}
	
	if (mtcp->smap[sockid].socktype != MTCP_SOCK_STREAM) {
		TRACE_API("Not an end socket. id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	if (!addr) {
		TRACE_API("Socket %d: empty address!\n", sockid);
		errno = EFAULT;
		return -1;
	}

	/* we only allow bind() for AF_INET address */
	if (addr->sa_family != AF_INET || addrlen < sizeof(struct sockaddr_in)) {
		TRACE_API("Socket %d: invalid argument!\n", sockid);
		errno = EAFNOSUPPORT;
		return -1;
	}

	socket = &mtcp->smap[sockid];
	if (socket->stream) {
		TRACE_API("Socket %d: stream already exist!\n", sockid);
		if (socket->stream->state >= TCP_ST_ESTABLISHED) {
			errno = EISCONN;
		} else {
			errno = EALREADY;
		}
		return -1;
	}

	addr_in = (struct sockaddr_in *)addr;
	dip = addr_in->sin_addr.s_addr;
	dport = addr_in->sin_port;

	/* address binding */
	if ((socket->opts & MTCP_ADDR_BIND) && 
	    socket->saddr.sin_port != INPORT_ANY &&
	    socket->saddr.sin_addr.s_addr != INADDR_ANY) {
		int rss_core;
		uint8_t endian_check = FetchEndianType();
		
		rss_core = GetRSSCPUCore(socket->saddr.sin_addr.s_addr, dip, 
					 socket->saddr.sin_port, dport, num_queues, endian_check);
		
		if (rss_core != mctx->cpu) {
			errno = EINVAL;
			return -1;
		}
	} else {
		if (mtcp->ap) {
			ret = FetchAddressPerCore(mtcp->ap, 
						  mctx->cpu, num_queues, addr_in, &socket->saddr);
		} else {
			uint8_t is_external;
			nif = GetOutputInterface(dip, &is_external);
			if (nif < 0) {
				errno = EINVAL;
				return -1;
			}
			ret = FetchAddress(ap[nif], 
					   mctx->cpu, num_queues, addr_in, &socket->saddr);
			UNUSED(is_external);
		}
		if (ret < 0) {
			errno = EAGAIN;
			return -1;
		}
		socket->opts |= MTCP_ADDR_BIND;
		is_dyn_bound = TRUE;
	}
	
	cur_stream = CreateTCPStream(mtcp, socket, socket->socktype, 
			socket->saddr.sin_addr.s_addr, socket->saddr.sin_port, dip, dport);
	
	if (!cur_stream) {
		TRACE_ERROR("Socket %d: failed to create tcp_stream!\n", sockid);
		errno = ENOMEM;
		return -1;
	}
	
	if (is_dyn_bound)
		cur_stream->is_bound_addr = TRUE;
	cur_stream->sndvar->cwnd = 1;
	cur_stream->sndvar->ssthresh = cur_stream->sndvar->mss * 10;

	cur_stream->state = TCP_ST_SYN_SENT;
	TRACE_STATE("Stream %d: TCP_ST_SYN_SENT\n", cur_stream->id);
	
	SQ_LOCK(&mtcp->ctx->connect_lock);
	ret = StreamEnqueue(mtcp->connectq, cur_stream);
	SQ_UNLOCK(&mtcp->ctx->connect_lock);
	mtcp->wakeup_flag = TRUE;
	if (ret < 0) {
		TRACE_ERROR("Socket %d: failed to enqueue to conenct queue!\n", sockid);
		SQ_LOCK(&mtcp->ctx->destroyq_lock);
		StreamEnqueue(mtcp->destroyq, cur_stream);
		SQ_UNLOCK(&mtcp->ctx->destroyq_lock);
		errno = EAGAIN;
		return -1;
	}
	
	/* if nonblocking socket, return EINPROGRESS */
	if (socket->opts & MTCP_NONBLOCK) {
		errno = EINPROGRESS;
		TRACE_INFO("nonblocking socket\n");
		return -1;

	} else {
		while (1) {
			if (!cur_stream) {
				TRACE_ERROR("STREAM DESTROYED\n");
				errno = ETIMEDOUT;
				return -1;
			}
			if (cur_stream->state > TCP_ST_ESTABLISHED) {
				TRACE_ERROR("Socket %d: weird state %s\n", 
						sockid, TCPStateToString(cur_stream));
				// TODO: how to handle this?
				errno = ENOSYS;
				return -1;
			}
			TRACE_INFO("infinite loop?");
			if (cur_stream->state == TCP_ST_ESTABLISHED) {
				break;
			}
			usleep(1000);
		}
	}
	
	return 0;
}
/*----------------------------------------------------------------------------*/
static inline int 
CloseStreamSocket(mctx_t mctx, int sockid)
{
	mtcp_manager_t mtcp;
	tcp_stream *cur_stream;
	int ret;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	cur_stream = mtcp->smap[sockid].stream;
	if (!cur_stream) {
		TRACE_API("Socket %d: stream does not exist.\n", sockid);
		errno = ENOTCONN;
		return -1;
	}

	if (cur_stream->closed) {
		TRACE_API("Socket %d (Stream %u): already closed stream\n", 
				sockid, cur_stream->id);
		return 0;
	}
	cur_stream->closed = TRUE;
		
	TRACE_API("Stream %d: closing the stream.\n", cur_stream->id);

	cur_stream->socket = NULL;

	if (cur_stream->state == TCP_ST_CLOSED) {
		TRACE_API("Stream %d at TCP_ST_CLOSED. destroying the stream.\n", 
				cur_stream->id);
		SQ_LOCK(&mtcp->ctx->destroyq_lock);
		StreamEnqueue(mtcp->destroyq, cur_stream);
		mtcp->wakeup_flag = TRUE;
		SQ_UNLOCK(&mtcp->ctx->destroyq_lock);
		return 0;

	} else if (cur_stream->state == TCP_ST_SYN_SENT) {
#if 1
		SQ_LOCK(&mtcp->ctx->destroyq_lock);
		StreamEnqueue(mtcp->destroyq, cur_stream);
		SQ_UNLOCK(&mtcp->ctx->destroyq_lock);
		mtcp->wakeup_flag = TRUE;
#endif
		return -1;

	} else if (cur_stream->state != TCP_ST_ESTABLISHED && 
			cur_stream->state != TCP_ST_CLOSE_WAIT) {
		TRACE_API("Stream %d at state %s\n", 
				cur_stream->id, TCPStateToString(cur_stream));
		errno = EBADF;
		return -1;
	}
	
	SQ_LOCK(&mtcp->ctx->close_lock);
	cur_stream->sndvar->on_closeq = TRUE;
	ret = StreamEnqueue(mtcp->closeq, cur_stream);
	mtcp->wakeup_flag = TRUE;
	SQ_UNLOCK(&mtcp->ctx->close_lock);

	if (ret < 0) {
		TRACE_ERROR("(NEVER HAPPEN) Failed to enqueue the stream to close.\n");
		errno = EAGAIN;
		return -1;
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
static inline int 
CloseListeningSocket(mctx_t mctx, int sockid)
{
	mtcp_manager_t mtcp;
	struct tcp_listener *listener;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	listener = mtcp->smap[sockid].listener;
	if (!listener) {
		errno = EINVAL;
		return -1;
	}

	if (listener->acceptq) {
		DestroyStreamQueue(listener->acceptq);
		listener->acceptq = NULL;
	}

	pthread_mutex_lock(&listener->accept_lock);
	pthread_cond_signal(&listener->accept_cond);
	pthread_mutex_unlock(&listener->accept_lock);

	pthread_cond_destroy(&listener->accept_cond);
	pthread_mutex_destroy(&listener->accept_lock);

	free(listener);
	mtcp->smap[sockid].listener = NULL;

	return 0;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_close(mctx_t mctx, int sockid)
{
	mtcp_manager_t mtcp;
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

	if (mtcp->smap[sockid].socktype == MTCP_SOCK_UNUSED) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = EBADF;
		return -1;
	}

	TRACE_API("Socket %d: mtcp_close called.\n", sockid);

	switch (mtcp->smap[sockid].socktype) {
	case MTCP_SOCK_STREAM:
		ret = CloseStreamSocket(mctx, sockid);
		break;

	case MTCP_SOCK_LISTENER:
		ret = CloseListeningSocket(mctx, sockid);
		break;

	case MTCP_SOCK_EPOLL:
		ret = CloseEpollSocket(mctx, sockid);
		break;

	case MTCP_SOCK_PIPE:
		ret = PipeClose(mctx, sockid);
		break;

	default:
		errno = EINVAL;
		ret = -1;
		break;
	}
	
	FreeSocket(mctx, sockid, FALSE);
	//TRACE_INFO("Fre socket, sockid=%d\n", sockid);
	return ret;
}
/*----------------------------------------------------------------------------*/
int 
mtcp_abort(mctx_t mctx, int sockid)
{
	mtcp_manager_t mtcp;
	tcp_stream *cur_stream;
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

	if (mtcp->smap[sockid].socktype == MTCP_SOCK_UNUSED) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = EBADF;
		return -1;
	}
	
	if (mtcp->smap[sockid].socktype != MTCP_SOCK_STREAM) {
		TRACE_API("Not an end socket. id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	cur_stream = mtcp->smap[sockid].stream;
	if (!cur_stream) {
		TRACE_API("Stream %d: does not exist.\n", sockid);
		errno = ENOTCONN;
		return -1;
	}

	TRACE_API("Socket %d: mtcp_abort()\n", sockid);
	
	FreeSocket(mctx, sockid, FALSE);
	cur_stream->socket = NULL;

	if (cur_stream->state == TCP_ST_CLOSED) {
		TRACE_API("Stream %d: connection already reset.\n", sockid);
		return ERROR;

	} else if (cur_stream->state == TCP_ST_SYN_SENT) {
		/* TODO: this should notify event failure to all 
		   previous read() or write() calls */
		cur_stream->state = TCP_ST_CLOSED;
		cur_stream->close_reason = TCP_ACTIVE_CLOSE;
		TRACE_CLOSE_REASON("TCP_ACTIVE_CLOSE\n");
		SQ_LOCK(&mtcp->ctx->destroyq_lock);
		StreamEnqueue(mtcp->destroyq, cur_stream);
		SQ_UNLOCK(&mtcp->ctx->destroyq_lock);
		mtcp->wakeup_flag = TRUE;
		return 0;

	} else if (cur_stream->state == TCP_ST_CLOSING || 
			cur_stream->state == TCP_ST_LAST_ACK || 
			cur_stream->state == TCP_ST_TIME_WAIT) {
		cur_stream->state = TCP_ST_CLOSED;
		cur_stream->close_reason = TCP_ACTIVE_CLOSE;
		TRACE_CLOSE_REASON("TCP_ACTIVE_CLOSE\n");
		SQ_LOCK(&mtcp->ctx->destroyq_lock);
		StreamEnqueue(mtcp->destroyq, cur_stream);
		SQ_UNLOCK(&mtcp->ctx->destroyq_lock);
		mtcp->wakeup_flag = TRUE;
		return 0;
	}

	/* the stream structure will be destroyed after sending RST */
	if (cur_stream->sndvar->on_resetq) {
		TRACE_ERROR("Stream %d: calling mtcp_abort() "
				"when in reset queue.\n", sockid);
		errno = ECONNRESET;
		return -1;
	}
	SQ_LOCK(&mtcp->ctx->reset_lock);
	cur_stream->sndvar->on_resetq = TRUE;
	ret = StreamEnqueue(mtcp->resetq, cur_stream);
	SQ_UNLOCK(&mtcp->ctx->reset_lock);
	mtcp->wakeup_flag = TRUE;

	if (ret < 0) {
		TRACE_ERROR("(NEVER HAPPEN) Failed to enqueue the stream to close.\n");
		errno = EAGAIN;
		return -1;
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
static inline int
PeekForUser(mtcp_manager_t mtcp, tcp_stream *cur_stream, char *buf, int len)
{
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	int copylen;
	
	copylen = MIN(rcvvar->rcvbuf->merged_len, len);
	if (copylen <= 0) {
		errno = EAGAIN;
		return -1;
	}

	/* Only copy data to user buffer */
	memcpy(buf, rcvvar->rcvbuf->head, copylen);
	
	return copylen;
}
/*----------------------------------------------------------------------------*/
static inline int
CopyToUser(mtcp_manager_t mtcp, tcp_stream *cur_stream, char *buf, int len)
{
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	uint32_t prev_rcv_wnd;
	int copylen;

	copylen = MIN(rcvvar->rcvbuf->merged_len, len);
	if (copylen <= 0) {
		errno = EAGAIN;
		return -1;
	}

	prev_rcv_wnd = rcvvar->rcv_wnd;
	/* Copy data to user buffer and remove it from receiving buffer */
	memcpy(buf, rcvvar->rcvbuf->head, copylen);
	RBRemove(mtcp->rbm_rcv, rcvvar->rcvbuf, copylen, AT_APP);
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;

	/* Advertise newly freed receive buffer */
	if (cur_stream->need_wnd_adv) {
		if (rcvvar->rcv_wnd > cur_stream->sndvar->eff_mss) {
			if (!cur_stream->sndvar->on_ackq) {
				SQ_LOCK(&mtcp->ctx->ackq_lock);
				cur_stream->sndvar->on_ackq = TRUE;
				StreamEnqueue(mtcp->ackq, cur_stream); /* this always success */
				SQ_UNLOCK(&mtcp->ctx->ackq_lock);
				cur_stream->need_wnd_adv = FALSE;
				mtcp->wakeup_flag = TRUE;
			}
		}
	}

	UNUSED(prev_rcv_wnd);
	return copylen;
}
/*----------------------------------------------------------------------------*/
ssize_t
mtcp_recv(mctx_t mctx, int sockid, char *buf, size_t len, int flags)
{
	mtcp_manager_t mtcp;
	socket_map_t socket;
	tcp_stream *cur_stream;
	struct tcp_recv_vars *rcvvar;
	int event_remaining;
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
		return PipeRead(mctx, sockid, buf, len);
	}
	
	if (socket->socktype != MTCP_SOCK_STREAM) {
		TRACE_API("Not an end socket. id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}
	
	/* stream should be in ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT */
	cur_stream = socket->stream;
        if (!cur_stream || 
	    !(cur_stream->state >= TCP_ST_ESTABLISHED && 
	      cur_stream->state <= TCP_ST_CLOSE_WAIT)) {
		errno = ENOTCONN;
		return -1;
	}

	rcvvar = cur_stream->rcvvar;
	
	/* if CLOSE_WAIT, return 0 if there is no payload */
	if (cur_stream->state == TCP_ST_CLOSE_WAIT) {
		if (!rcvvar->rcvbuf)
			return 0;
		
		if (rcvvar->rcvbuf->merged_len == 0)
			return 0;
        }
	
	/* return EAGAIN if no receive buffer */
	if (socket->opts & MTCP_NONBLOCK) {
		if (!rcvvar->rcvbuf || rcvvar->rcvbuf->merged_len == 0) {
			errno = EAGAIN;
			return -1;
		}
	}
	
	SBUF_LOCK(&rcvvar->read_lock);
#if BLOCKING_SUPPORT
	if (!(socket->opts & MTCP_NONBLOCK)) {
		while (rcvvar->rcvbuf->merged_len == 0) {
			if (!cur_stream || cur_stream->state != TCP_ST_ESTABLISHED) {
				SBUF_UNLOCK(&rcvvar->read_lock);
				errno = EINTR;
				return -1;
			}
			pthread_cond_wait(&rcvvar->read_cond, &rcvvar->read_lock);
		}
	}
#endif

	switch (flags) {
	case 0:
		ret = CopyToUser(mtcp, cur_stream, buf, len);
		break;
	case MSG_PEEK:
		ret = PeekForUser(mtcp, cur_stream, buf, len);
		break;
	default:
		SBUF_UNLOCK(&rcvvar->read_lock);
		ret = -1;
		errno = EINVAL;
		return ret;
	}
	
	event_remaining = FALSE;
        /* if there are remaining payload, generate EPOLLIN */
	/* (may due to insufficient user buffer) */
	if (socket->epoll & MTCP_EPOLLIN) {
		if (!(socket->epoll & MTCP_EPOLLET) && rcvvar->rcvbuf->merged_len > 0) {
			event_remaining = TRUE;
		}
	}
        /* if waiting for close, notify it if no remaining data */
	if (cur_stream->state == TCP_ST_CLOSE_WAIT && 
	    rcvvar->rcvbuf->merged_len == 0 && ret > 0) {
		event_remaining = TRUE;
	}
	
	SBUF_UNLOCK(&rcvvar->read_lock);
	
	if (event_remaining) {
		if (socket->epoll) {
			AddEpollEvent(mtcp->ep, 
				      USR_SHADOW_EVENT_QUEUE, socket, MTCP_EPOLLIN);
#if BLOCKING_SUPPORT
		} else if (!(socket->opts & MTCP_NONBLOCK)) {
			if (!cur_stream->on_rcv_br_list) {
				cur_stream->on_rcv_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->rcv_br_list, 
						  cur_stream, rcvvar->rcv_br_link);
				mtcp->rcv_br_list_cnt++;
			}
#endif
		}
	}
	
	TRACE_API("Stream %d: mtcp_recv() returning %d\n", cur_stream->id, ret);
        return ret;
}
/*----------------------------------------------------------------------------*/
inline ssize_t
mtcp_read(mctx_t mctx, int sockid, char *buf, size_t len)
{
	return mtcp_recv(mctx, sockid, buf, len, 0);
}
/*----------------------------------------------------------------------------*/
int
mtcp_readv(mctx_t mctx, int sockid, const struct iovec *iov, int numIOV)
{
	mtcp_manager_t mtcp;
	socket_map_t socket;
	tcp_stream *cur_stream;
	struct tcp_recv_vars *rcvvar;
	int ret, bytes_read, i;
	int event_remaining;

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
	
	if (socket->socktype != MTCP_SOCK_STREAM) {
		TRACE_API("Not an end socket. id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	/* stream should be in ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT */
	cur_stream = socket->stream;
	if (!cur_stream || 
			!(cur_stream->state >= TCP_ST_ESTABLISHED && 
			  cur_stream->state <= TCP_ST_CLOSE_WAIT)) {
		errno = ENOTCONN;
		return -1;
	}

	rcvvar = cur_stream->rcvvar;

	/* if CLOSE_WAIT, return 0 if there is no payload */
	if (cur_stream->state == TCP_ST_CLOSE_WAIT) {
		if (!rcvvar->rcvbuf)
			return 0;
		
		if (rcvvar->rcvbuf->merged_len == 0)
			return 0;
	}

	/* return EAGAIN if no receive buffer */
	if (socket->opts & MTCP_NONBLOCK) {
		if (!rcvvar->rcvbuf || rcvvar->rcvbuf->merged_len == 0) {
			errno = EAGAIN;
			return -1;
		}
	}
	
	SBUF_LOCK(&rcvvar->read_lock);
#if BLOCKING_SUPPORT
	if (!(socket->opts & MTCP_NONBLOCK)) {
		while (rcvvar->rcvbuf->merged_len == 0) {
			if (!cur_stream || cur_stream->state != TCP_ST_ESTABLISHED) {
				SBUF_UNLOCK(&rcvvar->read_lock);
				errno = EINTR;
				return -1;
			}
			pthread_cond_wait(&rcvvar->read_cond, &rcvvar->read_lock);
		}
	}
#endif

	/* read and store the contents to the vectored buffers */ 
	bytes_read = 0;
	for (i = 0; i < numIOV; i++) {
		if (iov[i].iov_len <= 0)
			continue;

		ret = CopyToUser(mtcp, cur_stream, iov[i].iov_base, iov[i].iov_len);
		if (ret <= 0)
			break;

		bytes_read += ret;

		if (ret < iov[i].iov_len)
			break;
	}

	event_remaining = FALSE;
	/* if there are remaining payload, generate read event */
	/* (may due to insufficient user buffer) */
	if (socket->epoll & MTCP_EPOLLIN) {
		if (!(socket->epoll & MTCP_EPOLLET) && rcvvar->rcvbuf->merged_len > 0) {
			event_remaining = TRUE;
		}
	}
	/* if waiting for close, notify it if no remaining data */
	if (cur_stream->state == TCP_ST_CLOSE_WAIT && 
			rcvvar->rcvbuf->merged_len == 0 && bytes_read > 0) {
		event_remaining = TRUE;
	}

	SBUF_UNLOCK(&rcvvar->read_lock);

	if(event_remaining) {
		if ((socket->epoll & MTCP_EPOLLIN) && !(socket->epoll & MTCP_EPOLLET)) {
			AddEpollEvent(mtcp->ep, 
					USR_SHADOW_EVENT_QUEUE, socket, MTCP_EPOLLIN);
#if BLOCKING_SUPPORT
		} else if (!(socket->opts & MTCP_NONBLOCK)) {
			if (!cur_stream->on_rcv_br_list) {
				cur_stream->on_rcv_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->rcv_br_list, 
						cur_stream, rcvvar->rcv_br_link);
				mtcp->rcv_br_list_cnt++;
			}
#endif
		}
	}

	TRACE_API("Stream %d: mtcp_readv() returning %d\n", 
			cur_stream->id, bytes_read);
	return bytes_read;
}
/*----------------------------------------------------------------------------*/
static inline int 
CopyFromUser(mtcp_manager_t mtcp, tcp_stream *cur_stream, const char *buf, int len)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	int sndlen;
	int ret;

#if ENABLE_FLEX_BUFFER
	sndlen = len;
#else
	sndlen = MIN((int)sndvar->snd_wnd, len);
	if (sndlen <= 0) {
		errno = EAGAIN;
		return -1;
	}
#endif
	/* allocate send buffer if not exist */
	if (!sndvar->sndbuf) {
		sndvar->sndbuf = SBInit(mtcp->rbm_snd, sndvar->iss + 1);
		if (!sndvar->sndbuf) {
			cur_stream->close_reason = TCP_NO_MEM;
			/* notification may not required due to -1 return */
			errno = ENOMEM;
			return -1;
		}
	}

	ret = SBPut(mtcp->rbm_snd, sndvar->sndbuf, buf, sndlen);
	assert(ret == sndlen);
	if (ret == 0) {
		errno = EAGAIN;
		return -1;
	}
#if !ENABLE_FLEX_BUFFER
	sndvar->snd_wnd = sndvar->sndbuf->size - sndvar->sndbuf->len;
	if (ret <= 0) {
		TRACE_ERROR("SBPut failed. reason: %d (sndlen: %u, len: %u\n", 
				ret, sndlen, sndvar->sndbuf->len);
		errno = EAGAIN;
		return -1;
	}
	
	if (sndvar->snd_wnd <= 0) {
		TRACE_SNDBUF("%u Sending buffer became full!! snd_wnd: %u\n", 
				cur_stream->id, sndvar->snd_wnd);
	}
#endif

	return ret;
}
/*----------------------------------------------------------------------------*/
ssize_t
mtcp_write(mctx_t mctx, int sockid, const char *buf, size_t len)
{
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
		return PipeWrite(mctx, sockid, buf, len);
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

	if (len <= 0) {
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
#if !ENABLE_FLEX_BUFFER
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
#endif /* !ENABLE_FLEX_BUFFER */
#endif

	ret = CopyFromUser(mtcp, cur_stream, buf, len);

	SBUF_UNLOCK(&sndvar->write_lock);

#if 0
	if (ret > 0 && !(sndvar->on_sendq || sndvar->on_send_list)) {
		SQ_LOCK(&mtcp->ctx->sendq_lock);
		sndvar->on_sendq = TRUE;
		StreamEnqueue(mtcp->sendq, cur_stream);		/* this always success */
		SQ_UNLOCK(&mtcp->ctx->sendq_lock);
		mtcp->wakeup_flag = TRUE;
	}
#endif

	if (ret == 0 && (socket->opts & MTCP_NONBLOCK)) {
		ret = -1;
		errno = EAGAIN;
	}

	/* if there are remaining sending buffer, generate write event */
#if !ENABLE_FLEX_BUFFER
	if (sndvar->snd_wnd > 0) {
#endif
		if ((socket->epoll & MTCP_EPOLLOUT) && !(socket->epoll & MTCP_EPOLLET)) {
			AddEpollEvent(mtcp->ep, 
					USR_SHADOW_EVENT_QUEUE, socket, MTCP_EPOLLOUT);
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
/*----------------------------------------------------------------------------*/
int
mtcp_writev(mctx_t mctx, int sockid, const struct iovec *iov, int numIOV)
{
	mtcp_manager_t mtcp;
	socket_map_t socket;
	tcp_stream *cur_stream;
	struct tcp_send_vars *sndvar;
	int ret, to_write, i;

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
	//TRACE_INFO("sockid = %d, socktype = %u\n", sockid, socket->socktype);
	if (socket->socktype == MTCP_SOCK_UNUSED) {
		TRACE_API("Invalid socket id: %d\n", sockid);
		errno = EBADF;
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

	sndvar = cur_stream->sndvar;
	SBUF_LOCK(&sndvar->write_lock);
#if BLOCKING_SUPPORT
#if !ENABLE_FLEX_BUFFER
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
#endif /* !ENABLE_FLEX_BUFFER */
#endif

	/* write from the vectored buffers */ 
	to_write = 0;
	for (i = 0; i < numIOV; i++) {
		if (iov[i].iov_len <= 0)
			continue;

		ret = CopyFromUser(mtcp, cur_stream, iov[i].iov_base, iov[i].iov_len);
		if (ret <= 0)
			break;

		to_write += ret;

		if (ret < iov[i].iov_len)
			break;
	}
	SBUF_UNLOCK(&sndvar->write_lock);

//	SQ_LOCK(&mtcp->ctx->sendq_lock);
#if 0
	if (to_write > 0 && !(sndvar->on_sendq || sndvar->on_send_list)) {
		SQ_LOCK(&mtcp->ctx->sendq_lock);
		sndvar->on_sendq = TRUE;
		StreamEnqueue(mtcp->sendq, cur_stream);		/* this always success */
		SQ_UNLOCK(&mtcp->ctx->sendq_lock);
		mtcp->wakeup_flag = TRUE;
	}
#endif
//	SQ_UNLOCK(&mtcp->ctx->sendq_lock);

	if (to_write == 0 && (socket->opts & MTCP_NONBLOCK)) {
		to_write = -1;
		errno = EAGAIN;
	}

	/* if there are remaining sending buffer, generate write event */
#if !ENABLE_FLEX_BUFFER
	if (sndvar->snd_wnd > 0) {
#endif
		if ((socket->epoll & MTCP_EPOLLOUT) && !(socket->epoll & MTCP_EPOLLET)) {
			AddEpollEvent(mtcp->ep, 
					USR_SHADOW_EVENT_QUEUE, socket, MTCP_EPOLLOUT);
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

	TRACE_API("Stream %d: mtcp_writev() returning %d\n", 
			cur_stream->id, to_write);
	return to_write;
}
/*----------------------------------------------------------------------------*/
#if ENABLE_NIC_CACHE

#include "nic_cache.h"
#if SHOW_NIC_CACHE_STATISTICS
static const char *nvme_str[] = {
	"nvme0",
	"nvme1",
	"nvme2",
	"nvme3",
	"nvme4",
	"nvme5",
	"nvme6",
	"nvme7",
	"nvme8",
	"nvme9",
};

inline static void
__incr_num_nvmeReqs(mtcp_manager_t mtcp, const char *url) {
	int idx;
	char *p = NULL;
	for (idx = 0; idx < NUM_NVME; idx++) {
		p = strstr(url, nvme_str[idx]);
		if (p) break;
	}
	g_nic_cache_stat[mtcp->ctx->cpu].num_nvmeReqs[idx]++;
}
#endif

int
nic_cache_send(mctx_t mctx, int sockid, char *url, size_t url_len)
{
	/* TODO : Translation from URL to Absolute Path */
	mtcp_manager_t mtcp;
	socket_map_t socket;
	tcp_stream *cur_stream;
	struct tcp_send_vars *sndvar;
	int ret;
	uint64_t hv;
	uint32_t sz;
	void *block_map;
	int numBlocks;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
		TRACE_API("Socket id %d out of range.\n", sockid);
		errno = EBADF;
		return - 1;
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
		TRACE_API("Not an end socket. id : %d\n", sockid);
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
#if SHOW_NIC_CACHE_STATISTICS && SHOW_NUM_REQS_PER_NVME
	__incr_num_nvmeReqs(mtcp, url);
#endif

	sndvar = cur_stream->sndvar;
	ret = nic_cache_get_obj_hv(mtcp->ctx->cpu, cur_stream->id, url, url_len, 
			&hv, &sz, &block_map, &numBlocks);
	if (ret < 0) {
#if SHOW_NIC_CACHE_STATISTICS
		g_nic_cache_stat[mtcp->ctx->cpu].numReqs++;
		g_nic_cache_stat[mtcp->ctx->cpu].numDiskReads++;
#endif

#ifdef CHECK_CONTROLPLANE_ACCESS_LATENCY
		sndvar->sndbuf->obj_hv = hv;
#endif

#if DISABLE_FRD_OFFLOAD
		return HOST_SEND_PAYLOAD;
#endif
		ssize_t file_length;
		int fd;

		fd = open(url, O_RDONLY);
		if (fd < 0) {
			TRACE_ERROR("open(), %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		file_length = lseek(fd, 0, SEEK_END);
		close(fd);

		if (foc_setup_offload(mtcp, url, file_length, cur_stream, mtcp->cur_ts) < 0) {
			return HOST_SEND_PAYLOAD;
		}
		return file_length;
	}
#if 0
	if (!rate_limit_cache_can_send_now(mtcp, sz)) {
		nic_cache_free_obj_by_hv(mtcp->ctx->cpu, cur_stream->id, hv);
#if SHOW_NIC_CACHE_STATISTICS
		g_nic_cache_stat[mtcp->ctx->cpu].numReqs++;
		g_nic_cache_stat[mtcp->ctx->cpu].numDiskReads++;
#endif
		return HOST_SEND_PAYLOAD;
	}
#endif

#if ENABLE_FLOW_SCHED
	/* Setup priority */
	//cur_stream->prio = TCP_STREAM_SEND_PRIO_META;
	cur_stream->prio = TCP_STREAM_SEND_PRIO_NORMAL;
#endif

	SBUF_LOCK(&sndvar->write_lock);

	ret = SBMetaPut(mtcp->rbm_snd, sndvar->sndbuf, hv, sz, block_map, numBlocks);
	if (ret == 0) {
		TRACE_ERROR("Fail to push meta payload at msb.\n");
		nic_cache_free_obj_by_hv(mtcp->ctx->cpu, cur_stream->id, hv);
#if SHOW_NIC_CACHE_STATISTICS
		g_nic_cache_stat[mtcp->ctx->cpu].numReqs++;
		g_nic_cache_stat[mtcp->ctx->cpu].numDiskReads++;
#endif
		return HOST_SEND_PAYLOAD;
	}

#if SHOW_NIC_CACHE_STATISTICS
	g_nic_cache_stat[mtcp->ctx->cpu].numReqs++;
	if (numBlocks == -1)
		g_nic_cache_stat[mtcp->ctx->cpu].numL1Hits++;
	else 
		g_nic_cache_stat[mtcp->ctx->cpu].numL2Hits++;
#endif

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
	SBUF_UNLOCK(&sndvar->write_lock);

	NIC_CACHE_LOG_LOCK("Add meta object to Meta Buffer, ret=%u, on_sendq=%u, on_send_list=%u, "
			"cur_stream=%p, total_buf_size=%u\n", 
			ret, sndvar->on_sendq, sndvar->on_send_list, 
			cur_stream, sndvar->sndbuf->total_buf_size);

	SQ_LOCK(&mtcp->ctx->sendq_lock);
	if (ret > 0 && !(sndvar->on_sendq || sndvar->on_send_list)) {
		sndvar->on_sendq = TRUE;
		StreamEnqueue(mtcp->sendq, cur_stream);         /* this always success */
		mtcp->wakeup_flag = TRUE;
	}
	SQ_UNLOCK(&mtcp->ctx->sendq_lock);

	if (ret == 0 && (socket->opts & MTCP_NONBLOCK)) {
		ret = -1;
		errno = EAGAIN;
	}
	/*TRACE_INFO("Complete to add meta object to Meta buffer, on_sendq=%u, on_send_list=%u\n",
			sndvar->on_sendq, sndvar->on_send_list);*/

	/* if there are remaining sending buffer, generate write event */
	if (sndvar->snd_wnd > 0) {
		if ((socket->epoll & MTCP_EPOLLOUT) && !(socket->epoll & MTCP_EPOLLET)) {
			AddEpollEvent(mtcp->ep, USR_SHADOW_EVENT_QUEUE, socket, MTCP_EPOLLOUT);
#if BLOCKING_SUPPORT
		} else if (!(socket->opts & MTCP_NONBLOCK)) {
			if (!cur_stream->on_snd_br_list) {
				cur_stream->on_snd_br_list = TRUE;
				TAILQ_INSERT_TAIL(&mtcp->snd_br_list, cur_stream, sndvar->snd_br_link);
				mtcp->snd_br_list_cnt++;
			}
#endif
		}
	}

	TRACE_API("Stream %d: mtcp_write() returning %d\n", cur_stream->id, ret);
	return ret;
}
#else /* ENABLE_NIC_CACHE */
int
nic_cache_send(mctx_t mctx, int sockid, char *url, size_t url_len) {
	UNUSED(mctx);
	UNUSED(sockid);
	UNUSED(url);
	UNUSED(url_len);
	fprintf(stderr, "[FATAL ERROR] nic_cache send cannot run, check compile option at mtcp\n");
	return 0;
}
#endif /* ENABLE_NIC_CACHE */
/*----------------------------------------------------------------------------*/
#if 0
static inline int
DiskIOFromFile(mtcp_manager_t mtcp, tcp_stream *cur_stream, int in_fd, off_t *offset, size_t count) 
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	int sndlen;
	int ret;

	/* allocate send buffer if not exist */
	sndlen = MIN((int)sndvar->snd_wnd, count);
	if (sndlen <= 0) {
		errno = EAGAIN;
		return -1;
	}

	if (!sndvar->sndbuf) {
		sndvar->sndbuf = SBInit(mtcp->rbm_snd, sndvar->iss + 1);
		if (!sndvar->sndbuf) {
			cur_stream->close_reason = TCP_NO_MEM;
			errno = ENOMEM;
			return -1;
		}
	}

	ret = SBPutFromFile(sndvar->sndbuf, in_fd, offset, count);
	assert(ret == sndlen);
	sndvar->snd_wnd = sndvar->sndbuf->size - sndvar->sndbuf->len;
	if (ret <= 0) {
		TRACE_ERROR("SBPutFromFile failed. reason: %d (sndlen: %u, len: %u)\n",
				ret, sndlen, sndvar->sndbuf->len);
	}

	if (sndvar->snd_wnd <= 0) {
		TRACE_SNDBUF("%u Sending buffer became full!! snd_wnd: %u\n",
				cur_stream->id, sndvar->snd_wnd);
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
ssize_t
mtcp_sendfile(mctx_t mctx, int sockid, int in_fd, off_t *offset, size_t count) {
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

	ret = DiskIOFromFile(mtcp, cur_stream, in_fd, offset, count);

	SBUF_UNLOCK(&sndvar->write_lock);

	if (ret > 0 && !(sndvar->on_sendq || sndvar->on_send_list)) {
		SQ_LOCK(&mtcp->ctx->sendq_lock);
		sndvar->on_sendq = TRUE;
		StreamEnqueue(mtcp->sendq, cur_stream);		/* this always success */
		SQ_UNLOCK(&mtcp->ctx->sendq_lock);
		mtcp->wakeup_flag = TRUE;
	}

	if (ret == 0 && (socket->opts & MTCP_NONBLOCK)) {
		ret = -1;
		errno = EAGAIN;
	}

	/* if there are remaining sending buffer, generate write event */
	if (sndvar->snd_wnd > 0) {
		if ((socket->epoll & MTCP_EPOLLOUT) && !(socket->epoll & MTCP_EPOLLET)) {
			AddEpollEvent(mtcp->ep, 
					USR_SHADOW_EVENT_QUEUE, socket, MTCP_EPOLLOUT);
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
	}

	TRACE_API("Stream %d: mtcp_write() returning %d\n", cur_stream->id, ret);
	return ret;

}
#endif
/*----------------------------------------------------------------------------*/
