#ifndef __DEBUG_H__
#define __DEBUG_H__

#include "core.h"
#include "log.h"

void debug_setup(void);
void dump_log(char *filename, int line, char *log, ...);
void debug_teardown(void);

#define DBG FALSE
#define DBG_CACHE FALSE
#define DBG_INACTIVE FALSE

#define DBG_RTT FALSE
#define DBG_REC_CNT FALSE
#define DBG_CACHE_MEM_STATE FALSE
#define DBG_SINGLE_CLIENT FALSE

#define PRINT_CACHE_RESOURCE FALSE
#define ENABLE_DUMP_LOG TRUE
#define SHOW_OBJ_TRACE FALSE
#define SHOW_NET_STATUS FALSE

#define DUMP_OBJ_URL_AND_HV FALSE
#define DUMP_ENQUEUE_LATENCY FALSE

#if DBG_CACHE
#define LOG_CACHE(f, ...) fprintf(stderr, f, ##__VA_ARGS__);
#else
#define LOG_CACHE(f, ...) UNUSED(0)
#endif

#if DBG_RTT
#define LOG_RTT(o_rtt, e_rtt, o_time) log_pkt_rtt((o_rtt), (e_rtt), (o_time))
#else
#define LOG_RTT(o_rtt, e_rtt, o_time) UNUSED(0)
#endif

#if ENABLE_DUMP_LOG
#define DEBUG_GET_REQUEST FALSE
#define DEBUG_FREE_REQUEST FALSE
#else
#define DEBUG_GET_REQUEST FALSE
#define DEBUG_FREE_REQUEST FALSE
#endif

#define LOG_INFO(f, ...) do{\
	fprintf(stderr, "(%10s:%4d) " f, __func__, __LINE__, ##__VA_ARGS__);\
} while(0)

#define LOG_ERROR(f, ...) do {\
	fprintf(stderr, "(%10s:%4d) " f, __func__, __LINE__, ##__VA_ARGS__);\
} while(0)

#if DBG
#define DBG_TRACE(f, ...) LOG_ERROR(f, ##__VA_ARGS__)
#else
#define DBG_TRACE(f, ...) UNUSED(0)
#endif

#if ENABLE_DUMP_LOG
#define DUMP_LOG(f, ...) dump_log(NULL, -1, f, ##__VA_ARGS__)
#else
#define DUMP_LOG(f, ...) UNUSED(0)
#endif

#if DEBUG_GET_REQUEST
#define LOG_GET_REQUEST(f, ...) dump_log(__FILE__, __LINE__, f, __VA_ARGS__)
#else
#define LOG_GET_REQUEST(f, ...) UNUSED(0)
#endif

#if DEBUG_FREE_REQUEST
#define LOG_FREE_REQUEST(f, ...) dump_log(__FILE__, __LINE__, f, __VA_ARGS__)
#else
#define LOG_FREE_REQUEST(f, ...) UNUSED(0)
#endif

#if PRINT_CACHE_RESOURCE
#define PRINT_BLOCK_STATUS(f, ...) do{\
	LOG_INFO(f, ##__VA_ARGS__);\
} while(0)
#else
#define PRINT_BLOCK_STATUS(f, ...) UNUSED(0)
#endif

#endif /* __DEBUG_H__ */
