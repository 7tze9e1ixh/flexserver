#ifndef __FLEX_DEBUG_H__
#define __FLEX_DEBUG_H__

#include "debug.h"

#define DBG_SND 0
#define DBG_RCV 0
#define DBG_RATE_LIMIT 0
#define DUMP_FLEX_LOG 0
#define DUMP_RATE_LIMIT 0

#if DBG_SND
#define TRACE_SND(f, ...) TRACE_INFO(f, ##__VA_ARGS__)
#else
#define TRACE_SND(f, ...) (void)0
#endif

#if DBG_RCV
#define TRACE_RCV(f, ...) TRACE_INFO(f, ##__VA_ARGS__)
#else
#define TRACE_RCV(f, ...) (void)0
#endif


#if DBG_RATE_LIMIT
#define TRACE_RATE_LIMIT(f, ...) TRACE_INFO(f, ##__VA_ARGS__)
#else
#define TRACE_RATE_LIMIT(f, ...) (void)0
#endif

void
flex_log_buf_setup(void);

void
flex_log_buf_destroy(void);

void
flex_dump_log(char *log, ...);


#if DUMP_RATE_LIMIT && DUMP_FLEX_LOG
#define LOG_RATE_LIMIT(f, ...) flex_dump_log(f, ##__VA_ARGS__)
#else
#define LOG_RATE_LIMIT(f, ...) (void)0
#endif

#endif /* __FLEX_DEBUG_H__ */
