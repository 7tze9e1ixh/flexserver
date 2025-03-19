#ifndef __LOG_H__
#define __LOG_H__

#include "core.h"

#define LOG_BUF_SIZE (32 * 1024 * 1024)
#define FLUSH_PERIOD 2 // seconds

void log_setup(void);
void log_write(char *log, size_t log_len);
void log_pkt_rtt(uint64_t o_rtt, uint64_t e_rtt, uint64_t o_time);
void log_teardown(void);
#endif
