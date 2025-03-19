#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

inline static unsigned long 
get_cur_ms(void) {
	struct timespec ts_now;
	clock_gettime(CLOCK_REALTIME, &ts_now);
	return ts_now.tv_nsec / 1000000 + ts_now.tv_sec * 1000;
}

inline static unsigned long
get_cur_us(void) {
	struct timespec ts_now;
	clock_gettime(CLOCK_REALTIME, &ts_now);
	return ts_now.tv_nsec / 1000 + ts_now.tv_sec * 1000000;
}

inline static unsigned long
get_cur_ns(void) {
	struct timespec ts_now;
	clock_gettime(CLOCK_REALTIME, &ts_now);
	return ts_now.tv_nsec + ts_now.tv_sec * 1000000000;
}

inline static void
set_thread_core_affinity(int cpu) {
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

inline static size_t
get_howmany(size_t total_size, size_t unit) {
	//return total_size % unit ? total_size / unit + 1 : total_size / unit;
	return (total_size + unit - 1) / unit;
}

inline static uint32_t
get_wrapped_around_sequence_offset(uint32_t cur_seq, uint32_t next_seq) {
	return UINT32_MAX - cur_seq + next_seq + 1;
}

#endif /* __UTIL_H__ */
