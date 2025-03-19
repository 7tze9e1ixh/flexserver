#ifndef __LOG_H__
#define __LOG_H__

typedef struct log_buf log_buf;

void log_buf_global_init(uint16_t nb_cores);
void log_buf_write(char *log, size_t log_len);
void log_buf_global_destroy(void);
#endif
