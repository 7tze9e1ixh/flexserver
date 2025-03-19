#ifndef IP_OUT_H
#define IP_OUT_H

#include <stdint.h>
#include "tcp_stream.h"

#define FRD_OFFLOAD_DISK_READ 0x01
#define FRD_OFFLOAD_TRANSMISSION 0x02
#define FRD_OFFLOAD_FREE_FILE_BUF 0x03

extern inline int 
GetOutputInterface(uint32_t daddr, uint8_t *is_external);

void
ForwardIPv4Packet(mtcp_manager_t mtcp, int nif_in, char *buf, int len);

uint8_t *
IPOutputStandalone(struct mtcp_manager *mtcp, uint8_t protocol, 
		uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t tcplen);

uint8_t *
IPOutput(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen);

uint8_t *
IPOutputExt(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen, void **m);

uint8_t *
IPTransmissionOffload(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen);

uint8_t *
IPFrdOffload(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen);

uint8_t *
IPDPUNotify(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen, uint8_t foc_state);
#endif /* IP_OUT_H */
