#ifndef ETH_OUT_H
#define ETH_OUT_H

#include <stdint.h>

#include "mtcp.h"
#include "tcp_stream.h"
#include "ps.h"

uint8_t *
EthernetOutput(struct mtcp_manager *mtcp, uint16_t h_proto, 
		int nif, unsigned char* dst_haddr, uint16_t iplen);

uint8_t *
EthernetOutputExt(struct mtcp_manager *mtcp, uint16_t h_proto, 
		int nif, uint8_t *dst_haddr, uint16_t iplen, void **m);

uint8_t *
EthTransmissionOffload(struct mtcp_manager *mtcp, uint16_t h_proto,
		int nif, unsigned char* dst_haddr, uint16_t iplen);

uint8_t *
EthernetNotify(struct mtcp_manager *mtcp, uint16_t h_proto,  uint16_t len);
#endif /* ETH_OUT_H */
