#ifndef __VHT_H__
#define __VHT_H__

#include <stdint.h>
#include "item.h"

#define NUM_RESOLUTION 4
#define MAX_RESOLUTION 10
#define MAX_URL_LEN 512

TAILQ_HEAD(item_head, item_s);

/* Read only hashtable */
typedef struct vht vht;
typedef struct video video;

struct video {
	char *urlPrefix;
	uint16_t urlPrefixLen;
	struct item_head segList[NUM_RESOLUTION]; 
	uint16_t numSegs[NUM_RESOLUTION];
	uint16_t numResols;
	TAILQ_ENTRY(Video) vht_link;
};

#endif
