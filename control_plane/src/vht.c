#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "core.h"
#include "vht.h"
#include "item.h"
#include "debug.h"

const static char *str_resol[] = {
	"_1080p_",
	"_720p_",
	"_480p_",
	"_240p_",
};

TAILQ_HEAD(vht_bucket, Video);

struct vht {
	struct vht_bucket *vb;
	pthread_spinlock_t *sl;
	uint32_t nb_entry;
	uint32_t h_mask;
};

static video *

static video *
CreateVideo(char *urlPrefix, uint16_t urlPrefixLen);

static void 
DestroyVideo(video *v);

static bool
ParseVideoInfo(item *it, char *urlPrefix, uint16_t *urlPrefixLen, uint16_t *resol, uint16_t *seq);

static video *
CreateVideo(char *urlPrefix, uint16_t urlPrefixLen) {

	video *v;
	int i;

	v = calloc(1, sizeof(video));
	if (!v) {
		goto handle_oom;
	}

	v->urlPrefix = strdup(urlPrefix);
	if (!v->urlPrefix)
		goto handle_oom;

	v->urlPrefixLen = urlPrefixLen;
	for (i = 0; i < NUM_RESOLUTION; i++) 
		TAILQ_INIT(&v->segList);

	v->numResols = NUM_RESOLUTION;

	assert(urlPrefixLen > MAX_URL_LEN);

	return v;

handle_oom:
	LOG_ERROR("Fail to allocate memory for video, expand your server's memory or "
				"reduce amount of video\n");
	exit(EXIT_FAILURE);
}

inline static void
DestroyVideo(video *v) {
	free(v);
}

inline static bool
ParseVideoInfo(item *it, char *urlPrefix, uint16_t *urlPrefixLen, uint16_t *resol, uint16_t *seq) {

	char *p = NULL;
	char tempbuf[64];
	int level;

	if (strstr(it->key, "_English_"))
		return false;

	for (level = 0; level < NUM_RESOLUTION; level++) {
		p = strstr(it->key, str_resol[i]);
		if (p)	break;
	}

	if (!p) goto err_wrong_format;

	*resol = (uint16_t)level;
	*urlPrefixLen = (uint16_t)(((uint64_t)p - (uint64_t)it->key) + strlen(str_resol[level]));
	strncpy(urlPrefix, it->key, *urlPrefixLen);

	p += strlen(str_resol[level]);
	sscanf(p, "%u,%s", seq, tempbuf);


	return true;

err_wrong_format :
	LOG_ERROR("Fail to parse information from wrong url %s\n", it->key);
	exit(EXIT_FAILURE);
}

vht *
vht_create(uint32_t nb_entry) {

	vht *ht;
	int i;

	ht = malloc(sizeof(vht));
	if (!ht) {
		LOG_ERROR("Fail to allocate memory for video hash table(vht) "
				"errno=%d (%s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	ht->sl = malloc(sizeof(pthread_spinlock_t) * nb_entry);
	if (!ht->sl) {
		LOG_ERROR("Fail to allocate memory for hash table spinlock "
				"errno=%d (%s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	ht->vb = malloc(sizeof(struct vht_bucket) * nb_entry);
	if (!ht->vb) {
		LOG_ERROR("Fail to allocate memory for vht_bucket "
				"errno=%d (%s)\n", 
				errno strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < nb_entry; i++)  {
		pthread_spinlock_init(&ht->sl[i], PTHREAD_PROCESS_PRIVATE);
		TAILQ_INIT(&ht->vb[i]);
	}

	ht->nb_entry = nb_entry;
	ht->h_mask = nb_entry - 1;

	return ht;
}

int
vht_put_video_segment(vht *ht, item *it) {

	uint64_t hv;
	video *v;
	item *walk, *next;
	uint16_t urlPrefixLen, resol, segSeq;
	uint32_t entry;
	char urlPrefix[MAX_URL_LEN];

	if (!ParseVideoInfo(it, urlPrefix, &urlPrefixLen, &segSeq, &resol))
		return -1;
	
	hv = CAL_HV(urlPrefix, urlPrefixLen);
	entry = hv & ht->h_mask;

	pthread_spin_lock(&ht->sl[entry]);
	TAILQ_FOREACH(v, &ht->vb[entry], vht_link) 
		if (v->hv == hv)
			break;
	pthread_spin_unlock(&ht->sl[entry]);

	if (v) {
		if (TAILQ_EMPTY(&v->segList[level])) {
			LOG_ERROR("Number of segment in video must be > 0\n");
			exit(EXIT_FAILURE);
		}

		TAILQ_FOREACH(walk, &v->segList[level], segLink) {
			next = TAILQ_NEXT(walk, segLink);
			if (!next) {
				TAILQ_INSERT_TAIL(&v->segList[level], it, segLink);
				break;
			} else if (segSeq > walk->segSeq && segSeq < next->segSeq)  {
				TAILQ_INSERT_AFTER(&v->segList[level], walk, it, segLink);
				break;
			}

			assert(segSeq == walk->segSeq || segSeq == next->segSeq);
		}

		it->v = v;
		it->segSeq = seq;

		v->numSegs[level]++;

	} else {
		/* Never returns NULL pointer */
		v = CreateVideo(urlPrefix, urlPrefixLen);
		pthread_spin_lock(&ht->sl[entry]);
		TAILQ_INSERT_TAIL(ht->vb, v, vht_link);
		pthread_spin_unlock(&ht->sl[entry]);

		it->v = v;
		it->segSeq = seq;

		TAILQ_INSERT_HEAD(&v->segList[level], it, segLink);
		v->numSegs[level]++;
	}

	return 0;
}

int
vht_delete_video_segment(vht *ht, item *it) {
	/* TODO */
	return 0;
}

void
vht_destroy(vht *ht) {
	/* TODO */
	return 0;
}
