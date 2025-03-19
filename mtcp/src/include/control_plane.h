#ifndef __CONTROL_PLANE_H__
#define __CONTROL_PLANE_H__

#include <stdint.h>
#include <stddef.h>
#include <rte_common.h>

void control_plane_setup(void);

/* control_plane_get_obj_hv()
 * - Search object by hv
 * - Increase reference count of items
 *   - Success
 *		Return 0 : obj_hv and obj_sz
 *   - Fail
 *		Return -1 
 * */
int control_plane_get_obj_hv(int core_index, char *url, size_t url_len, 
							uint64_t *obj_hv, uint32_t *obj_sz,
							void **block_map, int *numBlock);

/* - control_plane_free_obj_by_hv() 
 * - Reduce refcount
 *  - Success
 *		Return 0
 *	- Fail (If wrong hv is sent)
 *		Return -1
 * */
int control_plane_free_obj_by_hv(int core_index, uint64_t hv);

/* control_plane_enqueue_reply()
 * Enqueue rx packets for check */
void control_plane_enqueue_reply(int core_index, void *pktbuf, uint32_t cur_ts);

/* Flush all packets in tx packet queue */
extern void control_plane_flush_message(int core_index, uint16_t portid, uint16_t qid);

int control_plane_get_nb_cpus(void);

/* Heat dataplane */
void control_plane_heat_dataplane(void);

void control_plane_mtcp_master_thread_ready(void);

/* Signal to Reply queue for processing offloading reply */
extern void control_plane_signal_to_replyq(int core_index);

void control_plane_wait_for_heat_dataplane(void);

void control_plane_teardown(void);

#endif
