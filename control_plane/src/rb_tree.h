#ifndef __RB_TREE_H__
#define __RB_TREE_H__

#include "item.h"

typedef struct optim_cache_context optim_cache_context;
typedef struct rb_tree_s rb_tree;

rb_tree *rb_tree_create(bool (*cmp)(item *x, item *y), uint64_t (*key)(item *x));

void rb_tree_destroy(rb_tree *rt);

item *rb_tree_first(rb_tree *rt);

size_t rb_tree_nb_nodes(rb_tree *rt);

void rb_tree_insert(rb_tree *rt, item *z);

void rb_tree_delete(rb_tree *rt, item *z);

item *rb_tree_search_with_key(rb_tree *rt, uint64_t key);

item *rb_tree_get_minimum(rb_tree *rt);

item *rb_tree_get_maximum(rb_tree *rt);

bool rb_tree_is_empty(rb_tree *rt);

item *rb_tree_pop(rb_tree *rt);

void rb_tree_inorder_traversal(rb_tree *rbt, 
		void (*t_cb)(optim_cache_context *oc_ctx, item *it), 
		optim_cache_context *oc_ctx);
#endif
