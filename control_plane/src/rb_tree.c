#include "rb_tree.h"
#include "core.h"
#include <stdio.h>

#define RED_COLOR	0U
#define BLACK_COLOR 1U

struct rb_tree_s {
	size_t nb_nodes;
	item *root;
	item sentinel;
	bool (*cmp)(item *x, item *y);
	uint64_t (*key)(item *x);
};

static void inorder_traversal(rb_tree *rbt, item *x, 
		void (*t_cb)(optim_cache_context *oc_ctx, item *it), optim_cache_context *oc_ctx);
static void RBTransplant(rb_tree *rt, item *x, item *v);
static void LeftRotate(rb_tree *rt, item *x);
static void RightRotate(rb_tree *rt, item *x);
static void InsertFixup(rb_tree *rt, item *z);
static void DeleteFixup(rb_tree *rt, item *x);
static item *TreeMinimum(rb_tree *rt, item *x);
static item *TreeMaximum(rb_tree *rt, item *x);

static void
inorder_traversal(rb_tree *rbt, item *x, 
		void (*t_cb)(optim_cache_context *oc_ctx, item *it), optim_cache_context *oc_ctx) {

	if (x != &rbt->sentinel) {
		inorder_traversal(rbt, x->left, t_cb, oc_ctx);
		t_cb(oc_ctx, x);
		inorder_traversal(rbt, x->right, t_cb, oc_ctx);
	}
}

static void
RBTransplant(rb_tree *rt, item *u, item *v)
{
	if (u->parent == &rt->sentinel)
		rt->root = v;
	else if (u == u->parent->left)
		u->parent->left = v;
	else 
		u->parent->right = v;

	v->parent = u->parent;
}

static void
LeftRotate(rb_tree *rt, item *x)
{
	item *y = x->right;
	x->right = y->left;

	if (y->left != &rt->sentinel)
		y->left->parent = x;

	y->parent = x->parent;

	if (x->parent == &rt->sentinel)
		rt->root = y;
	else if (x == x->parent->left)
		x->parent->left = y;
	else
		x->parent->right = y;

	y->left = x;
	x->parent = y;
}

static void
RightRotate(rb_tree *rt, item *x) 
{
	item *y = x->left;
	x->left = y->right;

	if (y->right != &rt->sentinel)
		y->right->parent = x;

	y->parent = x->parent;

	if (x->parent == &rt->sentinel)
		rt->root = y;
	else if (x == x->parent->left)
		x->parent->left = y;
	else
		x->parent->right = y;

	y->right = x;
	x->parent = y;
}

static void
InsertFixup(rb_tree *rt, item *z) 
{
	item *y = NULL;
	while (z->parent->color == RED_COLOR) {
		if (z->parent == z->parent->parent->left) {
			y = z->parent->parent->right;
			if (y->color == RED_COLOR) {
				z->parent->color = BLACK_COLOR;
				y->color = BLACK_COLOR;
				z->parent->parent->color = RED_COLOR;
				z = z->parent->parent;
			} else {
				if (z == z->parent->right) {
					z = z->parent;
					LeftRotate(rt, z);
				}

				z->parent->color = BLACK_COLOR;
				z->parent->parent->color = RED_COLOR;
				RightRotate(rt, z->parent->parent);
			}

		} else {
			y = z->parent->parent->left;
			if (y->color == RED_COLOR) {
				z->parent->color = BLACK_COLOR;
				y->color = BLACK_COLOR;
				z->parent->parent->color = RED_COLOR;
				z = z->parent->parent;
			} else {
				if (z == z->parent->left) {
					z = z->parent;
					RightRotate(rt, z);
				}
				z->parent->color = BLACK_COLOR;
				z->parent->parent->color = RED_COLOR;
				LeftRotate(rt, z->parent->parent);
			}
		}
	}
	rt->root->color = BLACK_COLOR;
}

static void
DeleteFixup(rb_tree *rt, item *x)
{
	item *w;

	while (x != rt->root && x->color == BLACK_COLOR) {
		if (x == x->parent->left) {
			w = x->parent->right;
			if (w->color == RED_COLOR) {
				w->color = BLACK_COLOR;
				x->parent->color = RED_COLOR;
				LeftRotate(rt, x->parent);
				w = x->parent->right;
			}

			if ((w->left->color == BLACK_COLOR) && (w->right->color == BLACK_COLOR)) {
				w->color = RED_COLOR;
				x = x->parent;
			} else {
				if (w->right->color == BLACK_COLOR) {
					w->left->color = BLACK_COLOR;
					w->color = RED_COLOR;
					RightRotate(rt, w);
					w = x->parent->right;
				}

				w->color = x->parent->color;
				x->parent->color = BLACK_COLOR;
				w->right->color = BLACK_COLOR;
				LeftRotate(rt, x->parent);
				x = rt->root;
			}
		} else {
			w = x->parent->left;
			if (w->color == RED_COLOR) {
				w->color = BLACK_COLOR;
				x->parent->color = RED_COLOR;
				RightRotate(rt, x->parent);
				w = x->parent->left;
			}

			if ((w->right->color == BLACK_COLOR) && (w->left->color == BLACK_COLOR)) {
				w->color = RED_COLOR;
				x = x->parent;
			} else {
				if (w->left->color == BLACK_COLOR) {
					w->right->color = BLACK_COLOR;
					w->color = RED_COLOR;
					LeftRotate(rt, w);
					w = x->parent->left;
				}
				w->color = x->parent->color;
				x->parent->color = BLACK_COLOR;
				//x->left->color = BLACK_COLOR;
				w->left->color = BLACK_COLOR;
				RightRotate(rt, x->parent);
				x = rt->root;
			}
		}
	}
	x->color = BLACK_COLOR;
}

inline static item *
TreeMinimum(rb_tree *rt, item *x) {
	item *y = x;
	while (y->left != &rt->sentinel)
		y = y->left;
	return y;
}

inline static item *
TreeMaximum(rb_tree *rt, item *x) {
	item *y = x;
	while (y->right != &rt->sentinel)
		y = y->right;
	return y;
}

rb_tree *
rb_tree_create(bool (*cmp)(item *x, item *y), uint64_t (*key)(item *x)) 
{
	rb_tree *rt;

	rt = calloc(1, sizeof(rb_tree));
	if (!rt) {
		perror("Fail to allocate memory for Red-Black Tree");
		return NULL;
	}

	rt->sentinel.color = BLACK_COLOR;
	rt->sentinel.left = NULL;
	rt->sentinel.right = NULL;
	rt->sentinel.parent = NULL;

	rt->root = &rt->sentinel;
	rt->cmp = cmp;
	rt->key = key;
	rt->nb_nodes = 0;

	return rt;
}

void
rb_tree_destroy(rb_tree *rt)
{
	free(rt);
}

inline item *
rb_tree_first(rb_tree *rt) {
	return rt->root;
}

size_t 
rb_tree_nb_nodes(rb_tree *rt)
{
	return rt->nb_nodes;
}

void
rb_tree_insert(rb_tree *rt, item *z)
{
	item *x = rt->root;
	item *y = &rt->sentinel;

	while (x != &rt->sentinel) {
		y = x;
		x = rt->cmp(z, y) ? x->left : x->right;
	}
	z->parent = y;

	if (y == &rt->sentinel)
		rt->root = z;
	else if (rt->cmp(z, y))
		y->left = z;
	else 
		y->right = z;

	z->left = &rt->sentinel;
	z->right = &rt->sentinel;
	z->color = RED_COLOR;
	InsertFixup(rt, z);
	rt->nb_nodes++;
}

void
rb_tree_delete(rb_tree *rt, item *z)
{
	uint8_t y_color;
	item *x, *y;
	y = z;
	y_color = y->color;

	if (z->left == &rt->sentinel) {
		x = z->right;
		RBTransplant(rt, z, z->right);
	} else if (z->right == &rt->sentinel) {
		x = z->left;
		RBTransplant(rt, z, z->left);
	} else {
		y = TreeMinimum(rt, z->right);
		y_color = y->color;
		x = y->right;

		if (y != z->right) {
			RBTransplant(rt, y, y->right);
			y->right = z->right;
			y->right->parent = y;
		} else {
			x->parent = y;
		}

		RBTransplant(rt, z, y);
		y->left = z->left;
		y->left->parent = y;
		y->color = z->color;
	}

	if (y_color == BLACK_COLOR)
		DeleteFixup(rt, x);

	rt->nb_nodes--;

	z->left = z->right = z->parent = NULL;
}

inline item *
rb_tree_search_with_key(rb_tree *rt, uint64_t key)
{
	item *x = rt->root;
	item *y __attribute__((unused));

	while (x != &rt->sentinel) {
		y = x;
		if (rt->key(x) == key)
			return x;
		else
			x = rt->key(x) < key ? x->left : x->right;
	}

	if (x == &rt->sentinel)
		return NULL;

	return x;
}

inline item *
rb_tree_get_minimum(rb_tree *rt)
{
	return TreeMinimum(rt, rt->root);
}

inline item *
rb_tree_get_maximum(rb_tree *rt)
{
	return TreeMaximum(rt, rt->root);
}


inline bool
rb_tree_is_empty(rb_tree *rt){
	return rt->root == &rt->sentinel;
}

inline item *
rb_tree_pop(rb_tree *rt) {
	item *it = rt->root;
	if (!it)
		return NULL;
	rb_tree_delete(rt, it);
	return it;
}

inline void
rb_tree_inorder_traversal(rb_tree *rbt, 
		void (*t_cb)(optim_cache_context *oc_ctx, item *it), 
		optim_cache_context *oc_ctx)
{
	inorder_traversal(rbt, rbt->root, t_cb, oc_ctx);
}
