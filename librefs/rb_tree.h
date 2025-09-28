//
// Based on Julienne Walker's <http://eternallyconfuzzled.com/> rb_tree
// implementation.
//
// Modified by Mirek Rusin <http://github.com/mirek/rb_tree>.
//
// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
//

#ifndef _REFS_RB_TREE_H
#define _REFS_RB_TREE_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#ifndef RB_ITER_MAX_HEIGHT
#define RB_ITER_MAX_HEIGHT 64 // Tallest allowable tree to iterate
#endif

struct refs_rb_node;
struct refs_rb_tree;

typedef int  (*refs_rb_tree_node_cmp_f) (struct refs_rb_tree *self, struct refs_rb_node *a, struct refs_rb_node *b);
typedef void (*refs_rb_tree_node_f)     (struct refs_rb_tree *self, struct refs_rb_node *node);

struct refs_rb_node {
    int             red;     // Color red (1), black (0)
    struct refs_rb_node *link[2]; // Link left [0] and right [1]
    void           *value;   // User provided, used indirectly via refs_rb_tree_node_cmp_f.
};

struct refs_rb_tree {
    struct refs_rb_node    *root;
    refs_rb_tree_node_cmp_f cmp;
    size_t             size;
    void              *info; // User provided, not used by rb_tree.
};

struct refs_rb_iter {
    struct refs_rb_tree *tree;
    struct refs_rb_node *node;                // Current node
    struct refs_rb_node *path[RB_ITER_MAX_HEIGHT]; // Traversal path
    size_t          top;                      // Top of stack
    void           *info;                     // User provided, not used by rb_iter.
};

int             refs_rb_tree_node_cmp_ptr_cb (struct refs_rb_tree *self, struct refs_rb_node *a, struct refs_rb_node *b);
void            refs_rb_tree_node_dealloc_cb (struct refs_rb_tree *self, struct refs_rb_node *node);

struct refs_rb_node *refs_rb_node_alloc      (void);
struct refs_rb_node *refs_rb_node_create     (void *value);
struct refs_rb_node *refs_rb_node_init       (struct refs_rb_node *self, void *value);
void            refs_rb_node_dealloc         (struct refs_rb_node *self);

struct refs_rb_tree *refs_rb_tree_alloc      (void);
struct refs_rb_tree *refs_rb_tree_create     (refs_rb_tree_node_cmp_f cmp);
struct refs_rb_tree *refs_rb_tree_init       (struct refs_rb_tree *self, refs_rb_tree_node_cmp_f cmp);
void            refs_rb_tree_dealloc         (struct refs_rb_tree *self, refs_rb_tree_node_f node_cb);
void           *refs_rb_tree_find            (struct refs_rb_tree *self, void *value);
int             refs_rb_tree_insert          (struct refs_rb_tree *self, void *value);
int             refs_rb_tree_remove          (struct refs_rb_tree *self, void *value);
size_t          refs_rb_tree_size            (struct refs_rb_tree *self);

int             refs_rb_tree_insert_node     (struct refs_rb_tree *self, struct refs_rb_node *node);
int             refs_rb_tree_remove_with_cb  (struct refs_rb_tree *self, void *value, refs_rb_tree_node_f node_cb);

int             refs_rb_tree_test            (struct refs_rb_tree *self, struct refs_rb_node *root);

struct refs_rb_iter *refs_rb_iter_alloc      (void);
struct refs_rb_iter *refs_rb_iter_init       (struct refs_rb_iter *self);
struct refs_rb_iter *refs_rb_iter_create     (void);
void            refs_rb_iter_dealloc         (struct refs_rb_iter *self);
void           *refs_rb_iter_first           (struct refs_rb_iter *self, struct refs_rb_tree *tree);
void           *refs_rb_iter_last            (struct refs_rb_iter *self, struct refs_rb_tree *tree);
void           *refs_rb_iter_next            (struct refs_rb_iter *self);
void           *refs_rb_iter_prev            (struct refs_rb_iter *self);

#endif /* !defined(_REFS_RB_TREE_H) */
