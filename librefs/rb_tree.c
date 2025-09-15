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

#include "rb_tree.h"

// rb_node

struct refs_rb_node *
refs_rb_node_alloc (void) {
    return malloc(sizeof(struct refs_rb_node));
}

struct refs_rb_node *
refs_rb_node_init (struct refs_rb_node *self, void *value) {
    if (self) {
        self->red = 1;
        self->link[0] = self->link[1] = NULL;
        self->value = value;
    }
    return self;
}

struct refs_rb_node *
refs_rb_node_create (void *value) {
    return refs_rb_node_init(refs_rb_node_alloc(), value);
}

void
refs_rb_node_dealloc (struct refs_rb_node *self) {
    if (self) {
        free(self);
    }
}

static int
refs_rb_node_is_red (const struct refs_rb_node *self) {
    return self ? self->red : 0;
}

static struct refs_rb_node *
refs_rb_node_rotate (struct refs_rb_node *self, int dir) {
    struct refs_rb_node *result = NULL;
    if (self) {
        result = self->link[!dir];
        self->link[!dir] = result->link[dir];
        result->link[dir] = self;
        self->red = 1;
        result->red = 0;
    }
    return result;
}

static struct refs_rb_node *
refs_rb_node_rotate2 (struct refs_rb_node *self, int dir) {
    struct refs_rb_node *result = NULL;
    if (self) {
        self->link[!dir] = refs_rb_node_rotate(self->link[!dir], !dir);
        result = refs_rb_node_rotate(self, dir);
    }
    return result;
}

// refs_rb_tree - default callbacks

int
refs_rb_tree_node_cmp_ptr_cb (struct refs_rb_tree *self, struct refs_rb_node *a, struct refs_rb_node *b) {
    (void) self;
    return (a->value > b->value) - (a->value < b->value);
}

void
refs_rb_tree_node_dealloc_cb (struct refs_rb_tree *self, struct refs_rb_node *node) {
    if (self) {
        if (node) {
            refs_rb_node_dealloc(node);
        }
    }
}

// refs_rb_tree

struct refs_rb_tree *
refs_rb_tree_alloc (void) {
    return malloc(sizeof(struct refs_rb_tree));
}

struct refs_rb_tree *
refs_rb_tree_init (struct refs_rb_tree *self, refs_rb_tree_node_cmp_f node_cmp_cb) {
    if (self) {
        self->root = NULL;
        self->size = 0;
        self->cmp = node_cmp_cb ? node_cmp_cb : refs_rb_tree_node_cmp_ptr_cb;
    }
    return self;
}

struct refs_rb_tree *
refs_rb_tree_create (refs_rb_tree_node_cmp_f node_cb) {
    return refs_rb_tree_init(refs_rb_tree_alloc(), node_cb);
}

void
refs_rb_tree_dealloc (struct refs_rb_tree *self, refs_rb_tree_node_f node_cb) {
    if (self) {
        if (node_cb) {
            struct refs_rb_node *node = self->root;
            struct refs_rb_node *save = NULL;
            
            // Rotate away the left links so that
            // we can treat this like the destruction
            // of a linked list
            while (node) {
                if (node->link[0] == NULL) {

                    // No left links, just kill the node and move on
                    save = node->link[1];
                    node_cb(self, node);
                    node = NULL;
                } else {
                    
                    // Rotate away the left link and check again
                    save = node->link[0];
                    node->link[0] = save->link[1];
                    save->link[1] = node;
                }
                node = save;
            }
        }
        free(self);
    }
}

int
refs_rb_tree_test (struct refs_rb_tree *self, struct refs_rb_node *root) {
    int lh, rh;
    
    if ( root == NULL )
        return 1;
    else {
        struct refs_rb_node *ln = root->link[0];
        struct refs_rb_node *rn = root->link[1];
        
        /* Consecutive red links */
        if (refs_rb_node_is_red(root)) {
            if (refs_rb_node_is_red(ln) || refs_rb_node_is_red(rn)) {
                printf("Red violation");
                return 0;
            }
        }
        
        lh = refs_rb_tree_test(self, ln);
        rh = refs_rb_tree_test(self, rn);
        
        /* Invalid binary search tree */
        if ( ( ln != NULL && self->cmp(self, ln, root) >= 0 )
            || ( rn != NULL && self->cmp(self, rn, root) <= 0))
        {
            puts ( "Binary tree violation" );
            return 0;
        }
        
        /* Black height mismatch */
        if ( lh != 0 && rh != 0 && lh != rh ) {
            puts ( "Black violation" );
            return 0;
        }
        
        /* Only count black links */
        if ( lh != 0 && rh != 0 )
            return refs_rb_node_is_red ( root ) ? lh : lh + 1;
        else
            return 0;
    }
}

void *
refs_rb_tree_find(struct refs_rb_tree *self, void *value) {
    void *result = NULL;
    if (self) {
        struct refs_rb_node node = { .value = value };
        struct refs_rb_node *it = self->root;
        int cmp = 0;
        while (it) {
            if ((cmp = self->cmp(self, it, &node))) {

                // If the tree supports duplicates, they should be
                // chained to the right subtree for this to work
                it = it->link[cmp < 0];
            } else {
                break;
            }
        }
        result = it ? it->value : NULL;
    }
    return result;
}

// Creates (malloc'ates) 
int
refs_rb_tree_insert (struct refs_rb_tree *self, void *value) {
    return refs_rb_tree_insert_node(self, refs_rb_node_create(value));
}

// Returns 1 on success, 0 otherwise.
int
refs_rb_tree_insert_node (struct refs_rb_tree *self, struct refs_rb_node *node) {
    int result = 0;
    if (self && node) {
        if (self->root == NULL) {
            self->root = node;
            result = 1;
        } else {
            struct refs_rb_node head = { 0 }; // False tree root
            struct refs_rb_node *g, *t;       // Grandparent & parent
            struct refs_rb_node *p, *q;       // Iterator & parent
            int dir = 0, last = 0;

            // Set up our helpers
            t = &head;
            g = p = NULL;
            q = t->link[1] = self->root;

            // Search down the tree for a place to insert
            while (1) {
                if (q == NULL) {

                    // Insert node at the first null link.
                    p->link[dir] = q = node;
                } else if (refs_rb_node_is_red(q->link[0]) && refs_rb_node_is_red(q->link[1])) {
                
                    // Simple red violation: color flip
                    q->red = 1;
                    q->link[0]->red = 0;
                    q->link[1]->red = 0;
                }

                if (refs_rb_node_is_red(q) && refs_rb_node_is_red(p)) {

                    // Hard red violation: rotations necessary
                    int dir2 = t->link[1] == g;
                    if (q == p->link[last]) {
                        t->link[dir2] = refs_rb_node_rotate(g, !last);
                    } else {
                        t->link[dir2] = refs_rb_node_rotate2(g, !last);
                    }
                }
          
                // Stop working if we inserted a node. This
                // check also disallows duplicates in the tree
                if (self->cmp(self, q, node) == 0) {
                    break;
                }

                last = dir;
                dir = self->cmp(self, q, node) < 0;

                // Move the helpers down
                if (g != NULL) {
                    t = g;
                }

                g = p;
                p = q;
                q = q->link[dir];
            }

            // Update the root (it may be different)
            self->root = head.link[1];
        }

        // Make the root black for simplified logic
        self->root->red = 0;
        ++self->size;
    }
    
    return 1;
}

// Returns 1 if the value was removed, 0 otherwise. Optional node callback
// can be provided to dealloc node and/or user data. Use refs_rb_tree_node_dealloc
// default callback to deallocate node created by refs_rb_tree_insert(...).
int
refs_rb_tree_remove_with_cb (struct refs_rb_tree *self, void *value, refs_rb_tree_node_f node_cb) {
    int res = 0;
    if (self->root != NULL) {
        struct refs_rb_node head = {0}; // False tree root
        struct refs_rb_node node = { .value = value }; // Value wrapper node
        struct refs_rb_node *q, *p, *g; // Helpers
        struct refs_rb_node *f = NULL;  // Found item
        int dir = 1;

        // Set up our helpers
        q = &head;
        g = p = NULL;
        q->link[1] = self->root;
    
        // Search and push a red node down
        // to fix red violations as we go
        while (q->link[dir] != NULL) {
            int last = dir;

            // Move the helpers down
            g = p;
            p = q;
            q = q->link[dir];
            dir = self->cmp(self, q, &node) < 0;
      
            // Save the node with matching value and keep
            // going; we'll do removal tasks at the end
            if (self->cmp(self, q, &node) == 0) {
                f = q;
            }

            // Push the red node down with rotations and color flips
            if (!refs_rb_node_is_red(q) && !refs_rb_node_is_red(q->link[dir])) {
                if (refs_rb_node_is_red(q->link[!dir])) {
                    p = p->link[last] = refs_rb_node_rotate(q, dir);
                } else if (!refs_rb_node_is_red(q->link[!dir])) {
                    struct refs_rb_node *s = p->link[!last];
                    if (s) {
                        if (!refs_rb_node_is_red(s->link[!last]) && !refs_rb_node_is_red(s->link[last])) {

                            // Color flip
                            p->red = 0;
                            s->red = 1;
                            q->red = 1;
                        } else {
                            int dir2 = g->link[1] == p;
                            if (refs_rb_node_is_red(s->link[last])) {
                                g->link[dir2] = refs_rb_node_rotate2(p, last);
                            } else if (refs_rb_node_is_red(s->link[!last])) {
                                g->link[dir2] = refs_rb_node_rotate(p, last);
                            }
                            
                            // Ensure correct coloring
                            q->red = g->link[dir2]->red = 1;
                            g->link[dir2]->link[0]->red = 0;
                            g->link[dir2]->link[1]->red = 0;
                        }
                    }
                }
            }
        }

        // Replace and remove the saved node
        if (f) {
            void *tmp = f->value;
            f->value = q->value;
            q->value = tmp;
            
            p->link[p->link[1] == q] = q->link[q->link[0] == NULL];
            
            if (node_cb) {
                node_cb(self, q);
            }
            q = NULL;
            res = 1;
        }

        // Update the root (it may be different)
        self->root = head.link[1];

        // Make the root black for simplified logic
        if (self->root != NULL) {
            self->root->red = 0;
        }

        --self->size;
    }
    return res;
}

int
refs_rb_tree_remove (struct refs_rb_tree *self, void *value) {
    int result = 0;
    if (self) {
        result = refs_rb_tree_remove_with_cb(self, value, refs_rb_tree_node_dealloc_cb);
    }
    return result;
}

size_t
refs_rb_tree_size (struct refs_rb_tree *self) {
    size_t result = 0;
    if (self) {
        result = self->size;
    }
    return result;
}

// rb_iter

struct refs_rb_iter *
refs_rb_iter_alloc (void) {
    return malloc(sizeof(struct refs_rb_iter));
}

struct refs_rb_iter *
refs_rb_iter_init (struct refs_rb_iter *self) {
    if (self) {
        self->tree = NULL;
        self->node = NULL;
        self->top = 0;
    }
    return self;
}

struct refs_rb_iter *
refs_rb_iter_create (void) {
    return refs_rb_iter_init(refs_rb_iter_alloc());
}

void
refs_rb_iter_dealloc (struct refs_rb_iter *self) {
    if (self) {
        free(self);
    }
}

// Internal function, init traversal object, dir determines whether
// to begin traversal at the smallest or largest valued node.
static void *
refs_rb_iter_start (struct refs_rb_iter *self, struct refs_rb_tree *tree, int dir) {
    void *result = NULL;
    if (self) {
        self->tree = tree;
        self->node = tree->root;
        self->top = 0;

        // Save the path for later selfersal
        if (self->node != NULL) {
            while (self->node->link[dir] != NULL) {
                self->path[self->top++] = self->node;
                self->node = self->node->link[dir];
            }
        }

        result = self->node == NULL ? NULL : self->node->value;
    }
    return result;
}

// Traverse a red black tree in the user-specified direction (0 asc, 1 desc)
static void *
refs_rb_iter_move (struct refs_rb_iter *self, int dir) {
    if (self->node->link[dir] != NULL) {

        // Continue down this branch
        self->path[self->top++] = self->node;
        self->node = self->node->link[dir];
        while ( self->node->link[!dir] != NULL ) {
            self->path[self->top++] = self->node;
            self->node = self->node->link[!dir];
        }
    } else {
        
        // Move to the next branch
        struct refs_rb_node *last = NULL;
        do {
            if (self->top == 0) {
                self->node = NULL;
                break;
            }
            last = self->node;
            self->node = self->path[--self->top];
        } while (last == self->node->link[dir]);
    }
    return self->node == NULL ? NULL : self->node->value;
}

void *
refs_rb_iter_first (struct refs_rb_iter *self, struct refs_rb_tree *tree) {
    return refs_rb_iter_start(self, tree, 0);
}

void *
refs_rb_iter_last (struct refs_rb_iter *self, struct refs_rb_tree *tree) {
    return refs_rb_iter_start(self, tree, 1);
}

void *
refs_rb_iter_next (struct refs_rb_iter *self) {
    return refs_rb_iter_move(self, 1);
}

void *
refs_rb_iter_prev (struct refs_rb_iter *self) {
    return refs_rb_iter_move(self, 0);
}
