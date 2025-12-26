/*-
 * fsapi.h - ReFS public file system API (definitions).
 *
 * Copyright (c) 2025 Erik Larsson
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the source
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fsapi.h"
#include "fsapi_refs.h"

#include "layout.h"
#include "node.h"
#include "rb_tree.h"
#include "util.h"
#include "volume.h"

#define fsapi_log_enter(fmt, ...) \
	sys_log_trace("Entering %s(" fmt ")...", __FUNCTION__, ##__VA_ARGS__)

#define fsapi_log_leave(err, fmt, ...) \
	sys_log_trace("Leaving %s(" fmt "): %s%s%d%s", __FUNCTION__, \
		##__VA_ARGS__, err ? sys_strerror(err) : "", \
		err ? " (" : "", err, err ? ")" : "")

typedef struct fsapi_volume fsapi_volume;
typedef struct fsapi_node_path_element fsapi_node_path_element;
typedef struct fsapi_node fsapi_node;

static const size_t cached_nodes_max = 65536;

struct fsapi_volume {
	refs_volume *vol;
	fsapi_node *root_node;
	fsapi_refs_xattr_mode xattr_mode;

	char *volume_label_cstr;
	size_t volume_label_cstr_length;

	sys_mutex cache_lock;
	struct refs_rb_tree *cache_tree;
	size_t cached_nodes_count;
	fsapi_node *cached_nodes_list;
	struct refs_rb_tree *oid_to_cached_directory_tree;
};

struct fsapi_node_path_element {
	fsapi_node_path_element *parent;
	size_t depth;
	sys_bool name_is_subpath;
	union {
		/**
		 * When @p name_is_subpath is @ref SYS_FALSE, then this field is
		 * interpreted as a refcount.
		 */
		size_t refcount;
		/**
		 * When @p name_is_subpath is @ref SYS_TRUE, then this field is
		 * interprested as a subpath depth, i.e. the number of path
		 * elements in @p name.
		 */
		size_t subpath_depth;
	} u;
	size_t name_length;
	union {
		const char *ro;
		char *rw;
	} name;
};

struct fsapi_node {
	u64 refcount;
	fsapi_node_path_element *path;
	u64 node_number;
	u64 parent_directory_object_id;
	u64 directory_object_id;
	u64 hard_link_parent_object_id;
	u64 hard_link_id;
	sys_bool is_short_entry;
	sys_bool is_unresolved_hard_link;
	u16 entry_offset;
	u8 *key;
	size_t key_size;
	u8 *record;
	size_t record_size;
	fsapi_node_attributes attributes;

	fsapi_node *prev;
	fsapi_node *next;
};

static int fsapi_node_get_attributes_visit_symlink(
		void *context,
		refs_symlink_type type,
		const char *target,
		size_t target_length);

static int fsapi_node_list_visit_symlink(
		void *_context,
		refs_symlink_type type,
		const char *target,
		size_t target_length);

static int fsapi_node_path_element_compare(
		const fsapi_node_path_element *const a,
		const fsapi_node_path_element *const b);


static void fsapi_node_path_element_release(
		fsapi_node_path_element **const element)
{
	if((*element)->name_is_subpath) {
		sys_log_critical("Attempted to release element %p with "
			"subpath.", *element);
		return;
	}
	else if(!(*element)->u.refcount) {
		sys_log_critical("Attempted to release element %p with no "
			"references.", *element);
		return;
	}

	sys_log_debug("Releasing path element %p. Refcount: %" PRIuz " -> "
		"%" PRIuz,
		*element,
		PRAuz((*element)->u.refcount),
		PRAuz((*element)->u.refcount - 1));
	if(!--(*element)->u.refcount) {
		if((*element)->parent) {
			fsapi_node_path_element_release(&(*element)->parent);
		}

		sys_free((*element)->name_length, &(*element)->name.rw);
		sys_free(sizeof(**element), element);
	}
}

static int fsapi_node_path_element_compare(
		const fsapi_node_path_element *const a,
		const fsapi_node_path_element *const b)
{
	const fsapi_node_path_element *a_cur = a;
	const fsapi_node_path_element *b_cur = b;
	size_t a_true_depth = a->depth;
	size_t b_true_depth = b->depth;
	size_t a_subpath_depth = 0;
	size_t a_subpath_length = 0;
	size_t b_subpath_depth = 0;
	size_t b_subpath_length = 0;
	size_t i = 0;
	int res = 0;

	sys_log_trace("Comparing paths %p (depth: %" PRIuz ", name_length: "
		"%" PRIuz ", name: \"%" PRIbs "\", subpath: %" PRIu8 ", "
		"subpath_depth: %" PRIuz ") and %p (depth: %" PRIuz ", "
		"name_length: %" PRIuz ", name: \"%" PRIbs "\", "
		"subpath: %" PRIu8 ", subpath_depth: %" PRIuz ")...",
		a, PRAuz(a->depth), PRAuz(a->name_length),
		PRAbs(a->name_length, a->name.ro), PRAu8(a->name_is_subpath),
		PRAuz(a->name_is_subpath ? a->u.subpath_depth : 0),
		b, PRAuz(b->depth), PRAuz(b->name_length),
		PRAbs(b->name_length, b->name.ro), PRAu8(b->name_is_subpath),
		PRAuz(b->name_is_subpath ? b->u.subpath_depth : 0));

	if(a_cur == b_cur) {
		sys_log_trace("Taking shortcut because we are comparing the "
			"identical element.");
		res = 0;
		goto out;
	}

	if(a_cur->name_is_subpath) {
		a_subpath_depth = a_cur->u.subpath_depth;
		a_subpath_length = a_cur->name_length;
		a_true_depth += a_subpath_depth - 1;
	}

	if(b_cur->name_is_subpath) {
		b_subpath_depth = b_cur->u.subpath_depth;
		b_subpath_length = b_cur->name_length;
		b_true_depth += b_subpath_depth - 1;
	}

	/* Find the smallest common depth so that we can start comparing at the
	 * same depth. */
	if(a_true_depth < b_true_depth) {
		if(a_true_depth < b->depth) {
			size_t descend_count = b->depth - a_true_depth;

			sys_log_trace("Descending B to the smallest common "
				"depth: %" PRIuz " -> %" PRIuz " (%" PRIuz " "
				"levels)",
				PRAuz(b->depth),
				PRAuz(b->depth - descend_count),
				PRAuz(descend_count));

			while(descend_count--) {
				b_cur = b_cur->parent;
			}

			b_subpath_depth = 0;
		}
		else {
			/* Descend through subpaths of B. */
			size_t descend_count = b_true_depth - a_true_depth;

			sys_log_trace("Descending B subpath to the smallest "
				"common depth: %" PRIuz " -> %" PRIuz " "
				"(%" PRIuz " levels)",
				PRAuz(b_true_depth),
				PRAuz(b_true_depth - descend_count),
				PRAuz(descend_count));

			sys_log_trace("Subpath before descending: "
				"\"%" PRIbs "\" (length: %" PRIuz ")",
				PRAbs(b_subpath_length, b->name.ro),
				PRAuz(b_subpath_length));

			while(descend_count--) {
				refs_util_reverse_trim_string(b_cur->name.ro,
					&b_subpath_length, '/');
				refs_util_reverse_search_string(b_cur->name.ro,
					&b_subpath_length, '/');
				sys_log_trace("Subpath with %" PRIuz " more "
					"steps remaining: \"%" PRIbs "\" "
					"(length: %" PRIuz ")",
					PRAuz(descend_count),
					PRAbs(b_subpath_length, b->name.ro),
					PRAuz(b_subpath_length));
				--b_subpath_depth;
			}
		}
	}
	else if(a_true_depth > b_true_depth) {
		if(b_true_depth < a->depth) {
			size_t descend_count = a->depth - b_true_depth;

			sys_log_trace("Descending A to the smallest common "
				"depth: %" PRIuz " -> %" PRIuz " (%" PRIuz " "
				"levels)",
				PRAuz(a->depth),
				PRAuz(a->depth - descend_count),
				PRAuz(descend_count));

			while(descend_count--) {
				a_cur = a_cur->parent;
			}

			a_subpath_depth = 0;
		}
		else {
			/* Descend through subpaths of A. */
			size_t descend_count = a_true_depth - b_true_depth;

			sys_log_trace("Descending A subpath to the smallest "
				"common depth: %" PRIuz " -> %" PRIuz " "
				"(%" PRIuz " levels)",
				PRAuz(a_true_depth),
				PRAuz(a_true_depth - descend_count),
				PRAuz(descend_count));

			sys_log_trace("Subpath before descending: "
				"\"%" PRIbs "\" (length: %" PRIuz ")",
				PRAbs(a_subpath_length, a->name.ro),
				PRAuz(a_subpath_length));

			while(descend_count--) {
				refs_util_reverse_trim_string(a_cur->name.ro,
					&a_subpath_length, '/');
				refs_util_reverse_search_string(a_cur->name.ro,
					&a_subpath_length, '/');
				refs_util_reverse_trim_string(a_cur->name.ro,
					&a_subpath_length, '/');
				sys_log_trace("Subpath with %" PRIuz " more "
					"steps remaining: \"%" PRIbs "\" "
					"(length: %" PRIuz ")",
					PRAuz(descend_count),
					PRAbs(a_subpath_length, a->name.ro),
					PRAuz(a_subpath_length));
				--a_subpath_depth;
			}
		}
	}

	/* Iterate over the path in reverse order from the common prefix.
	 *
	 * If a difference is found in a path element, record it and overwrite
	 * any existing 'res' value. If there is no difference, then keep the
	 * current 'res' value and keep descending to get a stable sort from the
	 * root up. */
	while(a_cur && b_cur) {
		const char *a_name;
		size_t a_name_length;
		const char *b_name;
		size_t b_name_length;
		int cur_res;

		sys_log_trace("Iteration %" PRIuz ":", PRAuz(i + 1));
		++i;
		sys_log_trace("  A: %p", a_cur);
		sys_log_trace("    parent: %p", a_cur->parent);
		sys_log_trace("    depth: %" PRIuz, PRAuz(a_cur->depth));
		if(a_subpath_depth) {
			sys_log_trace("    subpath_depth: %" PRIuz,
				PRAuz(a_subpath_depth));
			sys_log_trace("    subpath_length: %" PRIuz,
				PRAuz(a_subpath_length));
			sys_log_trace("    subpath: \"%" PRIbs "\"",
				PRAbs(a_subpath_length, a_cur->name.ro));

			/* Skip any trailing '/':es. */
			refs_util_reverse_trim_string(a_cur->name.ro,
				&a_subpath_length, '/');
			if(!a_subpath_length) {
				a_cur = a_cur->parent;
				continue;
			}

			/* Iterate backwards until we find the next '/'. */
			a_name_length = a_subpath_length;
			refs_util_reverse_search_string(a_cur->name.ro,
				&a_subpath_length, '/');

			/* Set the name at the current subpath length. */
			a_name = &a_cur->name.ro[a_subpath_length];
			a_name_length -= a_subpath_length;
			a_subpath_depth--;
			if(!a_subpath_depth) {
				a_cur = a_cur->parent;
			}
			else {
				/* Trim any trailing '/' from the new subpath
				 * after extracting the current component's
				 * name. */
				refs_util_reverse_trim_string(a_cur->name.ro,
					&a_subpath_length, '/');
			}
		}
		else {
			a_name = a_cur->name.ro;
			a_name_length = a_cur->name_length;
			a_cur = a_cur->parent;
		}
		sys_log_trace("    name_length: %" PRIuz, PRAuz(a_name_length));
		sys_log_trace("    name: \"%" PRIbs "\"",
			PRAbs(a_name_length, a_name));

		sys_log_trace("  B: %p", b_cur);
		sys_log_trace("    parent: %p", b_cur->parent);
		sys_log_trace("    depth: %" PRIuz, PRAuz(b_cur->depth));
		if(b_subpath_depth) {
			sys_log_trace("    subpath_depth: %" PRIuz,
				PRAuz(b_subpath_depth));
			sys_log_trace("    subpath_length: %" PRIuz,
				PRAuz(b_subpath_length));
			sys_log_trace("    subpath: \"%" PRIbs "\"",
				PRAbs(b_subpath_length, b_cur->name.ro));

			/* Skip any trailing '/':es. */
			refs_util_reverse_trim_string(b_cur->name.ro,
				&b_subpath_length, '/');

			if(!b_subpath_length) {
				b_cur = b_cur->parent;
				continue;
			}

			/* Iterate backwards until we find the next '/'. */
			b_name_length = b_subpath_length;
			refs_util_reverse_search_string(b_cur->name.ro,
				&b_subpath_length, '/');

			/* Set the name at the current subpath length. */
			b_name = &b_cur->name.ro[b_subpath_length];
			b_name_length -= b_subpath_length;
			b_subpath_depth--;
			if(!b_subpath_depth) {
				b_cur = b_cur->parent;
			}
			else {
				/* Trim any trailing '/' from the new subpath
				 * after extracting the current component's
				 * name. */
				refs_util_reverse_trim_string(b_cur->name.ro,
					&b_subpath_length, '/');
			}
		}
		else {
			b_name = b_cur->name.ro;
			b_name_length = b_cur->name_length;
			b_cur = b_cur->parent;
		}
		sys_log_trace("    name_length: %" PRIuz, PRAuz(b_name_length));
		sys_log_trace("    name: \"%" PRIbs "\"",
			PRAbs(b_name_length, b_name));

		cur_res = strncmp(a_name, b_name,
			sys_min(a_name_length, b_name_length));
		if(cur_res) {
			res = cur_res;
		}
		else if(a_name_length < b_name_length) {
			res = -1;
		}
		else if(a_name_length > b_name_length) {
			res = 1;
		}

		if(a_cur == b_cur && !a_subpath_depth && !b_subpath_depth) {
			/* The paths are identical from here on, no need to
			 * compare further. */
			sys_log_trace("Breaking because paths are identical "
				"below this level.");
			break;
		}
	}

	if((a_cur || b_cur) && a_cur != b_cur) {
		sys_log_critical("Unexpected: %s is not at the root after "
			"descending from the smallest common depth!",
			a_cur ? "A" : "B");
	}

	/* If there is no difference in the common prefix, then sort the one
	 * with the smaller depth before the one with the greater depth. */
	if(res);
	else if(a_true_depth < b_true_depth) {
		res = -1;
	}
	else if(a_true_depth > b_true_depth) {
		res = 1;
	}
out:
	sys_log_trace("Compare result: %d", res);

	return res;
}

static void fsapi_node_init(
		fsapi_node *const node,
		fsapi_node_path_element *const path,
		const u64 node_number,
		const u64 parent_directory_object_id,
		const u64 directory_object_id,
		const u64 hard_link_parent_object_id,
		const u64 hard_link_id,
		const sys_bool is_short_entry,
		const sys_bool is_unresolved_hard_link,
		const u16 entry_offset,
		u8 *const key,
		const size_t key_size,
		u8 *const record,
		const size_t record_size,
		fsapi_node *const prev,
		fsapi_node *const next)
{
	sys_log_trace("%s(node=%p, path=%p, node_number=%" PRIu64 ", "
		"parent_directory_object_id=0x%" PRIX64 ", "
		"directory_object_id=0x%" PRIX64 " "
		"hard_link_parent_object_id=0x%" PRIX64 ", "
		"hard_link_id=0x%" PRIX64 ", is_short_entry=%d, "
		"is_unresolved_hard_link=%d, key=%p, "
		"key_size=%" PRIuz ", record=%p, record_size=%" PRIuz ", "
		"prev=%p, next=%p): Entering...",
		__FUNCTION__, node, path, PRAu64(node_number),
		PRAX64(parent_directory_object_id), PRAX64(directory_object_id),
		PRAX64(hard_link_parent_object_id), PRAX64(hard_link_id),
		is_short_entry, is_unresolved_hard_link, key, PRAuz(key_size),
		record, PRAuz(record_size), prev, next);

	node->refcount = 0;
	node->path = path;
	node->node_number = node_number;
	node->parent_directory_object_id = parent_directory_object_id;
	node->directory_object_id = directory_object_id;
	node->hard_link_parent_object_id = hard_link_parent_object_id;
	node->hard_link_id = hard_link_id;
	node->is_short_entry = is_short_entry;
	node->is_unresolved_hard_link = is_unresolved_hard_link;
	node->entry_offset = entry_offset;
	node->key = key;
	node->key_size = key_size;
	node->record = record;
	node->record_size = record_size;
	node->prev = prev;
	node->next = next;
}

static int fsapi_node_deinit(
		fsapi_node *node)
{
	if(node->attributes.symlink_target) {
		sys_free(node->attributes.symlink_target_length,
			&node->attributes.symlink_target);
	}

	if(node->record) {
		sys_log_debug("Freeing record %p.",
			 node->record);
		sys_free(node->record_size, &node->record);
	}

	if(node->key) {
		sys_log_debug("Freeing key %p.",
			 node->key);
		sys_free(node->key_size, &node->key);
	}

	if(node->path) {
		sys_log_debug("Freeing path %p.", node->path);
		fsapi_node_path_element_release(&node->path);
	}

	return 0;
}

static int fsapi_node_recycle(
		fsapi_node *node)
{
	fsapi_node_deinit(
		/* fsapi_node *node */
		node);
	memset(node, 0, sizeof(*node));

	return 0;
}

static int fsapi_node_destroy(
		fsapi_node **node)
{
	fsapi_node_deinit(
		/* fsapi_node *node */
		*node);
	sys_free(sizeof(**node), node);

	return 0;
}

typedef struct {
	char *volume_label_cstr;
	size_t volume_label_cstr_length;
} fsapi_node_get_attributes_volume_label_context;

static int fsapi_volume_get_attributes_volume_label_entry(
		void *const _context,
		const refschar *const volume_label,
		const u16 volume_label_length)
{
	fsapi_node_get_attributes_volume_label_context *const context =
		(fsapi_node_get_attributes_volume_label_context*) _context;

	int err = 0;
	char *volume_label_cstr = NULL;
	size_t volume_label_cstr_length = 0;

	err = sys_unistr_decode(
		/* const refschar *ins */
		volume_label,
		/* size_t ins_len */
		volume_label_length,
		/* char **outs */
		&volume_label_cstr,
		/* size_t *outs_len */
		&volume_label_cstr_length);
	if(err) {
		goto out;
	}

	context->volume_label_cstr = volume_label_cstr;
	context->volume_label_cstr_length = volume_label_cstr_length;
	err = -1;
out:
	return err;
}

static int fsapi_volume_get_attributes_common(
		fsapi_volume *const vol,
		fsapi_volume_attributes *const out_attrs)
{
	int err = 0;

	if(out_attrs->requested & FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_SIZE) {
		out_attrs->block_size = vol->vol->cluster_size;
		out_attrs->valid |= FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_SIZE;
	}
	if(out_attrs->requested & FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_COUNT) {
		out_attrs->block_count = vol->vol->cluster_count;
		out_attrs->valid |= FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_COUNT;
	}
	if(out_attrs->requested & FSAPI_VOLUME_ATTRIBUTE_TYPE_FREE_BLOCKS) {
		out_attrs->free_blocks = 0;
		out_attrs->valid |= FSAPI_VOLUME_ATTRIBUTE_TYPE_FREE_BLOCKS;
	}

	if(out_attrs->requested & FSAPI_VOLUME_ATTRIBUTE_TYPE_VOLUME_NAME) {
		if(!vol->volume_label_cstr) {
			refs_node_walk_visitor visitor;
			fsapi_node_get_attributes_volume_label_context context;
			u64 object_id = 0;

			memset(&visitor, 0, sizeof(visitor));
			memset(&context, 0, sizeof(context));

			visitor.context = &context;
			visitor.node_volume_label_entry =
				fsapi_volume_get_attributes_volume_label_entry;

			/* Look up node 0x500 where the volume label resides. */
			object_id = 0x500;

			err = refs_node_walk(
				/* sys_device *dev */
				vol->vol->dev,
				/* const REFS_BOOT_SECTOR *bs */
				vol->vol->bs,
				/* REFS_SUPERBLOCK_HEADER **sb */
				NULL,
				/* REFS_LEVEL1_NODE **primary_level1_node */
				NULL,
				/* REFS_LEVEL1_NODE **secondary_level1_node */
				NULL,
				/* refs_block_map **block_map */
				&vol->vol->block_map,
				/* refs_node_cache **node_cache */
				&vol->vol->node_cache,
				/* const u64 *start_node */
				NULL,
				/* const u64 *object_id */
				&object_id,
				/* refs_node_walk_visitor *visitor */
				&visitor);
			if(err == -1) {
				/* Manual break. */
				err = 0;
			}
			else if(err) {
				goto out;
			}

			/* Cache the string in the fsapi_volume struct until
			 * unmount time. */
			vol->volume_label_cstr = context.volume_label_cstr;
			vol->volume_label_cstr_length =
				context.volume_label_cstr_length;
		}

		out_attrs->volume_name = vol->volume_label_cstr;
		out_attrs->volume_name_length = vol->volume_label_cstr_length;
		out_attrs->valid |= FSAPI_VOLUME_ATTRIBUTE_TYPE_VOLUME_NAME;
	}
out:
	return err;
}

static void fsapi_add_cached_node_to_list(
		fsapi_volume *const vol,
		fsapi_node *const cached_node)
{
	cached_node->next =
		vol->cached_nodes_list ? vol->cached_nodes_list : cached_node;
	cached_node->prev =
		vol->cached_nodes_list ? vol->cached_nodes_list->prev :
		cached_node;
	if(vol->cached_nodes_list) {
		vol->cached_nodes_list->prev->next = cached_node;
		vol->cached_nodes_list->prev = cached_node;
	}

	vol->cached_nodes_list = cached_node;
}

static void fsapi_remove_cached_node_from_list(
		fsapi_volume *const vol,
		fsapi_node *const cached_node)
{
	/* Detach from the list. */
	if(cached_node == cached_node->next) {
		vol->cached_nodes_list = NULL;
	}
	else {
		cached_node->next->prev = cached_node->prev;
		cached_node->prev->next = cached_node->next;

		/* If we're removing the head of the list, replace the head of
		 * the list with the next item. */
		if(cached_node == vol->cached_nodes_list) {
			vol->cached_nodes_list = cached_node->next;
		}
	}

	cached_node->next = NULL;
	cached_node->prev = NULL;
}

static int fsapi_node_cache_evict(
		fsapi_volume *vol,
		fsapi_node **out_evicted_node)
{
	int err = 0;
	fsapi_node *lru_node = NULL;

	lru_node = vol->cached_nodes_list->prev;

	/* Remove node from path cache tree. */
	if(!refs_rb_tree_remove(vol->cache_tree, lru_node)) {
		sys_log_warning("Failed to remove node %p from tree!",
			lru_node);
	}

	fsapi_remove_cached_node_from_list(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *cached_node */
		lru_node);

	sys_log_debug("Decrementing cached nodes when evicting node %p "
		"(0x%" PRIX64 ":\"%.*s\") with refcount %" PRIu64 ": "
		"%" PRIu64 " -> %" PRIu64,
		lru_node,
		PRAX64(lru_node->parent_directory_object_id),
		(int) sys_min(INT_MAX, lru_node->path->name_length),
		lru_node->path->name.ro,
		PRAu64(lru_node->refcount),
		PRAu64(vol->cached_nodes_count),
		PRAu64(vol->cached_nodes_count - 1));

	--vol->cached_nodes_count;
	if(out_evicted_node) {
		*out_evicted_node = lru_node;
		lru_node = NULL; /* Caller takes ownership. */
	}

	if(lru_node) {
		fsapi_node_destroy(
			/* fsapi_node *cached_node */
			&lru_node);
	}

	return err;
}

static int fsapi_node_cache_put(
		fsapi_volume *const vol,
		fsapi_node *const node)
{
	int err = 0;

	if(vol->cached_nodes_count == cached_nodes_max) {
		/* Evict tail node from cache. It is the least recently used
		 * node and can safely be evicted. */
		err = fsapi_node_cache_evict(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **out_evicted_node */
			NULL);
		if(err) {
			goto out;
		}
	}
	else if(vol->cached_nodes_count > cached_nodes_max) {
		sys_log_critical("Attempted to add a node to an overfilled "
			"cache! Cached nodes: %" PRIu64 " Max: %" PRIu64,
			PRAu64(vol->cached_nodes_count),
			PRAu64(cached_nodes_max));
		err = EINVAL;
		goto out;
	}

	/* Insert cached node as the head of the MRU list. */
	fsapi_add_cached_node_to_list(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *cached_node */
		node);

	sys_log_debug("Incrementing cached nodes when putting node %p "
		"(0x%" PRIX64 ":\"%.*s\") with refcount %" PRIu64 ": "
		"%" PRIu64 " -> %" PRIu64,
		node,
		PRAX64(node->parent_directory_object_id),
		(int) sys_min(INT_MAX, node->path->name_length),
		node->path->name.ro,
		PRAu64(node->refcount),
		PRAu64(vol->cached_nodes_count),
		PRAu64(vol->cached_nodes_count + 1));

	++vol->cached_nodes_count;
out:
	return err;
}

static void fsapi_node_cache_get(
		fsapi_volume *const vol,
		fsapi_node *const node)
{
	/* Remove cached node from MRU list. */
	fsapi_remove_cached_node_from_list(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *cached_node */
		node);

	sys_log_debug("Decrementing cached nodes when getting node %p "
		"(0x%" PRIX64 ":\"%.*s\") with refcount %" PRIu64 ": "
		"%" PRIu64 " -> %" PRIu64,
		node,
		PRAX64(node->parent_directory_object_id),
		(int) sys_min(INT_MAX, node->path->name_length),
		node->path->name.ro,
		PRAu64(node->refcount),
		PRAu64(vol->cached_nodes_count),
		PRAu64(vol->cached_nodes_count - 1));

	--vol->cached_nodes_count;
}

static int fsapi_node_cache_enter(
		fsapi_volume *const vol,
		char *const name,
		const size_t name_length,
		fsapi_node_path_element *const parent_element,
		const u64 node_number,
		const u64 parent_directory_object_id,
		const u64 directory_object_id,
		const u64 hard_link_parent_object_id,
		const u64 hard_link_id,
		const sys_bool is_short_entry,
		const sys_bool is_unresolved_hard_link,
		const u16 entry_offset,
		u8 *const key,
		const size_t key_size,
		u8 *const record,
		const size_t record_size,
		fsapi_node **const out_new_node)
{
	int err = 0;
	fsapi_node *new_node = NULL;
	fsapi_node_path_element *new_path_element = NULL;

	if(vol->cached_nodes_count >= cached_nodes_max) {
		/* Reuse the existing node at the tail of the list, i.e. the one
		 * that was used least recently. */

		err = fsapi_node_cache_evict(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **out_evicted_node */
			&new_node);
		if(err) {
			goto out;
		}

		sys_log_debug("Reusing node %p for \"%" PRIbs "\" since we "
			"reached the maximum number of cached nodes "
			"(%" PRIuz " >= %" PRIuz ").",
			new_node,
			PRAbs(name_length, name),
			PRAuz(vol->cached_nodes_count + 1),
			PRAuz(cached_nodes_max));

		/* Free resources of existing node and zero the allocation. */
		fsapi_node_recycle(
			/* fsapi_node *node */
			new_node);
	}
	else {
		err = sys_calloc(sizeof(*new_node), &new_node);
		if(err) {
			goto out;
		}

		sys_log_debug("Allocated new node %p for \"%" PRIbs "\" since "
			"we are below the maximum number of cached nodes "
			"(%" PRIuz " < %" PRIuz ").",
			new_node,
			PRAbs(name_length, name),
			PRAuz(vol->cached_nodes_count),
			PRAuz(cached_nodes_max));
	}

	err = sys_calloc(sizeof(*new_path_element), &new_path_element);
	if(err) {
		goto out;
	}

	if(parent_element) {
		parent_element->u.refcount++;
	}

	new_path_element->parent = parent_element;
	new_path_element->depth =
		(parent_element ? parent_element->depth : 0) + 1;
	new_path_element->name_is_subpath = SYS_FALSE;
	new_path_element->u.refcount = 1;
	new_path_element->name.rw = name;
	new_path_element->name_length = name_length;

	fsapi_node_init(
		/* fsapi_node *node */
		new_node,
		/* fsapi_node_path_element *path */
		new_path_element,
		/* u64 node_number */
		node_number,
		/* u64 parent_directory_object_id */
		parent_directory_object_id,
		/* u64 directory_object_id */
		directory_object_id,
		/* u64 hard_link_parent_object_id */
		hard_link_parent_object_id,
		/* u64 hard_link_id */
		hard_link_id,
		/* sys_bool is_short_entry */
		is_short_entry,
		/* sys_bool is_unresolved_hard_link */
		is_unresolved_hard_link,
		/* u16 entry_offset */
		entry_offset,
		/* u8 *key */
		key,
		/* size_t key_size */
		key_size,
		/* u8 *record */
		record,
		/* size_t record_size */
		record_size,
		/* fsapi_node *prev */
		NULL,
		/* fsapi_node *next */
		NULL);

	sys_log_debug("Lookup result:");
	sys_log_debug("    parent_directory_object_id: "
		"%" PRIu64,
		PRAu64(new_node->parent_directory_object_id));
	sys_log_debug("    directory_object_id: %" PRIu64,
		PRAu64(new_node->directory_object_id));
	sys_log_debug("    key: %p", new_node->key);
	sys_log_debug("    key_size: %" PRIuz,
		PRAuz(new_node->key_size));
	sys_log_debug("    record: %p", new_node->record);
	sys_log_debug("    record_size: %" PRIuz,
		PRAuz(new_node->record_size));

	if(!refs_rb_tree_insert(
		/* struct refs_rb_tree *self */
		vol->cache_tree,
		/* void *value */
		new_node))
	{
		sys_log_error("Error inserting looked up entry in cache.");
		err = ENOMEM;
		goto out;
	}

	if(out_new_node) {
		*out_new_node = new_node;
	}
	else {
		err = fsapi_node_cache_put(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			new_node);
		if(err) {
			goto out;
		}
	}

	new_node = NULL;
	/* Ownership of the element passed to the node. */
	new_path_element = NULL;
out:
	if(new_path_element) {
		sys_free(sizeof(*new_path_element), &new_path_element);
	}

	if(new_node) {
		sys_free(sizeof(*new_node), &new_node);
	}

	return err;
}

static int fsapi_lookup_by_posix_path_compare(
		struct refs_rb_tree *const tree,
		struct refs_rb_node *const a,
		struct refs_rb_node *const b)
{
	const fsapi_node *const a_node = (const fsapi_node*) a->value;
	const fsapi_node *const b_node = (const fsapi_node*) b->value;

	int res;

	(void) tree;

	res = fsapi_node_path_element_compare(
		/* const fsapi_node_path_element *a */
		a_node->path,
		/* const fsapi_node_path_element *b */
		b_node->path);

	return res;
}

static int fsapi_lookup_by_posix_path(
		fsapi_volume *vol,
		fsapi_node *root_node,
		const char *path,
		size_t path_length,
		fsapi_node **out_node)
{
	int err = 0;
	sys_bool cache_locked = SYS_FALSE;
	size_t i;
	u64 start_object_id = 0;
	size_t subpath_depth = 0;
	sys_bool name_is_subpath = SYS_FALSE;
	fsapi_node *cached_node = NULL;
	fsapi_node *cached_parent_node = NULL;
	fsapi_node *new_node = NULL;
	fsapi_node_path_element *new_path_element = NULL;

	if(!root_node && path_length == 1 && path[0] == '/') {
		*out_node = vol->root_node;
		goto out;
	}

	if(!root_node) {
		root_node = vol->root_node;
	}

	if(root_node->directory_object_id != 0x600) {
		start_object_id = root_node->directory_object_id;

		sys_log_debug("Starting from non-root:");
		sys_log_debug("    start_object_id: %" PRIu64,
			PRAu64(start_object_id));
	}

	for(i = 0; i < path_length; ++i) {
		if(path[i] == '/') {
			const sys_bool old_is_subpath = name_is_subpath;

			name_is_subpath = SYS_TRUE;
			++subpath_depth;

			/* Swallow repeated '/' separators. */
			while(i + 1 < path_length && path[i + 1] == '/') {
				++i;
			}

			/* Revert if we reach the of the path without finding a
			 * new element. */
			if(i + 1 == path_length) {
				--subpath_depth;
				name_is_subpath = old_is_subpath;
			}
		}
	}

	if(!vol->cache_tree) {
		vol->cache_tree = refs_rb_tree_create(
			/* refs_rb_tree_node_cmp_f cmp */
			fsapi_lookup_by_posix_path_compare);
		if(!vol->cache_tree) {
			err = ENOMEM;
			goto out;
		}
	}
	else {
		fsapi_node_path_element search_path_element;
		fsapi_node search_node;

		memset(&search_path_element, 0, sizeof(search_path_element));
		memset(&search_node, 0, sizeof(search_node));

		search_path_element.parent = root_node->path;
		search_path_element.depth =
			(root_node->path ? root_node->path->depth : 0) + 1;
		search_path_element.u.subpath_depth = subpath_depth;
		search_path_element.name_is_subpath = name_is_subpath;
		search_path_element.name_length = path_length;
		search_path_element.name.ro = path;

		search_node.path = &search_path_element;

		/* Strip any leading '/' characters in the search path. */
		refs_util_trim_string(
			&search_path_element.name.ro,
			&search_path_element.name_length,
			'/');

		/* Skip past any trailing '/' characters in the search path. */
		refs_util_reverse_trim_string(
			search_path_element.name.ro,
			&search_path_element.name_length,
			'/');

		sys_log_debug("Searching for path:");
		sys_log_debug("  depth: %" PRIuz,
			PRAuz(search_path_element.depth));
		sys_log_debug("  name_is_subpath: %" PRIu8,
			PRAu8(search_path_element.name_is_subpath));
		sys_log_debug("  subpath_depth: %" PRIuz,
			PRAuz(search_path_element.u.subpath_depth));
		sys_log_debug("  name_length: %" PRIuz,
			PRAuz(search_path_element.name_length));
		sys_log_debug("  name: \"%" PRIbs "\"",
			PRAbs(search_path_element.name_length,
			search_path_element.name.ro));

		err = sys_mutex_lock(
			/* sys_mutex *mutex */
			&vol->cache_lock);
		if(err) {
			goto out;
		}

		cache_locked = SYS_TRUE;

		cached_node = refs_rb_tree_find(
			/* struct refs_rb_tree *self */
			vol->cache_tree,
			/* void *value */
			&search_node);
		if(cached_node) {
			sys_log_debug("Cache hit for path \"%" PRIbs "\" in "
				"parent node %p: %p%s",
				PRAbs(path_length, path), root_node,
				cached_node,
				cached_node->parent_directory_object_id ? "" :
				" (negative)");
		}
		else if(search_path_element.name_is_subpath &&
			search_path_element.u.subpath_depth > 1 &&
			search_path_element.name_length > 1)
		{
			/* Check if there's a cache hit for its parent. */
			size_t child_name_length =
				search_path_element.name_length;
			const char *child_name = NULL;

			/* Search backwards for the next '/' from the end of the
			 * element. */
			refs_util_reverse_search_string(
				search_path_element.name.ro,
				&search_path_element.name_length, '/');

			child_name = &search_path_element.name.ro[
				search_path_element.name_length];
			child_name_length -=
				search_path_element.name_length;

			/* Trim any trailing '/' characters from the end of the
			 * string. */
			refs_util_reverse_trim_string(
				search_path_element.name.ro,
				&search_path_element.name_length, '/');

			--search_path_element.u.subpath_depth;

			sys_log_debug("Searching for parent path:");
			sys_log_debug("  depth: %" PRIuz,
				PRAuz(search_path_element.depth));
			sys_log_debug("  name_is_subpath: %" PRIu8,
				PRAu8(search_path_element.name_is_subpath));
			sys_log_debug("  subpath_depth: %" PRIuz,
				PRAuz(search_path_element.u.subpath_depth));
			sys_log_debug("  name_length: %" PRIuz,
				PRAuz(search_path_element.name_length));
			sys_log_debug("  name: \"%" PRIbs "\"",
				PRAbs(search_path_element.name_length,
				search_path_element.name.ro));

			if(search_path_element.name_length) {
				sys_log_debug("Cache miss for path "
					"\"%" PRIbs "\" in parent node %p. "
					"Attempting to find parent directory "
					"\"%" PRIbs "\" in cache...",
					PRAbs(path_length, path), root_node,
					PRAbs(search_path_element.name_length,
					search_path_element.name.ro));

				cached_parent_node = refs_rb_tree_find(
					/* struct refs_rb_tree *self */
					vol->cache_tree,
					/* void *value */
					&search_node);
			}

			if(cached_parent_node) {
				const char *const child_path = path;
				const size_t child_path_length = path_length;

				path = child_name;
				path_length = child_name_length;

				start_object_id =
					cached_parent_node->directory_object_id;
				sys_log_debug("Cache miss for path "
					"\"%" PRIbs "\" but found parent "
					"directory in cache. Starting lookup "
					"at object ID 0x%" PRIX64 " with "
					"subpath \"%" PRIbs "\"...",
					PRAbs(child_path_length, child_path),
					PRAu64(start_object_id),
					PRAbs(path_length, path));

				if(cached_parent_node->next) {
					/* Put the looked up cached parent node
					 * at the start of the list to indicate
					 * recent use. */
					fsapi_remove_cached_node_from_list(
						/* fsapi_volume *vol */
						vol,
						/* fsapi_node *cached_node */
						cached_parent_node);
					fsapi_add_cached_node_to_list(
						/* fsapi_volume *vol */
						vol,
						/* fsapi_node *cached_node */
						cached_parent_node);
				}
			}
			else {
				sys_log_debug("Cache miss for path "
					"\"%" PRIbs "\" and its parent.",
					PRAbs(path_length, path));
			}
		}
		else {
			sys_log_debug("Cache miss for path \"%" PRIbs "\".",
				PRAbs(path_length, path));
		}

		if(cached_node && cached_node->is_unresolved_hard_link) {
			u64 parent_directory_object_id = 0;
			u64 directory_object_id = 0;
			sys_bool is_short_entry = 0;
			u64 node_number = 0;
			u16 entry_offset = 0;
			u8 *key = NULL;
			size_t key_size = 0;
			u8 *record = NULL;
			size_t record_size = 0;

			sys_log_debug("Resolving unresolved hard link of "
				"cached node %p with parent object ID "
				"%" PRIu64 ", hard link ID %" PRIu64 "...",
				cached_node,
				PRAu64(cached_node->hard_link_parent_object_id),
				PRAu64(cached_node->hard_link_id));

			err = refs_volume_resolve_hard_link_target(
				/* refs_volume *vol */
				vol->vol,
				/* u64 hard_link_parent_object_id */
				cached_node->hard_link_parent_object_id,
				/* u64 hard_link_id */
				cached_node->hard_link_id,
				/* u64 *out_parent_directory_object_id */
				&parent_directory_object_id,
				/* u64 *out_directory_object_id */
				&directory_object_id,
				/* sys_bool *out_is_short_entry */
				&is_short_entry,
				/* u64 *out_node_number */
				&node_number,
				/* u16 *out_entry_offset */
				&entry_offset,
				/* u8 **out_key */
				&key,
				/* size_t *out_key_size */
				&key_size,
				/* u8 **out_record */
				&record,
				/* size_t *out_record_size */
				&record_size);
			if(err) {
				goto out;
			}

			sys_log_debug("Resolved unresolved hard link of cached "
				"node %p to node number %" PRIu64 ", entry "
				"offset %" PRIu16 ".",
				cached_node, PRAu64(node_number),
				PRAu16(entry_offset));

			cached_node->parent_directory_object_id =
				parent_directory_object_id;
			cached_node->directory_object_id = directory_object_id;
			cached_node->is_short_entry = is_short_entry;
			cached_node->node_number = node_number;
			cached_node->entry_offset = entry_offset;
			if(cached_node->key) {
				sys_free(cached_node->key_size,
					&cached_node->key);
			}
			cached_node->key = key;
			cached_node->key_size = key_size;
			if(cached_node->record) {
				sys_free(cached_node->record_size,
					&cached_node->record);
			}
			cached_node->record = record;
			cached_node->record_size = record_size;

			/* Reset the unresolved hard link fields to match a
			 * normal lookup, so that the next lookup doesn't
			 * re-resolve the hard link. */
			cached_node->is_unresolved_hard_link = SYS_FALSE;
			cached_node->hard_link_id = 0;
			cached_node->hard_link_parent_object_id = 0;
		}

		err = sys_mutex_unlock(
			/* sys_mutex *mutex */
			&vol->cache_lock);
		if(err) {
			goto out;
		}

		cache_locked = SYS_FALSE;
	}

	if(cached_node) {
		/* We are done, nothing more to do. */
	}
	else {
		const size_t final_depth =
			(root_node->path ? root_node->path->depth : 0) +
			(name_is_subpath ? subpath_depth - 1 : 0) + 1;

		fsapi_node *cur_node = NULL;
		size_t cur_node_depth = 0;
		const char *cur_path = NULL;
		size_t cur_path_length = 0;
		char *dup_element = NULL;
		u64 node_number = 0;
		u64 parent_directory_object_id = 0;
		u64 directory_object_id = 0;
		sys_bool is_short_entry = 0;
		u16 entry_offset = 0;
		u8 *key = NULL;
		size_t key_size = 0;
		u8 *record = NULL;
		size_t record_size = 0;

		if(cached_parent_node) {
			size_t cur_element_start;

			sys_log_debug("Found parent node in cache.");
			cur_node_depth = final_depth - 1;
			cur_node = cached_parent_node;
			cur_path = path;
			cur_path_length = path_length;
			/* Trim any trailing '/' characters. */
			refs_util_reverse_trim_string(cur_path,
				&cur_path_length, '/');
			/* Seek backwards to the next '/'. */
			cur_element_start = cur_path_length;
			refs_util_reverse_search_string(cur_path,
				&cur_element_start, '/');
			/* Adjust 'cur_path' to the last path element bounds. */
			cur_path = &cur_path[cur_element_start];
			cur_path_length -= cur_element_start;
		}
		else {
			sys_log_debug("Searching from root.");
			cur_node_depth =
				root_node->path ? root_node->path->depth : 0;
			cur_node = root_node;
			cur_path = path;
			cur_path_length = path_length;
		}

		sys_log_debug("cur_node_depth: %" PRIuz, PRAuz(cur_node_depth));
		sys_log_debug("cur_node: %p", cur_node);
		sys_log_debug("cur_path_length: %" PRIuz,
			PRAuz(cur_path_length));
		sys_log_debug("cur_path: \"%" PRIbs "\"",
			PRAbs(cur_path_length, cur_path));
		sys_log_debug("final_depth: %" PRIuz, PRAuz(final_depth));

		if(cur_node_depth >= final_depth) {
			sys_log_critical("Internal error: Attempted to find "
				"root node which should have been found "
				"earlier.");
			err = ENXIO;
			goto out;
		}

		for(; cur_node_depth < final_depth; ++cur_node_depth) {
			const char *cur_element;
			size_t cur_element_length;
			fsapi_node_path_element search_path_element;
			fsapi_node search_node;

			memset(&search_path_element, 0,
				sizeof(search_path_element));
			memset(&search_node, 0, sizeof(search_node));

			/* Find the current path element. */

			/* Skip past any leading '/' characters. */
			refs_util_trim_string(&cur_path, &cur_path_length,
				'/');

			/* Search for the next '/' from the start of the
			 * element. */
			cur_element = cur_path;
			cur_element_length = cur_path_length;

			refs_util_search_string(cur_element,
				&cur_element_length, '/');
			cur_path = &cur_path[cur_element_length];
			cur_path_length -= cur_element_length;

			if(new_node) {
				/* Put previously looked up node back in the
				 * cache. */
				fsapi_node_cache_put(
					/* fsapi_volume *vol */
					vol,
					/* fsapi_node *node */
					new_node);

				err = sys_mutex_unlock(
					/* sys_mutex *mutex */
					&vol->cache_lock);
				if(err) {
					goto out;
				}

				cache_locked = SYS_FALSE;

				new_node = NULL;
			}

			sys_log_debug("Depth %" PRIuz "/%" PRIuz ":",
				PRAuz(cur_node_depth), PRAuz(final_depth));
			sys_log_debug("  cur_element_length: %" PRIuz,
				PRAuz(cur_element_length));
			sys_log_debug("  cur_element: \"%" PRIbs "\"",
				PRAbs(cur_element_length, cur_element));

			search_path_element.parent = cur_node->path;
			search_path_element.depth =
				(cur_node->path ? cur_node->path->depth : 0) +
				1;
			search_path_element.name_is_subpath = SYS_FALSE;
			search_path_element.name_length = cur_element_length;
			search_path_element.name.ro = cur_element;

			search_node.path = &search_path_element;

			err = sys_mutex_lock(
				/* sys_mutex *mutex */
				&vol->cache_lock);
			if(err) {
				goto out;
			}

			cache_locked = SYS_TRUE;

			cached_node = refs_rb_tree_find(
				/* struct refs_rb_tree *self */
				vol->cache_tree,
				/* void *value */
				&search_node);
			if(cached_node) {
				sys_log_debug("  Found element in cache. "
					"Continuing...");
				cur_node = cached_node;
				continue;
			}

			sys_log_debug("  Cache miss.");

			sys_log_debug("Looking up path \"%" PRIbs "\" starting "
				"at directory %" PRIu64 "...",
				PRAbs(cur_element_length, cur_element),
				PRAu64(cur_node->directory_object_id));

			err = refs_volume_lookup_by_posix_path(
				/* refs_volume *vol */
				vol->vol,
				/* const char *path */
				cur_element,
				/* size_t path_length */
				cur_element_length,
				/* const u64 *start_object_id */
				&cur_node->directory_object_id,
				/* u64 *out_parent_directory_object_id */
				&parent_directory_object_id,
				/* u64 *out_directory_object_id */
				&directory_object_id,
				/* sys_bool *out_is_short_entry */
				&is_short_entry,
				/* u64 *out_node_number */
				&node_number,
				/* u16 *out_entry_offset */
				&entry_offset,
				/* u8 **out_key */
				&key,
				/* size_t *out_key_size */
				&key_size,
				/* u8 **out_record */
				&record,
				/* size_t *out_record_size */
				&record_size);
			if(err) {
				sys_log_perror(err, "lookup error");
				goto out;
			}
			else if(!parent_directory_object_id) {
				/* Not found. */
				if(out_node) {
					*out_node = NULL;
				}

				goto out;
			}

			err = sys_strndup(
				/* const char *str */
				cur_element,
				/* size_t len */
				cur_element_length,
				/* char **dupstr */
				&dup_element);
			if(err) {
				sys_log_pdebug(err, "strndup error");
				goto out;
			}

			err = fsapi_node_cache_enter(
				/* fsapi_volume *vol */
				vol,
				/* char *name */
				dup_element,
				/* size_t name_length */
				cur_element_length,
				/* fsapi_node_path_element *parent_element */
				cur_node->path,
				/* u64 node_number */
				node_number,
				/* u64 parent_directory_object_id */
				parent_directory_object_id,
				/* u64 directory_object_id */
				directory_object_id,
				/* u64 hard_link_parent_object_id */
				0,
				/* u64 hard_link_id */
				0,
				/* sys_bool is_short_entry */
				is_short_entry,
				/* sys_bool is_unresolved_hard_link */
				SYS_FALSE,
				/* u16 entry_offset */
				entry_offset,
				/* u8 *key */
				key,
				/* size_t key_size */
				key_size,
				/* u8 *record */
				record,
				/* size_t record_size */
				record_size,
				/* fsapi_node **out_new_node */
				&new_node);
			if(err) {
				sys_free(cur_element_length + 1, &dup_element);
				goto out;
			}

			cached_node = cur_node = new_node;
		}

		new_node = NULL;
	}

	if(!cache_locked) {
		err = sys_mutex_lock(
			/* sys_mutex *mutex */
			&vol->cache_lock);
		if(err) {
			goto out;
		}

		cache_locked = SYS_TRUE;
	}

	if(out_node) {
		if(cached_node->next) {
			/* The node came from the node cache and needs to be
			 * detached first. */
			fsapi_node_cache_get(
				/* fsapi_volume *vol */
				vol,
				/* fsapi_node *node */
				cached_node);
		}

		cached_node->refcount++;
		sys_log_debug("Returning node %p with refcount %" PRIuz "...",
			cached_node, PRAuz(cached_node->refcount));
		*out_node = cached_node;
	}
	else if(!cached_node->refcount && !cached_node->next) {
		sys_log_debug("Putting node %p in the cache...", cached_node);
		err = fsapi_node_cache_put(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			cached_node);
	}
out:
	if(cache_locked) {
		int unlock_err = 0;

		unlock_err = sys_mutex_unlock(
			/* sys_mutex *mutex */
			&vol->cache_lock);
		if(unlock_err) {
			err = err ? err : unlock_err;
			goto out;
		}
	}

	if(new_path_element) {
		sys_free(sizeof(*new_path_element), &new_path_element);
	}

	if(new_node) {
		fsapi_node_destroy(
			/* fsapi_node **node */
			&new_node);
	}

	return err;
}

static int fsapi_fill_attributes(
		fsapi_node_attributes *attrs,
		sys_bool is_directory,
		u16 child_entry_offset,
		u32 file_flags,
		u64 node_number,
		u64 parent_node_object_id,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size)
{
	static const s64 filetime_offset =
		((s64) (369 * 365 + 89)) * 24 * 3600 * 10000000;

	(void) parent_node_object_id;

	attrs->valid = 0;
	attrs->is_directory = is_directory;

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_MODE) {
		attrs->mode = 0;
		if(file_flags & REFS_FILE_ATTRIBUTE_REPARSE_POINT) {
			attrs->mode |= SYS_S_IFLNK;
		}
		else if(is_directory) {
			attrs->mode |= S_IFDIR;
		}
		else {
			attrs->mode |= S_IFREG;
		}
		attrs->mode |= 0777U;
		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_MODE;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT) {
		attrs->link_count = is_directory ? 2 /* TODO */ : 1;
		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER) {
		/* This could in theory truncate node_number if it's huge, but
		 * it's likely not an issue in practice. 128-bit inode numbers
		 * would be needed to fix that properly, otherwise hashing might
		 * be a good intermediate solution. */
		attrs->inode_number =
			(node_number << 16) | child_entry_offset;
		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME) {
		attrs->creation_time.tv_sec =
			(create_time - filetime_offset) / 10000000;
		attrs->creation_time.tv_nsec =
			(create_time - filetime_offset) % 10000000;
		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME)
	{
		attrs->last_status_change_time.tv_sec =
			(last_mft_change_time - filetime_offset) / 10000000;
		attrs->last_status_change_time.tv_nsec =
			(last_mft_change_time - filetime_offset) % 10000000;
		attrs->valid |=
			FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME) {
		attrs->last_data_change_time.tv_sec =
			(last_write_time - filetime_offset) / 10000000;
		attrs->last_data_change_time.tv_nsec =
			(last_write_time - filetime_offset) % 10000000;
		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME) {
		attrs->last_data_access_time.tv_sec =
			(last_access_time - filetime_offset) / 10000000;
		attrs->last_data_access_time.tv_nsec =
			(last_access_time - filetime_offset) % 10000000;
		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_SIZE) {
		attrs->size = file_size;
		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_SIZE;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE) {
		attrs->allocated_size = allocated_size;
		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS) {
		attrs->bsd_flags = 0;
#ifdef UF_IMMUTABLE
		if(file_flags & REFS_FILE_ATTRIBUTE_READONLY) {
			attrs->bsd_flags |= UF_IMMUTABLE;
		}
#endif /* defined(UF_IMMUTABLE) */
#ifdef UF_HIDDEN
		if(file_flags & REFS_FILE_ATTRIBUTE_HIDDEN) {
			attrs->bsd_flags |= UF_HIDDEN;
		}
#endif /* defined(UF_HIDDEN) */
#ifdef SF_ARCHIVED
		if(!(file_flags & REFS_FILE_ATTRIBUTE_ARCHIVE)) {
			attrs->bsd_flags |= SF_ARCHIVED;
		}
#endif /* defined(SF_ARCHIVED) */

		if(attrs->bsd_flags) {
			attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS;
		}
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_WINDOWS_FLAGS) {
		attrs->windows_flags = file_flags;
		if(attrs->is_directory) {
			attrs->windows_flags &= ~0x10000000UL;
			attrs->windows_flags |= REFS_FILE_ATTRIBUTE_DIRECTORY;
		}
		else {
			attrs->windows_flags |= REFS_FILE_ATTRIBUTE_NORMAL;
		}

		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_WINDOWS_FLAGS;
	}

	return 0;
}

typedef struct {
	refs_volume *vol;
	fsapi_node_attributes *attrs;
} fsapi_node_get_attributes_context;

static int fsapi_node_get_attributes_visit_short_entry(
		void *const _context,
		const refschar *const file_name,
		const u16 file_name_length,
		const u16 child_entry_offset,
		const u32 file_flags,
		const u64 node_number,
		const u64 parent_node_object_id,
		const u64 object_id,
		const u64 hard_link_id,
		const u64 create_time,
		const u64 last_access_time,
		const u64 last_write_time,
		const u64 last_mft_change_time,
		const u64 file_size,
		const u64 allocated_size,
		const u8 *const key,
		const size_t key_size,
		const u8 *const record,
		const size_t record_size)
{
	fsapi_node_get_attributes_context *const context =
		(fsapi_node_get_attributes_context*) _context;

	int err = 0;

	(void) file_name;
	(void) file_name_length;
	(void) object_id;
	(void) hard_link_id;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	err = fsapi_fill_attributes(
		/* fsapi_node_attributes *attrs */
		context->attrs,
		/* sys_bool is_directory */
		(file_flags & 0x10000000UL) ? SYS_TRUE : SYS_FALSE,
		/* u16 child_entry_offset */
		child_entry_offset,
		/* u32 file_flags */
		file_flags & ~((u32) 0x10000000UL),
		/* u64 node_number */
		node_number,
		/* u64 parent_node_object_id */
		parent_node_object_id,
		/* u64 create_time */
		create_time,
		/* u64 last_access_time */
		last_access_time,
		/* u64 last_write_time */
		last_write_time,
		/* u64 last_mft_change_time */
		last_mft_change_time,
		/* u64 file_size */
		file_size,
		/* u64 allocated_size */
		allocated_size);
	if(err) {
		goto out;
	}

	if(file_flags & REFS_FILE_ATTRIBUTE_REPARSE_POINT) {
		/* Parse the reparse point node to get the symlink target. */
		refs_node_walk_visitor visitor;

		memset(&visitor, 0, sizeof(visitor));

		visitor.context = context;
		visitor.node_symlink = fsapi_node_get_attributes_visit_symlink;

		err = refs_node_walk(
			/* sys_device *dev */
			context->vol->dev,
			/* const REFS_BOOT_SECTOR *bs */
			context->vol->bs,
			/* REFS_SUPERBLOCK_HEADER **sb */
			&context->vol->sb,
			/* REFS_LEVEL1_NODE **primary_level1_node */
			&context->vol->primary_level1_node,
			/* REFS_LEVEL1_NODE **secondary_level1_node */
			&context->vol->secondary_level1_node,
			/* refs_block_map **block_map */
			&context->vol->block_map,
			/* refs_node_cache **node_cache */
			&context->vol->node_cache,
			/* const u64 *start_node */
			NULL,
			/* const u64 *object_id */
			&object_id,
			/* refs_node_walk_visitor *visitor */
			&visitor);
	}
out:
	return err;
}

static int fsapi_node_get_attributes_visit_long_entry(
		void *const context,
		const le16 *const file_name,
		const u16 file_name_length,
		const u16 child_entry_offset,
		const u32 file_flags,
		const u64 node_number,
		const u64 parent_node_object_id,
		const u64 create_time,
		const u64 last_access_time,
		const u64 last_write_time,
		const u64 last_mft_change_time,
		const u64 file_size,
		const u64 allocated_size,
		const u8 *const key,
		const size_t key_size,
		const u8 *const record,
		const size_t record_size)
{
	(void) file_name;
	(void) file_name_length;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	return fsapi_fill_attributes(
		/* fsapi_node_attributes *attrs */
		((fsapi_node_get_attributes_context*) context)->attrs,
		/* sys_bool is_directory */
		SYS_FALSE,
		/* u16 child_entry_offset */
		child_entry_offset,
		/* u32 file_flags */
		file_flags,
		/* u64 node_number */
		node_number,
		/* u64 parent_node_object_id */
		parent_node_object_id,
		/* u64 create_time */
		create_time,
		/* u64 last_access_time */
		last_access_time,
		/* u64 last_write_time */
		last_write_time,
		/* u64 last_mft_change_time */
		last_mft_change_time,
		/* u64 file_size */
		file_size,
		/* u64 allocated_size */
		allocated_size);
}

static int fsapi_node_get_attributes_visit_hardlink_entry(
		void *const context,
		const u64 hard_link_id,
		const u64 parent_id,
		const u16 child_entry_offset,
		const u32 file_flags,
		const u64 node_number,
		const u64 create_time,
		const u64 last_access_time,
		const u64 last_write_time,
		const u64 last_mft_change_time,
		const u64 file_size,
		const u64 allocated_size,
		const u8 *const key,
		const size_t key_size,
		const u8 *const record,
		const size_t record_size)
{
	(void) hard_link_id;
	(void) parent_id;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	return fsapi_fill_attributes(
		/* fsapi_node_attributes *attrs */
		((fsapi_node_get_attributes_context*) context)->attrs,
		/* sys_bool is_directory */
		SYS_FALSE,
		/* u16 child_entry_offset */
		child_entry_offset,
		/* u32 file_flags */
		file_flags,
		/* u64 node_number */
		node_number,
		/* u64 parent_node_object_id */
		parent_id,
		/* u64 create_time */
		create_time,
		/* u64 last_access_time */
		last_access_time,
		/* u64 last_write_time */
		last_write_time,
		/* u64 last_mft_change_time */
		last_mft_change_time,
		/* u64 file_size */
		file_size,
		/* u64 allocated_size */
		allocated_size);
}

static int fsapi_node_get_attributes_visit_symlink(
		void *const context,
		const refs_symlink_type type,
		const char *const target,
		const size_t target_length)
{
	fsapi_node_attributes *const attrs =
		((fsapi_node_get_attributes_context*) context)->attrs;

	int err = 0;

	(void) type;

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_SIZE) {
		attrs->size = target_length;
		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_SIZE;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_MODE) {
		attrs->mode = SYS_S_IFLNK | (attrs->mode & ~S_IFMT);
	}

	if((attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_SYMLINK_TARGET) &&
		!(attrs->valid & FSAPI_NODE_ATTRIBUTE_TYPE_SYMLINK_TARGET))
	{
		size_t symlink_target_size;

		if(!attrs->symlink_target) {
			symlink_target_size = target_length + 1;
			err = sys_malloc(symlink_target_size,
				&attrs->symlink_target);
			if(err) {
				goto out;
			}
		}
		else {
			symlink_target_size = attrs->symlink_target_length;
		}

		memcpy(attrs->symlink_target, target,
			sys_min(symlink_target_size, target_length));
		if(symlink_target_size > target_length) {
			attrs->symlink_target[target_length] = '\0';
		}
		attrs->symlink_target_length = target_length;

		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_SYMLINK_TARGET;
	}
out:
	return err;
}

static int fsapi_node_get_attributes_common(
		fsapi_volume *vol,
		fsapi_node *node,
		fsapi_node_attributes *attributes)
{
	static const s64 filetime_offset =
		((s64) (369 * 365 + 89)) * 24 * 3600 * 10000000;

	int err = 0;
	refs_node_crawl_context crawl_context;
	fsapi_node_get_attributes_context context;
	refs_node_walk_visitor visitor;
	fsapi_node_attribute_types provided_mask;

	memset(&visitor, 0, sizeof(visitor));
	memset(&context, 0, sizeof(context));

	if(!node->attributes.valid) {
		node->attributes.requested = FSAPI_NODE_ATTRIBUTE_TYPE_ALL;

		crawl_context = refs_volume_init_node_crawl_context(
			/* refs_volume *vol */
			vol->vol);
		context.vol = vol->vol;
		context.attrs = &node->attributes;
		visitor.context = &context;

		if(node->directory_object_id == 0x600) {
			/* Root directory. */
			err = fsapi_fill_attributes(
				/* fsapi_node_attributes *attrs */
				&node->attributes,
				/* sys_bool is_directory */
				SYS_TRUE,
				/* u16 child_entry_offset */
				node->entry_offset,
				/* u32 file_flags */
				REFS_FILE_ATTRIBUTE_SYSTEM |
				REFS_FILE_ATTRIBUTE_DIRECTORY |
				REFS_FILE_ATTRIBUTE_ARCHIVE,
				/* u64 node_number */
				node->node_number,
				/* u64 parent_node_object_id */
				node->parent_directory_object_id,
				/* u64 create_time */
				filetime_offset,
				/* u64 last_access_time */
				filetime_offset,
				/* u64 last_write_time */
				filetime_offset,
				/* u64 last_mft_change_time */
				filetime_offset,
				/* u64 file_size */
				0,
				/* u64 allocated_size */
				0);
		}
		else if(node->is_short_entry) {
			visitor.node_short_entry =
				fsapi_node_get_attributes_visit_short_entry;
			err = parse_level3_short_value(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* refs_node_walk_visitor *visitor */
				&visitor,
				/* const char *prefix */
				"",
				/* size_t indent */
				1,
				/* u64 parent_node_object_id */
				node->parent_directory_object_id,
				/* u64 node_number */
				node->node_number,
				/* u16 entry_offset */
				node->entry_offset,
				/* const u8 *key */
				node->key,
				/* u16 key_size */
				node->key_size,
				/* const u8 *value */
				node->record,
				/* u16 value_offset */
				0,
				/* u16 value_size */
				node->record_size,
				/* void *context */
				NULL);
		}
		else {
			visitor.node_long_entry =
				fsapi_node_get_attributes_visit_long_entry;
			visitor.node_hardlink_entry =
				fsapi_node_get_attributes_visit_hardlink_entry;
			visitor.node_symlink =
				fsapi_node_get_attributes_visit_symlink;

			err = parse_level3_long_value(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* refs_node_walk_visitor *visitor */
				&visitor,
				/* const char *prefix */
				"",
				/* size_t indent */
				1,
				/* u64 parent_node_object_id */
				node->parent_directory_object_id,
				/* u64 node_number */
				node->node_number,
				/* u16 entry_offset */
				node->entry_offset,
				/* const u8 *key */
				node->key,
				/* u16 key_size */
				node->key_size,
				/* const u8 *value */
				node->record,
				/* u16 value_offset */
				0,
				/* u16 value_size */
				node->record_size,
				/* void *context */
				NULL);
		}
	}

	provided_mask = attributes->requested & node->attributes.valid;
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_SIZE) {
		attributes->size = node->attributes.size;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE) {
		attributes->allocated_size = node->attributes.allocated_size;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT) {
		attributes->link_count = node->attributes.link_count;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER) {
		attributes->inode_number = node->attributes.inode_number;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_MODE) {
		attributes->mode = node->attributes.mode;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_UID) {
		attributes->uid = node->attributes.uid;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_GID) {
		attributes->gid = node->attributes.gid;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME) {
		attributes->creation_time = node->attributes.creation_time;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME) {
		attributes->last_status_change_time =
			node->attributes.last_status_change_time;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME) {
		attributes->last_data_change_time =
			node->attributes.last_data_change_time;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME) {
		attributes->last_data_access_time =
			node->attributes.last_data_access_time;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS) {
		attributes->bsd_flags = node->attributes.bsd_flags;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_WINDOWS_FLAGS) {
		attributes->windows_flags = node->attributes.windows_flags;
	}
	if(provided_mask & FSAPI_NODE_ATTRIBUTE_TYPE_SYMLINK_TARGET) {
		err = sys_strndup(node->attributes.symlink_target,
			node->attributes.symlink_target_length,
			&attributes->symlink_target);
		if(err) {
			goto out;
		}

		attributes->symlink_target_length =
			node->attributes.symlink_target_length;
	}

	attributes->valid = provided_mask;
out:
	sys_log_pdebug(err, "%s(node=%p, attributes=%p)",
		__FUNCTION__, node, attributes);

	return err;
}

int fsapi_iohandler_buffer_handle_io(
		void *_context,
		sys_device *dev,
		u64 offset,
		size_t size)
{
	fsapi_iohandler_buffer_context *const context =
		(fsapi_iohandler_buffer_context*) _context;
	const size_t bytes_to_transfer =
		sys_min(context->remaining_size, size);

	int err = 0;

	sys_log_debug("Handle I/O requested for offset %" PRIu64 " and size "
		"%" PRIuz "...", PRAu64(offset), PRAuz(size));
	if(context->is_read) {
		if(offset % 4096 || bytes_to_transfer % 4096) {
			const size_t buf_size =
				((offset + bytes_to_transfer + 4095) / 4096 -
				offset / 4096) * 4096;
			char *buf = NULL;

			sys_log_debug("Doing buffered read for alignment.");

			err = sys_malloc(buf_size, &buf);
			if(err) {
				goto out;
			}

			err = sys_device_pread(
				/* sys_device *dev */
				dev,
				/* u64 offset */
				offset,
				/* size_t nbytes */
				buf_size,
				/* void *buf */
				buf);
			if(!err) {
				memcpy(context->buf.rw, &buf[offset % 4096],
					bytes_to_transfer);
			}

			sys_free(buf_size, &buf);
		}
		else {
			err = sys_device_pread(
				/* sys_device *dev */
				dev,
				/* u64 offset */
				offset,
				/* size_t nbytes */
				bytes_to_transfer,
				/* void *buf */
				context->buf.rw);
		}
		if(err) {
			sys_log_perror(err, "sys_device_pread threw error");
			goto out;
		}

		context->buf.rw = &context->buf.rw[bytes_to_transfer];
	}
	else {
#if 1
		sys_log_critical("Writing is not supported yet.");
		err = ENOTSUP;
#else
		err = sys_device_pwrite(
			/* sys_device *dev */
			dev,
			/* u64 offset */
			offset,
			/* size_t nbytes */
			bytes_to_transfer,
			/* conte void *buf */
			context->buf.ro);
		if(err) {
			goto out;
		}

		context->buf.ro = &context->buf.ro[bytes_to_transfer];
#endif
	}

	context->remaining_size -= bytes_to_transfer;
out:
	return err;
}

int fsapi_iohandler_buffer_copy_data(
		void *_context,
		const void *buffer,
		size_t size)
{
	fsapi_iohandler_buffer_context *const context =
		(fsapi_iohandler_buffer_context*) _context;
	const size_t bytes_to_copy = sys_min(size, context->remaining_size);

	memcpy(context->buf.rw, buffer, bytes_to_copy);
	context->buf.rw = &context->buf.rw[bytes_to_copy];
	context->remaining_size -= bytes_to_copy;

	return 0;
}

int fsapi_iohandler_buffer_get_data(
		void *_context,
		void *buffer,
		size_t size)
{
	fsapi_iohandler_buffer_context *const context =
		(fsapi_iohandler_buffer_context*) _context;
	const size_t bytes_to_copy = sys_min(size, context->remaining_size);

	memcpy(buffer, context->buf.ro, bytes_to_copy);
	context->buf.ro = &context->buf.ro[bytes_to_copy];
	context->remaining_size -= bytes_to_copy;

	return 0;
}

int fsapi_volume_mount(
		sys_device *dev,
		sys_bool read_only,
		const void *custom_mount_options,
		fsapi_volume **out_vol,
		fsapi_node **out_root_node,
		fsapi_volume_attributes *out_attrs)
{
	const fsapi_refs_custom_mount_options *const refs_mount_options =
		(const fsapi_refs_custom_mount_options*) custom_mount_options;

	int err = 0;
	fsapi_volume *vol = NULL;
	fsapi_node *root_node = NULL;
	sys_bool cache_lock_initialized = SYS_FALSE;
	refs_volume *rvol = NULL;
	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;
	sys_bool is_short_entry = SYS_FALSE;
	u64 node_number = 0;
	u16 entry_offset = 0;
	u8 *key = NULL;
	size_t key_size = 0;
	u8 *record = NULL;
	size_t record_size = 0;

	fsapi_log_enter("dev=%p, read_only=%u, custom_mount_options=%p, "
		"out_vol=%p (->%p), out_root_node=%p (->%p), out_attrs=%p",
		dev, read_only, custom_mount_options,
		out_vol, out_vol ? *out_vol : NULL,
		out_root_node, out_root_node ? *out_root_node : NULL,
		out_attrs);

	if(!read_only) {
		sys_log_error("Read/write support not implemented yet.");
		err = EINVAL;
		goto out;
	}

	err = sys_calloc(sizeof(*vol), &vol);
	if(err) {
		goto out;
	}

	err = sys_calloc(sizeof(*root_node), &root_node);
	if(err) {
		goto out;
	}

	err = sys_mutex_init(
		/* sys_mutex *mutex */
		&vol->cache_lock);
	if(err) {
		goto out;
	}

	cache_lock_initialized = SYS_TRUE;

	err = refs_volume_create(
		/* sys_device *dev */
		dev,
		/* refs_volume **out_vol */
		&rvol);
	if(err) {
		sys_log_perror(err, "Error while mounting volume");
		goto out;
	}

	err = refs_volume_lookup_by_posix_path(
		/* refs_volume *vol */
		rvol,
		/* const char *path */
		"/",
		/* size_t path_length */
		1,
		/* const u64 *start_object_id */
		NULL,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* sys_bool *out_is_short_entry */
		&is_short_entry,
		/* u64 *out_node_number */
		&node_number,
		/* u16 *out_entry_offset */
		&entry_offset,
		/* u8 **out_key */
		&key,
		/* size_t *out_key_size */
		&key_size,
		/* u8 **out_record */
		&record,
		/* size_t *out_record_size */
		&record_size);
	if(err) {
		goto out;
	}

	sys_log_debug("Looked up root directory by posix path. Node number: "
		"0x%" PRIX64,
		PRAX64(node_number));

	fsapi_node_init(
		/* fsapi_node *node */
		root_node,
		/* fsapi_node_path_element *path */
		NULL,
		/* u64 parent_directory_object_id */
		parent_directory_object_id,
		/* u64 node_number */
		node_number,
		/* u64 directory_object_id */
		directory_object_id,
		/* u64 hard_link_parent_object_id */
		0,
		/* u64 hard_link_id */
		0,
		/* sys_bool is_short_entry */
		is_short_entry,
		/* sys_bool is_unresolved_hard_link */
		SYS_FALSE,
		/* u16 entry_offset */
		entry_offset,
		/* u8 *key */
		key,
		/* size_t key_size */
		key_size,
		/* u8 *record */
		record,
		/* size_t record_size */
		record_size,
		/* fsapi_node *prev */
		NULL,
		/* fsapi_node *next */
		NULL);

	/* Note: Not adding the root node to the lookup trees, instead handling
	 * it separately from the rest of the nodes. */

	vol->vol = rvol;
	vol->root_node = root_node;
	if(refs_mount_options) {
		vol->xattr_mode = refs_mount_options->xattr_mode;
	}
	else {
		vol->xattr_mode = FSAPI_REFS_XATTR_MODE_STREAMS;
	}

	if(out_attrs) {
		err = fsapi_volume_get_attributes_common(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_volume_attributes *out_attrs */
			out_attrs);
		if(err) {
			sys_log_perror(err, "Error while getting attributes "
				"for mounted volume");
			goto out;
		}
	}

	*out_vol = vol;
	if(out_root_node) {
		*out_root_node = vol->root_node;
	}
out:
	if(err) {
		if(rvol) {
			refs_volume_destroy(
				/* refs_volume **out_vol */
				&rvol);
		}

		if(cache_lock_initialized) {
			sys_mutex_deinit(
				/* sys_mutex *mutex */
				&vol->cache_lock);
		}

		if(root_node) {
			sys_free(sizeof(*root_node), &root_node);
		}

		if(vol) {
			sys_free(sizeof(*vol), &vol);
		}
	}

	fsapi_log_leave(err, "dev=%p, read_only=%u, custom_mount_options=%p, "
		"out_vol=%p (->%p), out_root_node=%p (->%p), out_attrs=%p",
		dev, read_only, custom_mount_options,
		out_vol, out_vol ? *out_vol : NULL,
		out_root_node, out_root_node ? *out_root_node : NULL,
		out_attrs);

	return err;
}

void fsapi_volume_get_root_node(
		fsapi_volume *vol,
		fsapi_node **out_root_node)
{
	fsapi_log_enter("vol=%p, out_root_node=%p (->%p)",
		vol, out_root_node, out_root_node ? *out_root_node : NULL);

	*out_root_node = vol->root_node;

	fsapi_log_leave(0, "vol=%p, out_root_node=%p (->%p)",
		vol, out_root_node, out_root_node ? *out_root_node : NULL);
}

int fsapi_volume_get_attributes(
		fsapi_volume *vol,
		fsapi_volume_attributes *out_attrs)
{
	int err = 0;

	fsapi_log_enter("vol=%p, out_attrs=%p",
		vol, out_attrs);

	err = fsapi_volume_get_attributes_common(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_volume_attributes *out_attrs */
		out_attrs);

	fsapi_log_leave(err, "vol=%p, out_attrs=%p",
		vol, out_attrs);

	return err;
}

int fsapi_volume_sync(
		fsapi_volume *vol)
{
	int err;

	fsapi_log_enter("vol=%p", vol);

	(void) vol;

	/* Syncing is always successful because there's nothing to sync at the
	 * moment. */
	err = 0;

	fsapi_log_leave(err, "vol=%p", vol);

	return err;
}

static void fsapi_volume_unmount_cache_tree_entry_destroy(
		struct refs_rb_tree *self,
		struct refs_rb_node *_node)
{
	fsapi_node *node = (fsapi_node*) _node->value;

	(void) self;

	sys_log_warning("Destroying node %p (0x%" PRIX64 ":\"%.*s\") with "
		"%" PRIu64 " remaining references...",
		node,
		PRAX64(node->parent_directory_object_id),
		(int) sys_min(INT_MAX, node->path->name_length),
		node->path->name.ro,
		PRAu64(node->refcount));

	fsapi_node_destroy(
		/* fsapi_node **node */
		&node);
	sys_free(sizeof(*_node), &_node);
}

int fsapi_volume_unmount(
		fsapi_volume **vol)
{
	fsapi_log_enter("vol=%p (->%p)", vol, vol ? *vol : NULL);

	sys_log_debug("Iterating over cached nodes list %p...",
		(*vol)->cached_nodes_list);

	if((*vol)->cached_nodes_list) {
		/* Iterate over cached nodes and free all resources. */
		fsapi_node *cur_node = (*vol)->cached_nodes_list;
		do {
			fsapi_node *next_node = cur_node->next;

			sys_log_debug("Cleaning up cached node %p / "
				"0x%" PRIX64 ":\"%.*s\" with refcount "
				"%" PRIu64 " (cached nodes: %" PRIuz " -> "
				"%" PRIuz ")...",
				cur_node,
				PRAX64(cur_node->parent_directory_object_id),
				(int) sys_min(INT_MAX,
				cur_node->path->name_length),
				cur_node->path->name.ro,
				PRAu64(cur_node->refcount),
				PRAuz((*vol)->cached_nodes_count),
				PRAuz((*vol)->cached_nodes_count - 1));

			--(*vol)->cached_nodes_count;
			refs_rb_tree_remove((*vol)->cache_tree, cur_node);

			fsapi_node_destroy(
				/* fsapi_node *cached_node */
				&cur_node);

			cur_node = next_node;
		} while(cur_node != (*vol)->cached_nodes_list);

		if((*vol)->cached_nodes_count) {
			sys_log_critical("Cached nodes count is non-0 after "
				"iterating over cached nodes list: %" PRIuz,
				PRAuz((*vol)->cached_nodes_count));
		}

		(*vol)->cached_nodes_count = 0;
		(*vol)->cached_nodes_list = NULL;
	}

	if((*vol)->cache_tree) {
		refs_rb_tree_dealloc((*vol)->cache_tree,
			fsapi_volume_unmount_cache_tree_entry_destroy);
	}

	if((*vol)->volume_label_cstr) {
		sys_free((*vol)->volume_label_cstr_length,
			&(*vol)->volume_label_cstr);
	}

	refs_volume_destroy(
		/* refs_volume **out_vol */
		&(*vol)->vol);

	sys_mutex_deinit(
		/* sys_mutex *mutex */
		&(*vol)->cache_lock);

	sys_free(sizeof(*(*vol)->root_node), &(*vol)->root_node);
	sys_free(sizeof(**vol), vol);

	fsapi_log_leave(0, "vol=%p (->%p)", vol, vol ? *vol : NULL);

	return 0;
}

int fsapi_node_lookup(
		fsapi_volume *vol,
		fsapi_node *parent_node,
		const char *path,
		size_t path_length,
		fsapi_node **out_child_node,
		fsapi_node_attributes *out_attributes)
{
	int err = 0;
	fsapi_node *child_node = NULL;

	fsapi_log_enter("vol=%p, parent_node=%p, path=%p (->\"%.*s\"), "
		"path_length=%" PRIuz ", out_child_node=%p (->%p), "
		"out_attributes=%p",
		vol, parent_node, path,
		path ? (int) sys_min(path_length, (size_t) INT_MAX) : 0,
		path ? path : 0,
		PRAuz(path_length),
		out_child_node, out_child_node ? *out_child_node : NULL,
		out_attributes);

	err = fsapi_lookup_by_posix_path(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *root_node */
		parent_node,
		/* const char *path */
		path,
		/* size_t path_length */
		path_length,
		/* fsapi_node **out_node */
		&child_node);
	if(err) {
		goto out;
	}
	else if(!child_node || !child_node->parent_directory_object_id) {
		if(out_child_node) {
			*out_child_node = NULL;
		}

		goto out;
	}

	if(child_node && out_attributes) {
		err = fsapi_node_get_attributes_common(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			child_node,
			/* fsapi_node_attributes *attributes */
			out_attributes);
		if(err) {
			goto out;
		}
	}

	if(out_child_node) {
		*out_child_node = child_node;
		child_node = NULL;
	}
out:
	if(child_node) {
		int release_err;

		release_err = fsapi_node_release(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **node */
			&child_node,
			/* size_t release_count */
			1);
		if(release_err) {
			sys_log_perror(release_err, "Error while releasing "
				"node on cleanup");
			err = err ? err : release_err;
		}
	}

	fsapi_log_leave(err, "vol=%p, parent_node=%p, path=%p (->\"%.*s\"), "
		"path_length=%" PRIuz ", out_child_node=%p (->%p), "
		"out_attributes=%p",
		vol, parent_node, path,
		path ? (int) sys_min(path_length, (size_t) INT_MAX) : 0,
		path ? path : 0,
		PRAuz(path_length),
		out_child_node, out_child_node ? *out_child_node : NULL,
		out_attributes);

	return err;
}

int fsapi_node_release(
		fsapi_volume *vol,
		fsapi_node **node,
		size_t release_count)
{
	int err = 0;
	sys_bool cache_locked = SYS_FALSE;

	fsapi_log_enter("vol=%p, node=%p (->%p), release_count=%" PRIuz,
		vol, node, node ? *node : NULL, PRAuz(release_count));

	if((*node) == vol->root_node) {
		/* Root node is not refcounted. It exists until the mount is
		 * torn down. */
		*node = NULL;
		goto out;
	}

	err = sys_mutex_lock(
		/* sys_mutex *mutex */
		&vol->cache_lock);
	if(err) {
		goto out;
	}

	cache_locked = SYS_TRUE;

	if(!(*node)->refcount) {
		sys_log_critical("Attempted to release node with 0 refcount!");
		err = EINVAL;
		goto out;
	}
	else if(release_count > (*node)->refcount) {
		sys_log_critical("Attempted to release more references than "
			"node %p currently has. Node has %" PRIuz " "
			"references. Attempted to release %" PRIuz " "
			"references.",
			*node, PRAuz((*node)->refcount), PRAuz(release_count));
		err = EINVAL;
		goto out;
	}

	sys_log_debug("Releasing node %p. Refcount: %" PRIu64 " -> %" PRIu64,
		*node, PRAu64((*node)->refcount),
		PRAu64((*node)->refcount - release_count));
	(*node)->refcount -= release_count;
	if(!(*node)->refcount) {
		fsapi_node_cache_put(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			*node);
	}
	*node = NULL;
out:
	if(cache_locked) {
		int unlock_err = 0;

		unlock_err = sys_mutex_unlock(
			/* sys_mutex *mutex */
			&vol->cache_lock);
		if(unlock_err) {
			err = err ? err : unlock_err;
			goto out;
		}
	}

	fsapi_log_leave(err, "vol=%p, node=%p (->%p), release_count=%" PRIuz,
		vol, node, node ? *node : NULL, PRAuz(release_count));

	return err;
}

typedef struct {
	fsapi_volume *vol;
	fsapi_node *node;
	fsapi_node_attributes *attributes;
	char *cname;
	size_t cname_length;
	void *handle_dirent_context;
	int (*handle_dirent)(
		void *context,
		const char *name,
		size_t name_length,
		fsapi_node_attributes *attributes);
} fsapi_readdir_context;

static int fsapi_node_list_cache_node(
		fsapi_readdir_context *const context,
		const refschar *const file_name,
		const u16 file_name_length,
		const u16 child_entry_offset,
		const sys_bool is_short_entry,
		const sys_bool is_unresolved_hard_link,
		const u64 node_number,
		const u64 parent_node_object_id,
		const u64 directory_object_id,
		const u64 hard_link_parent_object_id,
		const u64 hard_link_id,
		const u8 *const key,
		const size_t key_size,
		const u8 *const record,
		const size_t record_size)
{
	int err = 0;
	fsapi_node_path_element search_path_element;
	fsapi_node search_node;
	fsapi_node *cached_node = NULL;
	char *cname = NULL;
	size_t cname_length = 0;
	u8 *key_dup = NULL;
	u8 *record_dup = NULL;
	sys_bool cache_locked = SYS_TRUE;

	memset(&search_path_element, 0, sizeof(search_path_element));
	memset(&search_node, 0, sizeof(search_node));

	err = sys_unistr_decode(
		/* const refschar *ins */
		file_name,
		/* size_t ins_len */
		file_name_length,
		/* char **outs */
		&cname,
		/* size_t *outs_len */
		&cname_length);
	if(err) {
		goto out;
	}

	search_path_element.parent = context->node->path;
	search_path_element.depth =
		(context->node->path ? context->node->path->depth : 0) +
		1;
	search_path_element.name_is_subpath = SYS_FALSE;
	search_path_element.name_length = cname_length;
	search_path_element.name.ro = cname;

	search_node.path = &search_path_element;

	err = sys_mutex_lock(
		/* sys_mutex *mutex */
		&context->vol->cache_lock);
	if(err) {
		goto out;
	}

	cache_locked = SYS_TRUE;

	cached_node = refs_rb_tree_find(
		/* struct refs_rb_tree *self */
		context->vol->cache_tree,
		/* void *value */
		&search_node);
	if(cached_node) {
		sys_log_debug("Found 0x%" PRIX64 ":\"%.*s\" in cache. No need "
			"to enter into cache from directory listing...",
			PRAX64(parent_node_object_id),
			(int) sys_min(INT_MAX, cname_length), cname);
		goto out;
	}

	err = sys_malloc(key_size, &key_dup);
	if(err) {
		goto out;
	}

	memcpy(key_dup, key, key_size);

	err = sys_malloc(record_size, &record_dup);
	if(err) {
		goto out;
	}

	memcpy(record_dup, record, record_size);

	sys_log_debug("Entering directory entry 0x%" PRIX64 ":\"%.*s\" with "
		"%" PRIuz "-byte key and %" PRIuz "-byte record into cache...",
		PRAX64(parent_node_object_id),
		(int) sys_min(INT_MAX, cname_length), cname, PRAuz(key_size),
		PRAuz(record_size));

	err = fsapi_node_cache_enter(
		/* fsapi_volume *vol */
		context->vol,
		/* const char *name */
		cname,
		/* size_t name_length */
		cname_length,
		/* fsapi_node_path_element *parent_element */
		context->node->path,
		/* u64 node_number */
		node_number,
		/* u64 parent_directory_object_id */
		parent_node_object_id,
		/* u64 directory_object_id */
		directory_object_id,
		/* u64 hard_link_parent_object_id */
		hard_link_parent_object_id,
		/* u64 hard_link_id */
		hard_link_id,
		/* sys_bool is_short_entry */
		is_short_entry,
		/* sys_bool is_unresolved_hard_link */
		is_unresolved_hard_link,
		/* u16 entry_offset */
		child_entry_offset,
		/* const u8 *key */
		key_dup,
		/* size_t key_size */
		key_size,
		/* u8 *record */
		record_dup,
		/* size_t record_size */
		record_size,
		/* fsapi_node *out_new_node */
		NULL);
	if(err) {
		goto out;
	}

	/* Ownership passed to the cached node. */
	cname = NULL;
	key_dup = NULL;
	record_dup = NULL;
out:
	if(cache_locked) {
		int unlock_err = 0;

		unlock_err = sys_mutex_unlock(
			/* sys_mutex *mutex */
			&context->vol->cache_lock);
		if(unlock_err) {
			err = err ? err : unlock_err;
			goto out;
		}
	}

	if(record_dup) {
		sys_free(record_size, &record_dup);
	}

	if(key_dup) {
		sys_free(key_size, &key_dup);
	}

	if(cname) {
		sys_free(cname_length + 1, &cname);
	}

	return err;
}

static int fsapi_node_list_filldir(
		fsapi_readdir_context *context,
		const refschar *file_name,
		u16 file_name_length,
		sys_bool is_directory,
		u16 child_entry_offset,
		u32 file_flags,
		const u64 node_number,
		u64 parent_node_object_id,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size)
{
	int err = 0;
	char *cname = NULL;
	size_t cname_length = 0;

	if(context->cname) {
		/* We have a reparse point without finding its attribute. Just
		 * return it as-is. */
		err = context->handle_dirent(
			/* void *context */
			context->handle_dirent_context,
			/* const char *name */
			context->cname,
			/* size_t name_length */
			context->cname_length,
			/* fsapi_node_attributes *attributes */
			context->attributes);
		if(err) {
			goto out;
		}

		sys_free(context->cname_length + 1, &context->cname);
		context->cname_length = 0;
	}

	if(context->attributes) {
		err = fsapi_fill_attributes(
			/* fsapi_node_attributes *attrs */
			context->attributes,
			/* sys_bool is_directory */
			is_directory,
			/* u16 child_entry_offset */
			child_entry_offset,
			/* u32 file_flags */
			file_flags,
			/* u64 node_number */
			node_number,
			/* u64 parent_node_object_id */
			parent_node_object_id,
			/* u64 create_time */
			create_time,
			/* u64 last_access_time */
			last_access_time,
			/* u64 last_write_time */
			last_write_time,
			/* u64 last_mft_change_time */
			last_mft_change_time,
			/* u64 file_size */
			file_size,
			/* u64 allocated_size */
			allocated_size);
		if(err) {
			goto out;
		}
	}

	err = sys_unistr_decode(
		/* const refschar *ins */
		file_name,
		/* size_t ins_len */
		file_name_length,
		/* char **outs */
		&cname,
		/* size_t *outs_len */
		&cname_length);
	if(err) {
		sys_log_perror(err, "Error while decoding filename string");
		goto out;
	}

	if(file_flags & REFS_FILE_ATTRIBUTE_REPARSE_POINT) {
		/* Save the cname in the context and wait for the reparse point
		 * attribute to appear. */
		context->cname = cname;
		context->cname_length = cname_length;
		cname = NULL;
		cname_length = 0;
	}
	else {
		err = context->handle_dirent(
			/* void *context */
			context->handle_dirent_context,
			/* const char *name */
			cname,
			/* size_t name_length */
			cname_length,
			/* fsapi_node_attributes *attributes */
			context->attributes);
	}
out:
	if(cname) {
		sys_free(cname_length + 1, &cname);
	}

	return err;
}

static int fsapi_node_list_visit_short_entry(
		void *const _context,
		const refschar *const file_name,
		const u16 file_name_length,
		const u16 child_entry_offset,
		const u32 file_flags,
		const u64 node_number,
		const u64 parent_node_object_id,
		const u64 object_id,
		const u64 hard_link_id,
		const u64 create_time,
		const u64 last_access_time,
		const u64 last_write_time,
		const u64 last_mft_change_time,
		const u64 file_size,
		const u64 allocated_size,
		const u8 *const key,
		const size_t key_size,
		const u8 *const record,
		const size_t record_size)
{
	fsapi_readdir_context *const context =
		(fsapi_readdir_context*) _context;

	int err = 0;
	sys_bool is_hard_link = SYS_FALSE;

	(void) hard_link_id;

	sys_log_debug("Got short entry with file flags 0x%" PRIX32 ", hard "
		"link ID %" PRIu64 ", object ID %" PRIu64,
		PRAX32(file_flags), PRAu64(hard_link_id), PRAu64(object_id));

	err = fsapi_node_list_filldir(
		/* fsapi_readdir_context *context */
		context,
		/* const refschar *file_name */
		file_name,
		/* u16 file_name_length */
		file_name_length,
		/* sys_bool is_directory */
		(file_flags & 0x10000000UL) ? SYS_TRUE : SYS_FALSE,
		/* u16 child_entry_offset */
		child_entry_offset,
		/* u32 file_flags */
		file_flags,
		/* u64 node_number */
		node_number,
		/* u64 parent_node_object_id */
		parent_node_object_id,
		/* u64 create_time */
		create_time,
		/* u64 last_access_time */
		last_access_time,
		/* u64 last_write_time */
		last_write_time,
		/* u64 last_mft_change_time */
		last_mft_change_time,
		/* u64 file_size */
		file_size,
		/* u64 allocated_size */
		allocated_size);
	if(err) {
		goto out;
	}

	if(file_flags & REFS_FILE_ATTRIBUTE_REPARSE_POINT) {
		/* Parse the reparse point node to get the symlink target. */
		refs_node_walk_visitor visitor;

		memset(&visitor, 0, sizeof(visitor));

		visitor.context = context;
		visitor.node_symlink = fsapi_node_list_visit_symlink;

		err = refs_node_walk(
			/* sys_device *dev */
			context->vol->vol->dev,
			/* const REFS_BOOT_SECTOR *bs */
			context->vol->vol->bs,
			/* REFS_SUPERBLOCK_HEADER **sb */
			&context->vol->vol->sb,
			/* REFS_LEVEL1_NODE **primary_level1_node */
			&context->vol->vol->primary_level1_node,
			/* REFS_LEVEL1_NODE **secondary_level1_node */
			&context->vol->vol->secondary_level1_node,
			/* refs_block_map **block_map */
			&context->vol->vol->block_map,
			/* refs_node_cache **node_cache */
			&context->vol->vol->node_cache,
			/* const u64 *start_node */
			NULL,
			/* const u64 *object_id */
			&object_id,
			/* refs_node_walk_visitor *visitor */
			&visitor);
		if(err) {
			goto out;
		}
	}

	is_hard_link =
		(!(file_flags & 0x10000000UL) && hard_link_id) ? SYS_TRUE :
		SYS_FALSE;

	err = fsapi_node_list_cache_node(
		/* fsapi_readdir_context *context */
		context,
		/* const refschar *file_name */
		file_name,
		/* u16 file_name_length */
		file_name_length,
		/* u16 child_entry_offset */
		child_entry_offset,
		/* sys_bool is_short_entry */
		SYS_TRUE,
		/* sys_bool is_unresolved_hard_link */
		is_hard_link,
		/* u64 node_number */
		node_number,
		/* u64 parent_node_object_id */
		parent_node_object_id,
		/* u64 directory_object_id */
		is_hard_link ? 0 : object_id,
		/* u64 hard_link_parent_object_id */
		is_hard_link ? object_id : 0,
		/* u64 hard_link_id */
		is_hard_link ? hard_link_id : 0,
		/* const u8 *key */
		key,
		/* size_t key_size */
		key_size,
		/* const u8 *record */
		record,
		/* size_t record_size */
		record_size);
	if(err) {
		goto out;
	}
out:
	return err;
}

static int fsapi_node_list_visit_long_entry(
		void *const context,
		const le16 *const file_name,
		const u16 file_name_length,
		const u16 child_entry_offset,
		const u32 file_flags,
		const u64 node_number,
		const u64 parent_node_object_id,
		const u64 create_time,
		const u64 last_access_time,
		const u64 last_write_time,
		const u64 last_mft_change_time,
		const u64 file_size,
		const u64 allocated_size,
		const u8 *const key,
		const size_t key_size,
		const u8 *const record,
		const size_t record_size)
{
	int err = 0;

	sys_log_debug("Got long entry with file flags 0x%" PRIX32 ".",
		PRAX32(file_flags));

	err = fsapi_node_list_filldir(
		/* fsapi_readdir_context *context */
		(fsapi_readdir_context*) context,
		/* const refschar *file_name */
		file_name,
		/* u16 file_name_length */
		file_name_length,
		/* sys_bool is_directory */
		SYS_FALSE,
		/* u16 child_entry_offset */
		child_entry_offset,
		/* u32 file_flags */
		file_flags,
		/* u64 node_number */
		node_number,
		/* u64 parent_node_object_id */
		parent_node_object_id,
		/* u64 create_time */
		create_time,
		/* u64 last_access_time */
		last_access_time,
		/* u64 last_write_time */
		last_write_time,
		/* u64 last_mft_change_time */
		last_mft_change_time,
		/* u64 file_size */
		file_size,
		/* u64 allocated_size */
		allocated_size);
	if(err) {
		goto out;
	}

	err = fsapi_node_list_cache_node(
		/* fsapi_readdir_context *context */
		context,
		/* const refschar *file_name */
		file_name,
		/* u16 file_name_length */
		file_name_length,
		/* u16 child_entry_offset */
		child_entry_offset,
		/* sys_bool is_short_entry */
		SYS_FALSE,
		/* sys_bool is_unresolved_hard_link */
		SYS_FALSE,
		/* u64 node_number */
		node_number,
		/* u64 parent_node_object_id */
		parent_node_object_id,
		/* u64 directory_object_id */
		0,
		/* u64 hard_link_parent_object_id */
		0,
		/* u64 hard_link_id */
		0,
		/* const u8 *key */
		key,
		/* size_t key_size */
		key_size,
		/* const u8 *record */
		record,
		/* size_t record_size */
		record_size);
	if(err) {
		goto out;
	}
out:
	return err;
}

static int fsapi_node_list_visit_symlink(
		void *const _context,
		const refs_symlink_type type,
		const char *const target,
		const size_t target_length)
{
	fsapi_readdir_context *const context =
		(fsapi_readdir_context*) _context;

	int err = 0;

	(void) type;

	if(context->attributes->requested & FSAPI_NODE_ATTRIBUTE_TYPE_SIZE) {
		context->attributes->size = target_length;
		context->attributes->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_SIZE;
	}

	if(context->attributes->requested & FSAPI_NODE_ATTRIBUTE_TYPE_MODE) {
		context->attributes->mode =
			SYS_S_IFLNK | (context->attributes->mode & ~S_IFMT);
	}

	if(context->attributes->requested &
		FSAPI_NODE_ATTRIBUTE_TYPE_SYMLINK_TARGET)
	{
		size_t symlink_target_size;

		if(!context->attributes->symlink_target) {
			symlink_target_size = target_length + 1;
			err = sys_malloc(symlink_target_size,
				&context->attributes->symlink_target);
			if(err) {
				goto out;
			}
		}
		else {
			symlink_target_size =
				context->attributes->symlink_target_length;
		}

		memcpy(context->attributes->symlink_target, target,
			sys_min(symlink_target_size, target_length));
		if(symlink_target_size > target_length) {
			context->attributes->symlink_target[target_length] =
				'\0';
		}

		context->attributes->valid |=
			FSAPI_NODE_ATTRIBUTE_TYPE_SYMLINK_TARGET;
	}

	err = context->handle_dirent(
		/* void *context */
		context->handle_dirent_context,
		/* const char *name */
		context->cname,
		/* size_t name_length */
		context->cname_length,
		/* fsapi_node_attributes *attributes */
		context->attributes);
out:
	if(context->cname) {
		sys_free(context->cname_length + 1, &context->cname);
		context->cname_length = 0;
	}

	return err;
}

int fsapi_node_list(
		fsapi_volume *vol,
		fsapi_node *directory_node,
		fsapi_node_attributes *attributes,
		void *context,
		int (*handle_dirent)(
			void *context,
			const char *name,
			size_t name_length,
			fsapi_node_attributes *attributes))
{
	int err = 0;
	fsapi_readdir_context readdir_context;
	refs_node_walk_visitor visitor;

	memset(&readdir_context, 0, sizeof(readdir_context));
	memset(&visitor, 0, sizeof(visitor));

	fsapi_log_enter("vol=%p, directory_node=%p, attributes=%p, "
		"context=%p, handle_dirent=%p",
		vol, directory_node, attributes, context, handle_dirent);

	if(!directory_node->directory_object_id) {
		err = ENOTDIR;
		goto out;
	}

	readdir_context.vol = vol;
	readdir_context.node = directory_node;
	readdir_context.attributes = attributes;
	readdir_context.handle_dirent_context = context;
	readdir_context.handle_dirent = handle_dirent;
	visitor.context = &readdir_context;
	visitor.node_long_entry = fsapi_node_list_visit_long_entry;
	visitor.node_short_entry = fsapi_node_list_visit_short_entry;
	visitor.node_symlink = fsapi_node_list_visit_symlink;

	err = refs_node_walk(
		/* sys_device *dev */
		vol->vol->dev,
		/* const REFS_BOOT_SECTOR *bs */
		vol->vol->bs,
		/* REFS_SUPERBLOCK_HEADER **sb */
		&vol->vol->sb,
		/* REFS_LEVEL1_NODE **primary_level1_node */
		&vol->vol->primary_level1_node,
		/* REFS_LEVEL1_NODE **secondary_level1_node */
		&vol->vol->secondary_level1_node,
		/* refs_block_map **block_map */
		&vol->vol->block_map,
		/* refs_node_cache **node_cache */
		&vol->vol->node_cache,
		/* const u64 *start_node */
		NULL,
		/* const u64 *object_id */
		&directory_node->directory_object_id,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err == -1) {
		/* No need to log the 'break' error code but return to caller as
		 * this may be useful information. */
	}
	else if(err) {
		sys_log_perror(err, "Error while listing directory");
		goto out;
	}

	if(readdir_context.cname) {
		/* We have a reparse point without finding its attribute. Just
		 * return it as-is. */
		err = readdir_context.handle_dirent(
			/* void *context */
			readdir_context.handle_dirent_context,
			/* const char *name */
			readdir_context.cname,
			/* size_t name_length */
			readdir_context.cname_length,
			/* fsapi_node_attributes *attributes */
			readdir_context.attributes);

		sys_free(readdir_context.cname_length + 1,
			&readdir_context.cname);
		readdir_context.cname_length = 0;
	}
out:
	if(readdir_context.cname) {
		sys_free(readdir_context.cname_length + 1,
			&readdir_context.cname);
	}

	fsapi_log_leave(err, "vol=%p, directory_node=%p, attributes=%p, "
		"context=%p, handle_dirent=%p",
		vol, directory_node, attributes, context, handle_dirent);

	return err;
}

int fsapi_node_get_attributes(
		fsapi_volume *vol,
		fsapi_node *node,
		fsapi_node_attributes *out_attributes)
{
	int err;

	fsapi_log_enter("vol=%p, node=%p, out_attributes=%p",
		vol, node, out_attributes);

	err = fsapi_node_get_attributes_common(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* fsapi_node_attributes *attributes */
		out_attributes);

	fsapi_log_leave(err, "vol=%p, node=%p, out_attributes=%p",
		vol, node, out_attributes);

	return err;
}

int fsapi_node_set_attributes(
		fsapi_volume *vol,
		fsapi_node *node,
		fsapi_node_attributes *attributes)
{
	int err;

	fsapi_log_enter("vol=%p, node=%p, attributes=%p",
		vol, node, attributes);

	(void) vol;
	(void) node;
	(void) attributes;

	err = EROFS;

	fsapi_log_leave(err, "vol=%p, node=%p, attributes=%p",
		vol, node, attributes);

	return err;
}

typedef struct {
	sys_bool is_short_entry;
	u16 data_size;
	char data[0];
} fsapi_refs_raw_node_data;

int fsapi_node_get_raw_data(
		fsapi_volume *vol,
		fsapi_node *node,
		void **out_raw_data)
{
	int err = 0;
	fsapi_refs_raw_node_data *raw_data = NULL;

	fsapi_log_enter("vol=%p, node=%p, out_raw_data=%p",
		vol, node, out_raw_data);

	(void) vol;

	err = sys_malloc(sizeof(fsapi_refs_raw_node_data) + node->record_size,
		&raw_data);
	if(err) {
		goto out;
	}

	raw_data->is_short_entry = node->is_short_entry;
	raw_data->data_size = node->record_size;
	memcpy(&raw_data->data[0], node->record, node->record_size);

	*out_raw_data = raw_data;
out:
	fsapi_log_leave(err, "vol=%p, node=%p, out_raw_data=%p",
		vol, node, out_raw_data);

	return err;
}

typedef struct {
	refs_volume *vol;
	fsapi_iohandler *iohandler;
	size_t size;
	sys_bool is_sparse;
	u64 cur_offset;
	u64 start_offset;
	size_t bytes_read_in_iteration;
} fsapi_node_read_context;

static int fsapi_node_read_zeroes(
		fsapi_node_read_context *const context,
		const size_t bytes_to_zero)
{
	int err = 0;
	u8 zero_data[512];
	size_t remaining_bytes_to_zero = bytes_to_zero;

	memset(zero_data, 0, sizeof(zero_data));

	while(remaining_bytes_to_zero) {
		const size_t cur_bytes_to_zero =
			sys_min(sizeof(zero_data), remaining_bytes_to_zero);

		err = context->iohandler->copy_data(
			/* void *context */
			context->iohandler->context,
			/* const void *data */
			zero_data,
			/* size_t size */
			cur_bytes_to_zero);
		if(err) {
			context->cur_offset +=
				bytes_to_zero - remaining_bytes_to_zero;
			context->size -=
				bytes_to_zero - remaining_bytes_to_zero;
			goto out;
		}

		remaining_bytes_to_zero -= cur_bytes_to_zero;
	}

	context->cur_offset += bytes_to_zero;
	context->size -= bytes_to_zero;
out:
	return err;
}

static int fsapi_node_read_visit_entry(
		fsapi_node_read_context *const context,
		const u32 file_flags,
		const u64 file_size)
{
	int err = 0;
	u64 bytes_to_eof;

	if(file_flags & REFS_FILE_ATTRIBUTE_SPARSE_FILE) {
		sys_log_debug("File is sparse.");
		context->is_sparse = SYS_TRUE;
	}

	if(context->start_offset >= file_size) {
		/* Nothing to read. */
		sys_log_debug("Nothing to read, offset is beyond or at file "
			"size.");
		context->size = 0;
		err = -1;
		goto out;
	}

	bytes_to_eof = file_size - context->start_offset;
	if(context->size > bytes_to_eof) {
		/* Limit read to the end of the file. */
		sys_log_debug("Limiting read to end of file: %" PRIu64 " -> "
			"%" PRIu64,
			PRAu64(context->size), PRAu64(bytes_to_eof));
		context->size = bytes_to_eof;
	}
out:
	return err;
}

static int fsapi_node_read_visit_long_entry(
		void *const _context,
		const le16 *const file_name,
		const u16 file_name_length,
		const u16 child_entry_offset,
		const u32 file_flags,
		const u64 node_number,
		const u64 parent_node_object_id,
		const u64 create_time,
		const u64 last_access_time,
		const u64 last_write_time,
		const u64 last_mft_change_time,
		const u64 file_size,
		const u64 allocated_size,
		const u8 *const key,
		const size_t key_size,
		const u8 *const record,
		const size_t record_size)
{
	fsapi_node_read_context *const context =
		(fsapi_node_read_context*) _context;

	int err = 0;

	(void) file_name;
	(void) file_name_length;
	(void) child_entry_offset;
	(void) file_flags;
	(void) node_number;
	(void) parent_node_object_id;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) allocated_size;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	err = fsapi_node_read_visit_entry(
		/* fsapi_node_read_context *context */
		context,
		/* u32 file_flags */
		file_flags,
		/* u64 file_size */
		file_size);

	return err;
}

static int fsapi_node_read_visit_hardlink_entry(
		void *const _context,
		const u64 hard_link_id,
		const u64 parent_id,
		const u16 child_entry_offset,
		const u32 file_flags,
		const u64 node_number,
		const u64 create_time,
		const u64 last_access_time,
		const u64 last_write_time,
		const u64 last_mft_change_time,
		const u64 file_size,
		const u64 allocated_size,
		const u8 *const key,
		const size_t key_size,
		const u8 *const record,
		const size_t record_size)
{
	fsapi_node_read_context *const context =
		(fsapi_node_read_context*) _context;

	int err = 0;

	(void) hard_link_id;
	(void) parent_id;
	(void) child_entry_offset;
	(void) file_flags;
	(void) node_number;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) allocated_size;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	err = fsapi_node_read_visit_entry(
		/* fsapi_node_read_context *context */
		context,
		/* u32 file_flags */
		file_flags,
		/* u64 file_size */
		file_size);

	return err;
}

static int fsapi_node_read_visit_file_extent(
		void *const _context,
		const u64 first_logical_block,
		const u64 first_physical_block,
		const u64 block_count,
		const u32 block_index_unit)
{
	fsapi_node_read_context *const context =
		(fsapi_node_read_context*) _context;
	const u64 extent_logical_start = first_logical_block * block_index_unit;
	const u64 extent_size = block_count * block_index_unit;

	int err = 0;
	size_t copy_offset_in_buffer = 0;
	u64 remaining_bytes = 0;
	u64 offset_in_extent = 0;
	u64 remaining_extent_size = 0;
	u64 valid_extent_size = 0;
	u64 cur_pos = 0;
	size_t bytes_to_read = 0;

	sys_log_debug("Visiting file extent: [%" PRIu64 " - %" PRIu64 "] -> "
		"[%" PRIu64 " - %" PRIu64 "] (%" PRIu64 " blocks) Position "
		"(current): %" PRIu64 " Position (start): %" PRIu64 " "
		"Remaining size: %" PRIuz,
		PRAu64(first_logical_block),
		PRAu64(first_logical_block + block_count - 1),
		PRAu64(first_physical_block),
		PRAu64(first_physical_block + block_count - 1),
		PRAu64(block_count), PRAu64(context->cur_offset),
		PRAu64(context->start_offset), PRAuz(context->size));

	if(extent_logical_start + extent_size <= context->cur_offset) {
		goto out;
	}
	else if(extent_logical_start + extent_size <= context->start_offset) {
		sys_log_debug("Skipping extent that precedes the start offset "
			"of the read: %" PRIu64 " <= %" PRIu64,
			PRAu64(context->cur_offset + extent_size),
			PRAu64(context->start_offset));
		context->cur_offset += extent_size;
		goto out;
	}
	else if(extent_logical_start > context->cur_offset) {
		if(context->is_sparse) {
			/* We have encountered a hole. Return zeroes until we
			 * reach context->cur_offset or until the end of the
			 * read. */
			const u64 bytes_to_extent =
				extent_logical_start - context->cur_offset;
			const size_t bytes_to_zero =
				(size_t) sys_min(bytes_to_extent,
				context->size);

			err = fsapi_node_read_zeroes(
				/* fsapi_node_read_context *context */
				context,
				/* size_t bytes_to_zero */
				bytes_to_zero);
			if(err) {
				goto out;
			}

			if(!context->size) {
				goto out;
			}
		}
		else {
			/* Ignore extent. We'll get back to it in the next
			 * iteration. */
			goto out;
		}
	}

	copy_offset_in_buffer =
		((context->cur_offset < context->start_offset) ?
		context->start_offset - context->cur_offset : 0);
	remaining_bytes = copy_offset_in_buffer + context->size;
	offset_in_extent = context->cur_offset - extent_logical_start;
	remaining_extent_size = extent_size - offset_in_extent;
	valid_extent_size = sys_min(remaining_extent_size, remaining_bytes);
	valid_extent_size =
		/* Round up to the nearest sector boundary (this assumes that
		 * sector size is a power of 2!). */
		(valid_extent_size + (context->vol->sector_size - 1)) &
		~((u64) (context->vol->sector_size - 1));
	cur_pos = first_physical_block * block_index_unit;
	bytes_to_read = (size_t) sys_min(valid_extent_size, context->size);

	sys_log_debug("Reading %" PRIuz " bytes...",
		PRAuz(bytes_to_read));

	err = context->iohandler->handle_io(
		/* void *context */
		context->iohandler->context,
		/* sys_device *dev */
		context->vol->dev,
		/* u64 offset */
		cur_pos + copy_offset_in_buffer,
		/* size_t size */
		bytes_to_read);
	if(err) {
		/* Break code used by the handler when it wants
		 * to stop the iteration. */
		if(err == -1) {
			err = 0;
		}

		goto out;
	}

	context->cur_offset += bytes_to_read;
	context->size -= bytes_to_read;
	context->bytes_read_in_iteration += bytes_to_read;
out:
	return err;
}

static int fsapi_node_read_visit_file_data(
		void *const _context,
		const void *const data,
		const size_t size)
{
	fsapi_node_read_context *const context =
		(fsapi_node_read_context*) _context;

	int err = 0;
	size_t bytes_to_copy = 0;

	if(context->cur_offset >= size) {
		goto out;
	}
	else if(context->start_offset >= size) {
		context->cur_offset = size;
		goto out;
	}

	bytes_to_copy =
		sys_min(context->size, size - (size_t) context->start_offset);

	err = context->iohandler->copy_data(
		/* void *context */
		context->iohandler->context,
		/* sys_device *dev */
		data,
		/* size_t size */
		size);
	if(err) {
		/* Break code used by the handler when it wants
		 * to stop the iteration. */
		if(err == -1) {
			err = 0;
		}

		goto out;
	}

	context->size -= bytes_to_copy;
	context->cur_offset = context->start_offset + bytes_to_copy;
	context->bytes_read_in_iteration += bytes_to_copy;
out:
	return err;
}

int fsapi_node_read(
		fsapi_volume *vol,
		fsapi_node *node,
		u64 offset,
		size_t size,
		fsapi_iohandler *iohandler)
{
	int err = 0;
	fsapi_node_read_context context;
	refs_node_crawl_context crawl_context;
	refs_node_walk_visitor visitor;

	memset(&context, 0, sizeof(context));
	memset(&visitor, 0, sizeof(visitor));

	fsapi_log_enter("vol=%p, node=%p, offset=%" PRIu64 ", "
		"size=%" PRIuz ", iohandler=%p",
		vol, node, PRAu64(offset), PRAuz(size), iohandler);

	context.vol = vol->vol;
	context.iohandler = iohandler;
	context.size = size;
	context.cur_offset = offset;
	context.start_offset = offset;

	if(node->is_short_entry) {
		/* Don't know how to find extents for short entries yet. These
		 * may be hard links and might need resolving in other ways. */
		goto out;
	}

	crawl_context = refs_volume_init_node_crawl_context(
		/* refs_volume *vol */
		vol->vol);
	visitor.context = &context;
	visitor.node_long_entry = fsapi_node_read_visit_long_entry;
	visitor.node_hardlink_entry = fsapi_node_read_visit_hardlink_entry;
	visitor.node_file_extent = fsapi_node_read_visit_file_extent;
	visitor.node_file_data = fsapi_node_read_visit_file_data;

	do {
		context.bytes_read_in_iteration = 0;
		err = parse_level3_long_value(
			/* refs_node_crawl_context *crawl_context */
			&crawl_context,
			/* refs_node_walk_visitor *visitor */
			&visitor,
			/* const char *prefix */
			"",
			/* size_t indent */
			1,
			/* u64 parent_node_object_id */
			node->parent_directory_object_id,
			/* u64 node_number */
			node->node_number,
			/* u16 entry_offset */
			node->entry_offset,
			/* const u8 *key */
			node->key,
			/* u16 key_size */
			node->key_size,
			/* const u8 *value */
			node->record,
			/* u16 value_offset */
			0,
			/* u16 value_size */
			node->record_size,
			/* void *context */
			NULL);
		if(err == -1) {
			err = 0;
		}
		else if(err) {
			goto out;
		}

		/* Clear the long entry/hard link entry callback on repeated
		 * iterations since we already have gathered the needed data
		 * from the file/hardlink entry. */
		visitor.node_long_entry = NULL;
		visitor.node_hardlink_entry = NULL;
	} while(context.bytes_read_in_iteration && context.size);

	if(context.size) {
		if(!context.is_sparse) {
			sys_log_error("Couldn't find all extents in non-sparse "
				"file: %" PRIuz " remaining bytes",
				PRAuz(context.size));
			err = EIO;
			goto out;
		}

		sys_log_debug("Filling sparse tail with %" PRIuz " zeroed "
			"bytes.", PRAuz(context.size));
		err = fsapi_node_read_zeroes(
			/* fsapi_node_read_context *context */
			&context,
			/* size_t bytes_to_zero */
			context.size);
		if(err) {
			goto out;
		}
	}
out:
	fsapi_log_leave(err, "vol=%p, node=%p, offset=%" PRIu64 ", "
		"size=%" PRIuz ", iohandler=%p",
		vol, node, PRAu64(offset), PRAuz(size), iohandler);

	return err;
}

int fsapi_node_write(
		fsapi_volume *vol,
		fsapi_node *node,
		u64 offset,
		size_t size,
		fsapi_iohandler *iohandler)
{
	int err;

	fsapi_log_enter("vol=%p, node=%p, offset=%" PRIu64 ", "
		"size=%" PRIuz ", iohandler=%p",
		vol, node, PRAu64(offset), PRAuz(size), iohandler);

	(void) vol;
	(void) node;
	(void) offset;
	(void) size;
	(void) iohandler;

	err = EROFS;

	fsapi_log_leave(err, "vol=%p, node=%p, offset=%" PRIu64 ", "
		"size=%" PRIuz ", iohandler=%p",
		vol, node, PRAu64(offset), PRAuz(size), iohandler);

	return err;
}

int fsapi_node_sync(
		fsapi_volume *vol,
		fsapi_node *node,
		sys_bool data_only)
{
	int err;

	fsapi_log_enter("vol=%p, node=%p, data_only=%u",
		vol, node, data_only);

	(void) vol;
	(void) node;
	(void) data_only;

	/* Syncing is always successful because there's nothing to sync at the
	 * moment. */
	err = 0;

	fsapi_log_leave(err, "vol=%p, node=%p, data_only=%u",
		vol, node, data_only);

	return err;
}

int fsapi_node_create(
		fsapi_volume *vol,
		fsapi_node *node,
		const char *name,
		size_t name_length,
		fsapi_node_attributes *attributes,
		fsapi_node **out_node)
{
	int err;

	fsapi_log_enter("vol=%p, node=%p, name=%p (->%.*s), "
		"name_length=%" PRIuz ", attributes=%p, out_node=%p (->%p)",
		vol, node,
		name, name ? (int) sys_min(name_length, INT_MAX) : 0,
		name ? name : "",
		PRAuz(name_length),
		attributes,
		out_node, out_node ? *out_node : NULL);


	(void) vol;
	(void) node;
	(void) name;
	(void) name_length;
	(void) attributes;
	(void) out_node;

	err = EROFS;

	fsapi_log_leave(err, "vol=%p, node=%p, name=%p (->%.*s), "
		"name_length=%" PRIuz ", attributes=%p, out_node=%p (->%p)",
		vol, node,
		name, name ? (int) sys_min(name_length, INT_MAX) : 0,
		name ? name : "",
		PRAuz(name_length),
		attributes,
		out_node, out_node ? *out_node : NULL);

	return err;
}

int fsapi_node_hardlink(
		fsapi_volume *vol,
		fsapi_node *node,
		fsapi_node *link_parent,
		const char *link_name,
		size_t link_name_length,
		fsapi_node_attributes *out_attributes)
{
	int err;

	fsapi_log_enter("vol=%p, node=%p, link_parent=%p, "
		"link_name=%p (->%.*s), link_name_length=%" PRIuz ", "
		"out_attributes=%p",
		vol, node, link_parent,
		link_name,
		link_name ? (int) sys_min(link_name_length, INT_MAX) : 0,
		link_name ? link_name : "",
		PRAuz(link_name_length),
		out_attributes);

	(void) vol;
	(void) node;
	(void) link_parent;
	(void) link_name;
	(void) link_name_length;
	(void) out_attributes;

	err = EROFS;

	fsapi_log_leave(err, "vol=%p, node=%p, link_parent=%p, "
		"link_name=%p (->%.*s), link_name_length=%" PRIuz ", "
		"out_attributes=%p",
		vol, node, link_parent,
		link_name,
		link_name ? (int) sys_min(link_name_length, INT_MAX) : 0,
		link_name ? link_name : "",
		PRAuz(link_name_length),
		out_attributes);

	return err;
}

int fsapi_node_rename(
		fsapi_volume *vol,
		fsapi_node *source_dir_node,
		const char *source_name,
		size_t source_name_length,
		fsapi_node *target_dir_node,
		const char *target_name,
		size_t target_name_length,
		fsapi_rename_flags flags)
{
	int err;


	fsapi_log_enter("vol=%p, source_dir_node=%p, "
		"source_name=%p (->%.*s), source_name_length=%" PRIuz ", "
		"target_dir_node=%p, target_name=%p (->%.*s), "
		"target_name_length=%" PRIuz ", flags=0x%X",
		vol,
		source_dir_node,
		source_name,
		source_name ? (int) sys_min(source_name_length, INT_MAX) : 0,
		source_name ? source_name : "",
		PRAuz(source_name_length),
		target_dir_node,
		target_name,
		target_name ? (int) sys_min(target_name_length, INT_MAX) : 0,
		target_name ? target_name : "",
		PRAuz(target_name_length),
		flags);

	(void) vol;
	(void) source_dir_node;
	(void) source_name;
	(void) source_name_length;
	(void) target_dir_node;
	(void) target_name;
	(void) target_name_length;
	(void) flags;

	err = EROFS;

	fsapi_log_leave(err, "vol=%p, source_dir_node=%p, "
		"source_name=%p (->%.*s), source_name_length=%" PRIuz ", "
		"target_dir_node=%p, target_name=%p (->%.*s), "
		"target_name_length=%" PRIuz ", flags=0x%X",
		vol,
		source_dir_node,
		source_name,
		source_name ? (int) sys_min(source_name_length, INT_MAX) : 0,
		source_name ? source_name : "",
		PRAuz(source_name_length),
		target_dir_node,
		target_name,
		target_name ? (int) sys_min(target_name_length, INT_MAX) : 0,
		target_name ? target_name : "",
		PRAuz(target_name_length),
		flags);

	return err;
}

int fsapi_node_remove(
		fsapi_volume *vol,
		fsapi_node *parent_node,
		sys_bool is_directory,
		const char *name,
		size_t name_length,
		fsapi_node **out_removed_node)
{
	int err;

	fsapi_log_enter("vol=%p, parent_node=%p, is_directory=%u, "
		"name=%p (->%.*s), name_length=%" PRIuz ", "
		"out_removed_node=%p (->%p)",
		vol, parent_node, is_directory,
		name, name ? (int) sys_min(name_length, INT_MAX) : 0,
		name ? name : "",
		PRAuz(name_length),
		out_removed_node, out_removed_node ? *out_removed_node : NULL);

	(void) vol;
	(void) parent_node;
	(void) is_directory;
	(void) name;
	(void) name_length;
	(void) out_removed_node;

	err = EROFS;

	fsapi_log_leave(err, "vol=%p, parent_node=%p, is_directory=%u, "
		"name=%p (->%.*s), name_length=%" PRIuz ", "
		"out_removed_node=%p (->%p)",
		vol, parent_node, is_directory,
		name, name ? (int) sys_min(name_length, INT_MAX) : 0,
		name ? name : "",
		PRAuz(name_length),
		out_removed_node, out_removed_node ? *out_removed_node : NULL);

	return err;
}

typedef struct {
	refs_volume *vol;
	sys_bool show_eas;
	sys_bool show_streams;
	void *context;
	int (*xattr_handler)(
		void *context,
		const char *name,
		size_t name_length,
		size_t size);
} fsapi_node_list_extended_attributes_context;

static int fsapi_node_list_extended_attributes_visit_ea(
		void *const context,
		const char *const name,
		const size_t name_length,
		const void *const data,
		const size_t data_size)
{
	fsapi_node_list_extended_attributes_context *const ctx =
		(fsapi_node_list_extended_attributes_context*) context;

	int err = 0;

	(void) data;

	if(ctx->show_eas) {
		err = ctx->xattr_handler(
			/* void *context */
			ctx->context,
			/* const char *name */
			name,
			/* size_t name_length */
			name_length,
			/* size_t size */
			data_size);
	}

	return err;
}

static int fsapi_node_list_extended_attributes_visit_stream(
		void *const context,
		const char *const name,
		const size_t name_length,
		const u64 data_size,
		const refs_node_stream_data *const data_reference)
{
	fsapi_node_list_extended_attributes_context *const ctx =
		(fsapi_node_list_extended_attributes_context*) context;

	int err = 0;

	(void) data_reference;

	if(ctx->show_streams) {
		err = ctx->xattr_handler(
			/* void *context */
			ctx->context,
			/* const char *name */
			name,
			/* size_t name_length */
			name_length,
			/* size_t size */
			data_size);
	}

	return err;
}

int fsapi_node_list_extended_attributes(
		fsapi_volume *vol,
		fsapi_node *node,
		void *context,
		int (*xattr_handler)(
			void *context,
			const char *name,
			size_t name_length,
			size_t size))
{
	int err = 0;

	fsapi_node_list_extended_attributes_context xattr_context;
	refs_node_crawl_context crawl_context;
	refs_node_walk_visitor visitor;

	memset(&xattr_context, 0, sizeof(xattr_context));
	memset(&crawl_context, 0, sizeof(crawl_context));
	memset(&visitor, 0, sizeof(visitor));

	fsapi_log_enter("vol=%p, node=%p, context=%p, xattr_handler=%p",
		vol, node, context, xattr_handler);

	if(node == vol->root_node || node->is_short_entry) {
		/* TODO: Check where root node's streams and EAs are located. */
		err = 0;
		goto out;
	}

	xattr_context.vol = vol->vol;
	if(vol->xattr_mode == FSAPI_REFS_XATTR_MODE_BOTH ||
		vol->xattr_mode == FSAPI_REFS_XATTR_MODE_EAS)
	{
		xattr_context.show_eas = SYS_TRUE;
	}
	if(vol->xattr_mode == FSAPI_REFS_XATTR_MODE_BOTH ||
		vol->xattr_mode == FSAPI_REFS_XATTR_MODE_STREAMS)
	{
		xattr_context.show_streams = SYS_TRUE;
	}
	xattr_context.context = context;
	xattr_context.xattr_handler = xattr_handler;

	crawl_context = refs_volume_init_node_crawl_context(
		/* refs_volume *vol */
		vol->vol);
	visitor.context = &xattr_context;
	visitor.node_ea = fsapi_node_list_extended_attributes_visit_ea;
	visitor.node_stream = fsapi_node_list_extended_attributes_visit_stream;

	err = parse_level3_long_value(
		/* refs_node_crawl_context *crawl_context */
		&crawl_context,
		/* refs_node_walk_visitor *visitor */
		&visitor,
		/* const char *prefix */
		"",
		/* size_t indent */
		1,
		/* u64 parent_node_object_id */
		node->parent_directory_object_id,
		/* u64 node_number */
		node->node_number,
		/* u16 entry_offset */
		node->entry_offset,
		/* const u8 *key */
		node->key,
		/* u16 key_size */
		node->key_size,
		/* const u8 *value */
		node->record,
		/* u16 value_offset */
		0,
		/* u16 value_size */
		node->record_size,
		/* void *context */
		NULL);
	if(err == -1) {
		err = 0;
	}
	else if(err) {
		sys_log_perror(err, "Error while parsing node for listing "
			"extended attributes");
	}
out:
	fsapi_log_leave(err, "vol=%p, node=%p, context=%p, xattr_handler=%p",
		vol, node, context, xattr_handler);

	return err;
}

typedef struct {
	refs_volume *vol;
	const char *xattr_name;
	size_t xattr_name_length;
	u64 offset;
	size_t size;
	fsapi_iohandler *iohandler;
	sys_bool stream_found;
	u64 stream_non_resident_id;
	u64 stream_size;
	u64 remaining_bytes;
} fsapi_node_read_extended_attribute_context;

static int fsapi_node_read_extended_attribute_visit_ea(
		void *const _context,
		const char *const name,
		const size_t name_length,
		const void *const data,
		const size_t data_size)
{
	fsapi_node_read_extended_attribute_context *const context =
		(fsapi_node_read_extended_attribute_context*) _context;

	int err = 0;

	if(name_length != context->xattr_name_length ||
		memcmp(name, context->xattr_name, name_length))
	{
		/* No match. */
		goto out;
	}

	context->stream_found = SYS_TRUE;
	context->stream_size = data_size;
	context->remaining_bytes = data_size;

	if(context->iohandler) {
		err = context->iohandler->copy_data(
			/* void *context */
			context->iohandler->context,
			/* const void *data */
			data,
			/* size_t size */
			data_size);
		if(err) {
			goto out;
		}

		context->remaining_bytes -= data_size;
	}

	/* Stop iterating since we found our match. */
	err = -1;
out:
	return err;
}

static int fsapi_node_read_extended_attribute_visit_stream(
		void *const _context,
		const char *const name,
		const size_t name_length,
		const u64 data_size,
		const refs_node_stream_data *const data_reference)
{
	fsapi_node_read_extended_attribute_context *const context =
		(fsapi_node_read_extended_attribute_context*) _context;
	int err = 0;

	if(name_length != context->xattr_name_length ||
		memcmp(name, context->xattr_name, name_length))
	{
		/* No match. */
		goto out;
	}

	context->stream_found = SYS_TRUE;
	if(!context->remaining_bytes) {
		context->remaining_bytes = data_size;
	}
	context->stream_size = data_size;

	if(!context->iohandler);
	else if(data_reference->resident) {
		err = context->iohandler->copy_data(
			/* void *context */
			context->iohandler->context,
			/* const void *data */
			data_reference->data.resident,
			/* size_t size */
			data_size);
		if(err) {
			goto out;
		}

		context->remaining_bytes -= data_size;
	}
	else {
		context->stream_non_resident_id =
			data_reference->data.non_resident.stream_id;
	}

	/* Stop iterating since we found our match. Stream extents will be
	 * iterated over separately as they may precede this entry. */
	err = -1;
out:
	return err;
}

static int fsapi_node_read_extended_attribute_visit_stream_extent(
		void *const _context,
		const u64 stream_id,
		const u64 first_logical_block,
		const u64 first_physical_block,
		const u32 block_index_unit,
		const u32 cluster_count)
{
	fsapi_node_read_extended_attribute_context *const context =
		(fsapi_node_read_extended_attribute_context*) _context;
	const u64 read_offset = first_physical_block * block_index_unit;
	const u64 extent_size = cluster_count * context->vol->cluster_size;
	const u64 valid_extent_size =
		sys_min(extent_size, context->remaining_bytes);

	int err = 0;

	sys_log_debug("Got stream extent with stream id 0x%" PRIX64 ", first "
		"logical block 0x%" PRIX64 ", first physical block "
		"0x%" PRIX64 "...",
		PRAX64(stream_id), PRAX64(first_logical_block),
		PRAX64(first_physical_block));

	if(stream_id != context->stream_non_resident_id) {
		/* Not the stream that we are looking for. */
		goto out;
	}

	/* TODO: Skip holes in attribute stream extents? Are they even allowed
	 * to be sparse? */
	(void) first_logical_block;

	err = context->iohandler->handle_io(
		/* void *context */
		context->iohandler->context,
		/* sys_device *dev */
		context->vol->dev,
		/* u64 offset */
		read_offset,
		/* size_t size */
		valid_extent_size);
	if(err) {
		goto out;
	}

	context->remaining_bytes -= valid_extent_size;

	/* Stop iterating since we found our match. Stream extents will be
	 * iterated over separately as they may precede this entry. */
	err = -1;
out:
	return err;
}

int fsapi_node_read_extended_attribute(
		fsapi_volume *vol,
		fsapi_node *node,
		const char *xattr_name,
		size_t xattr_name_length,
		u64 offset,
		size_t size,
		fsapi_iohandler *iohandler,
		u64 *out_xattr_size)
{
	int err = 0;

	fsapi_node_read_extended_attribute_context context;
	refs_node_crawl_context crawl_context;
	refs_node_walk_visitor visitor;

	memset(&context, 0, sizeof(context));
	memset(&crawl_context, 0, sizeof(crawl_context));
	memset(&visitor, 0, sizeof(visitor));

	fsapi_log_enter("vol=%p, node=%p, xattr_name=%p (->%.*s), "
		"xattr_name_length=%" PRIuz ", offset=%" PRIu64 ", "
		"size=%" PRIuz ", iohandler=%p, out_xattr_size=%p "
		"(->%" PRIu64 ")",
		vol, node, xattr_name,
		xattr_name ? (int) sys_min(xattr_name_length, INT_MAX) : 0,
		xattr_name ? xattr_name : "",
		PRAuz(xattr_name_length), PRAu64(offset), PRAuz(size),
		iohandler, out_xattr_size,
		PRAu64(out_xattr_size ? *out_xattr_size : 0));

	if(node == vol->root_node || node->is_short_entry) {
		/* TODO: Check where root node's streams and EAs are located. */
		err = ENOENT;
		goto out;
	}

	crawl_context = refs_volume_init_node_crawl_context(
		/* refs_volume *vol */
		vol->vol);
	context.vol = vol->vol;
	context.xattr_name = xattr_name;
	context.xattr_name_length = xattr_name_length;
	context.offset = offset;
	context.size = size;
	context.iohandler = iohandler;
	visitor.context = &context;
	visitor.node_ea = fsapi_node_read_extended_attribute_visit_ea;
	visitor.node_stream = fsapi_node_read_extended_attribute_visit_stream;

	err = parse_level3_long_value(
		/* refs_node_crawl_context *crawl_context */
		&crawl_context,
		/* refs_node_walk_visitor *visitor */
		&visitor,
		/* const char *prefix */
		"",
		/* size_t indent */
		1,
		/* u64 parent_node_object_id */
		node->parent_directory_object_id,
		/* u64 node_number */
		node->node_number,
		/* u16 entry_offset */
		node->entry_offset,
		/* const u8 *key */
		node->key,
		/* u16 key_size */
		node->key_size,
		/* const u8 *value */
		node->record,
		/* u16 value_offset */
		0,
		/* u16 value_size */
		node->record_size,
		/* void *context */
		NULL);
	if(err == -1) {
		/* Manual break code, this one is expected. */
		err = 0;
	}
	else if(err) {
		sys_log_perror(err, "Error while parsing node for listing "
			"extended attributes");
		goto out;
	}
	else {
		/* If there's no break code we should return ENOENT. */
		err = ENOENT;
		goto out;
	}

	if(context.stream_non_resident_id) {
		/* We encountered a non-resident stream. Iterate again to find
		 * its associated stream extents. */
		memset(&visitor, 0, sizeof(visitor));
		visitor.context = &context;
		visitor.node_stream_extent =
			fsapi_node_read_extended_attribute_visit_stream_extent;

		sys_log_debug("Walking the entry a second time to find "
			"non-resident stream data for id %" PRIX64 "...",
			PRAX64(context.stream_non_resident_id));
		err = parse_level3_long_value(
			/* refs_node_crawl_context *crawl_context */
			&crawl_context,
			/* refs_node_walk_visitor *visitor */
			&visitor,
			/* const char *prefix */
			"",
			/* size_t indent */
			1,
			/* u64 node_number */
			node->node_number,
			/* u64 parent_node_object_id */
			node->parent_directory_object_id,
			/* u16 entry_offset */
			node->entry_offset,
			/* const u8 *key */
			node->key,
			/* u16 key_size */
			node->key_size,
			/* const u8 *value */
			node->record,
			/* u16 value_offset */
			0,
			/* u16 value_size */
			node->record_size,
			/* void *context */
			NULL);
		if(err == -1) {
			/* Manual break code, this one is expected. */
			err = 0;
		}
		else if(err) {
			sys_log_perror(err, "Error while listing directory");
			goto out;
		}
		else {
			sys_log_error("Couldn't find stream extent with id "
				"%" PRIu64 " for extended attributes "
				"\"%" PRIbs "\".",
				PRAu64(context.stream_non_resident_id),
				PRAbs(xattr_name_length, xattr_name));
			err = EIO;
			goto out;
		}
	}

	if(out_xattr_size) {
		*out_xattr_size = context.stream_size;
	}
out:
	fsapi_log_leave(err, "vol=%p, node=%p, xattr_name=%p (->%.*s), "
		"xattr_name_length=%" PRIuz ", offset=%" PRIu64 ", "
		"size=%" PRIuz ", iohandler=%p, out_xattr_size=%p "
		"(->%" PRIu64 ")",
		vol, node, xattr_name,
		xattr_name ? (int) sys_min(xattr_name_length, INT_MAX) : 0,
		xattr_name ? xattr_name : "",
		PRAuz(xattr_name_length), PRAu64(offset), PRAuz(size),
		iohandler, out_xattr_size,
		PRAu64(out_xattr_size ? *out_xattr_size : 0));

	return err;
}

int fsapi_node_write_extended_attribute(
		fsapi_volume *vol,
		fsapi_node *node,
		const char *xattr_name,
		size_t xattr_name_length,
		fsapi_node_extended_attribute_flags flags,
		u64 offset,
		size_t size,
		fsapi_iohandler *iohandler)
{
	int err;

	fsapi_log_enter("vol=%p, node=%p, xattr_name=%p (->%.*s), "
		"xattr_name_length=%" PRIuz ", flags=0x%X, offset=%" PRIu64 ", "
		"size=%" PRIuz ", iohandler=%p",
		vol, node, xattr_name,
		xattr_name ? (int) sys_min(xattr_name_length, INT_MAX) : 0,
		xattr_name ? xattr_name : "",
		PRAuz(xattr_name_length), flags, PRAu64(offset), PRAuz(size),
		iohandler);

	(void) vol;
	(void) node;
	(void) xattr_name;
	(void) xattr_name_length;
	(void) flags;
	(void) offset;
	(void) size;
	(void) iohandler;

	err = EROFS;

	fsapi_log_leave(err, "vol=%p, node=%p, xattr_name=%p (->%.*s), "
		"xattr_name_length=%" PRIuz ", flags=0x%X, offset=%" PRIu64 ", "
		"size=%" PRIuz ", iohandler=%p",
		vol, node, xattr_name,
		xattr_name ? (int) sys_min(xattr_name_length, INT_MAX) : 0,
		xattr_name ? xattr_name : "",
		PRAuz(xattr_name_length), flags, PRAu64(offset), PRAuz(size),
		iohandler);

	return err;
}

int fsapi_node_remove_extended_attribute(
		fsapi_volume *vol,
		fsapi_node *node,
		const char *xattr_name,
		size_t xattr_name_length)
{
	int err;

	fsapi_log_enter("vol=%p, node=%p, xattr_name=%p (->%.*s), "
		"xattr_name_length=%" PRIuz,
		vol, node, xattr_name,
		xattr_name ? (int) sys_min(xattr_name_length, INT_MAX) : 0,
		xattr_name ? xattr_name : "",
		PRAuz(xattr_name_length));

	(void) vol;
	(void) node;
	(void) xattr_name;
	(void) xattr_name_length;

	err = EROFS;

	fsapi_log_leave(err, "vol=%p, node=%p, xattr_name=%p (->%.*s), "
		"xattr_name_length=%" PRIuz,
		vol, node, xattr_name,
		xattr_name ? (int) sys_min(xattr_name_length, INT_MAX) : 0,
		xattr_name ? xattr_name : "",
		PRAuz(xattr_name_length));

	return err;
}
