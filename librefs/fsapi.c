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
#include "volume.h"

typedef struct fsapi_volume fsapi_volume;
typedef struct fsapi_node fsapi_node;

static const size_t cached_nodes_max = 1024;

struct fsapi_volume {
	refs_volume *vol;
	fsapi_node *root_node;
	fsapi_refs_xattr_mode xattr_mode;

	struct rb_tree *cache_tree;
	size_t cached_nodes_count;
	fsapi_node *cached_nodes_list;
	struct rb_tree *oid_to_cached_directory_tree;
};

struct fsapi_node {
	u64 refcount;
	char *path;
	size_t path_length;
	u64 parent_directory_object_id;
	u64 directory_object_id;
	sys_bool is_short_entry;
	u8 *key;
	size_t key_size;
	u8 *record;
	size_t record_size;

	fsapi_node *prev;
	fsapi_node *next;
};

static void fsapi_node_init(
		fsapi_node *const node,
		char *const path,
		const size_t path_length,
		const u64 parent_directory_object_id,
		const u64 directory_object_id,
		const sys_bool is_short_entry,
		u8 *const key,
		const size_t key_size,
		u8 *const record,
		const size_t record_size,
		fsapi_node *const prev,
		fsapi_node *const next)
{
	sys_log_trace("%s(node=%p, path=%" PRIbs ", path_length=%" PRIuz ", "
		"parent_directory_object_id=0x%" PRIX64 ", "
		"directory_object_id=0x%" PRIX64 ", is_short_entry=%d, key=%p, "
		"key_size=%" PRIuz ", record=%p, record_size=%" PRIuz ", "
		"prev=%p, next=%p): Entering...",
		__FUNCTION__, node, PRAbs(path_length, path),
		PRAuz(path_length), PRAX64(parent_directory_object_id),
		PRAX64(directory_object_id), is_short_entry, key,
		PRAuz(key_size), record, PRAuz(record_size), prev, next);

	node->refcount = 0;
	node->path = path;
	node->path_length = path_length;
	node->parent_directory_object_id = parent_directory_object_id;
	node->directory_object_id = directory_object_id;
	node->is_short_entry = is_short_entry;
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
	if(node->record) {
		sys_log_debug("Freeing record %p.",
			 node->record);
		sys_free(&node->record);
	}

	if(node->key) {
		sys_log_debug("Freeing key %p.",
			 node->key);
		sys_free(&node->key);
	}

	if(node->path) {
		sys_log_debug("Freeing path %p.", node->path);
		sys_free(&node->path);
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
	sys_free(node);

	return 0;
}

static int fsapi_node_volume_label_entry(
		void *const context,
		const refschar *const volume_label,
		const u16 volume_label_length)
{
	int err = 0;
	char *volume_label_cstr = NULL;
	size_t volume_label_cstr_length = 0;

	(void) context;

	err = sys_unistr_decode(
		volume_label,
		volume_label_length,
		&volume_label_cstr,
		&volume_label_cstr_length);
	if(err) {
		goto out;
	}

	fprintf(stdout, "%" PRIbs "\n",
		PRAbs(volume_label_cstr_length, volume_label_cstr));
	sys_free(&volume_label_cstr);
	err = -1;
out:
	return err;
}

static int fsapi_volume_get_attributes_common(
		refs_volume *const vol,
		fsapi_volume_attributes *const out_attrs)
{
	int err = 0;

	if(out_attrs->requested & FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_SIZE) {
		out_attrs->block_size = vol->cluster_size;
		out_attrs->valid |= FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_SIZE;
	}
	if(out_attrs->requested & FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_COUNT) {
		out_attrs->block_count = vol->cluster_count;
		out_attrs->valid |= FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_COUNT;
	}
	if(out_attrs->requested & FSAPI_VOLUME_ATTRIBUTE_TYPE_FREE_BLOCKS) {
		out_attrs->free_blocks = 0;
		out_attrs->valid |= FSAPI_VOLUME_ATTRIBUTE_TYPE_FREE_BLOCKS;
	}

	if(out_attrs->requested & FSAPI_VOLUME_ATTRIBUTE_TYPE_VOLUME_NAME) {
		refs_node_walk_visitor visitor;
		u64 object_id = 0;

		memset(&visitor, 0, sizeof(visitor));

		visitor.node_volume_label_entry = fsapi_node_volume_label_entry;

		/* Look up node 0x500 where the volume label resides. */
		object_id = 0x500;

		err = refs_node_walk(
			/* sys_device *dev */
			vol->dev,
			/* REFS_BOOT_SECTOR *bs */
			vol->bs,
			/* REFS_SUPERBLOCK_HEADER **sb */
			NULL,
			/* REFS_LEVEL1_NODE **primary_level1_node */
			NULL,
			/* REFS_LEVEL1_NODE **secondary_level1_node */
			NULL,
			/* refs_block_map **block_map */
			NULL,
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
	if(!rb_tree_remove(vol->cache_tree, lru_node)) {
		sys_log_warning("Failed to remove node %p (path: "
			"\"%" PRIbs "\") from tree!",
			lru_node, PRAbs(lru_node->path_length, lru_node->path));
	}

	fsapi_remove_cached_node_from_list(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *cached_node */
		lru_node);
	sys_log_debug("Decrementing cached nodes on evict: %" PRIu64 " -> "
		"%" PRIu64,
		PRAu64(vol->cached_nodes_count),
		PRAu64(vol->cached_nodes_count - 1));
	--vol->cached_nodes_count;
	if(out_evicted_node) {
		*out_evicted_node = lru_node;
		lru_node = NULL; /* Caller takes ownership. */
	}
out:
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
	sys_log_debug("Incrementing cached nodes on put: %" PRIu64 " -> "
		"%" PRIu64,
		PRAu64(vol->cached_nodes_count),
		PRAu64(vol->cached_nodes_count + 1));
	++vol->cached_nodes_count;
out:
	return err;
}

static int fsapi_lookup_by_posix_path_compare(
		struct rb_tree *tree, struct rb_node *a, struct rb_node *b)
{
	const fsapi_node *const a_node = (fsapi_node*) a->value;
	const fsapi_node *const b_node = (fsapi_node*) b->value;

	int res;

	sys_log_trace("Comparing strings \"%.*s\" and \"%.*s\"",
		(int) a_node->path_length, a_node->path,
		(int) b_node->path_length, b_node->path);
	res = strncmp(a_node->path, b_node->path,
		sys_min(a_node->path_length, b_node->path_length));
	if(res) {
		/* A difference was found in the common prefix. Just return
		 * res. */
	}
	else if(a_node->path_length < b_node->path_length) {
		res = -1;
	}
	else if(a_node->path_length > b_node->path_length) {
		res = 1;
	}

	sys_log_trace("Compared strings \"%.*s\" and \"%.*s\": %d",
		(int) a_node->path_length, a_node->path,
		(int) b_node->path_length, b_node->path, res);

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
	const char *full_child_path = NULL;
	size_t full_child_path_length = 0;
	char *full_child_path_alloc = NULL;
	fsapi_node *cached_node = NULL;
	fsapi_node *new_node = NULL;
	u64 start_object_id = 0;
	const char *lookup_path = NULL;
	size_t lookup_path_length = 0;

	if(path_length == 1 && path[0] == '/') {
		*out_node = vol->root_node;
		goto out;
	}

	if(root_node && root_node->directory_object_id != 0x600) {
		size_t i = 0;

		start_object_id = root_node->directory_object_id;

		err = sys_malloc(root_node->path_length +
			((path[0] == '/') ? 0 : 1) + path_length + 1,
			&full_child_path_alloc);
		if(err) {
			goto out;
		}

		memcpy(&full_child_path_alloc[i], root_node->path,
			root_node->path_length);
		i += root_node->path_length;
		if(path[0] != '/') {
			full_child_path_alloc[i++] = '/';
		}
		memcpy(&full_child_path_alloc[i], path, path_length);
		i += path_length;
		full_child_path_alloc[i] = '\0';

		full_child_path = full_child_path_alloc;
		full_child_path_length = i;
	}
	else {
		full_child_path = path;
		full_child_path_length = path_length;
	}

	if(!vol->cache_tree) {
		vol->cache_tree = rb_tree_create(
			/* rb_tree_node_cmp_f cmp */
			fsapi_lookup_by_posix_path_compare);
		if(!vol->cache_tree) {
			err = (err = errno) ? err : ENOMEM;
			goto out;
		}
	}
	else {
		fsapi_node search_node;

		memset(&search_node, 0, sizeof(search_node));
		search_node.path = (char*) full_child_path;
		search_node.path_length = full_child_path_length;

		cached_node = rb_tree_find(
			/* struct rb_tree *self */
			vol->cache_tree,
			/* void *value */
			&search_node);
		if(cached_node) {
			sys_log_debug("Cache hit for path \"%" PRIbs "\": %p%s",
				PRAbs(full_child_path_length, full_child_path),
				cached_node,
				cached_node->parent_directory_object_id ? "" :
				" (negative)");

			if(cached_node->next) {
				/* Put the looked up node at the start of the
				 * list to indicate recent use. */
				fsapi_remove_cached_node_from_list(
					/* fsapi_volume *vol */
					vol,
					/* fsapi_node *cached_node */
					cached_node);
				sys_log_debug("Decrementing cached nodes on "
					"cache hit: %" PRIu64 " -> %" PRIu64,
					PRAu64(vol->cached_nodes_count),
					PRAu64(vol->cached_nodes_count - 1));
				--vol->cached_nodes_count;
			}
		}
		else if(search_node.path_length > 1) {
			/* Check if there's a cache hit for its parent. */
			size_t i;
			fsapi_node *cached_parent_node = NULL;

			for(i = search_node.path_length; i > 0;) {
				if(search_node.path[--i] == '/') {
					break;
				}
			}

			search_node.path_length = i ? i : 1;

			sys_log_debug("Cache miss for path \"%" PRIbs "\". "
				"Attempting to find parent directory "
				"\"%" PRIbs "\" in cache...",
				PRAbs(full_child_path_length, full_child_path),
				PRAbs(search_node.path_length,
				search_node.path));

			cached_parent_node = rb_tree_find(
				/* struct rb_tree *self */
				vol->cache_tree,
				/* void *value */
				&search_node);
			if(cached_parent_node) {
				lookup_path = &full_child_path[i];
				lookup_path_length = path_length - i;
				start_object_id =
					cached_parent_node->directory_object_id;
				sys_log_debug("Cache miss for path "
					"\"%" PRIbs "\" but found parent "
					"directory in cache. Starting lookup "
					"at object ID 0x%" PRIX64 " with "
					"subpath \"%" PRIbs "\"...",
					PRAbs(full_child_path_length,
					full_child_path),
					PRAu64(start_object_id),
					PRAbs(lookup_path_length, lookup_path));

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
					"\"%" PRIbs "\".",
					PRAbs(full_child_path_length,
					full_child_path));
			}
		}
		else {
			sys_log_debug("Cache miss for path \"%" PRIbs "\".",
				PRAbs(full_child_path_length, full_child_path));
		}
	}

	if(!cached_node) {
		char *dup_path = NULL;
		u64 parent_directory_object_id = 0;
		u64 directory_object_id = 0;
		sys_bool is_short_entry = 0;
		u8 *key = NULL;
		size_t key_size = 0;
		u8 *record = NULL;
		size_t record_size = 0;

		if(vol->cached_nodes_count >= cached_nodes_max) {
			/* Reuse the existing node at the tail of the list, i.e.
			 * the one that was used least recently. */

			err = fsapi_node_cache_evict(
				/* fsapi_volume *vol */
				vol,
				/* fsapi_node **out_evicted_node */
				&new_node);
			if(err) {
				goto out;
			}

			sys_log_debug("Reusing node %p for \"%" PRIbs "\" "
				"since we reached the maximum number of cached "
				"nodes (%" PRIuz " >= %" PRIuz ").",
				new_node,
				PRAbs(path_length, path),
				PRAuz(vol->cached_nodes_count + 1),
				PRAuz(cached_nodes_max));

			/* Free resources of existing node and zero the
			 * allocation. */
			fsapi_node_recycle(
				/* fsapi_node *node */
				new_node);
		}
		else {
			sys_log_debug("Allocating new node for \"%s\" since "
				"we are below the maximum number of cached "
				"nodes (%" PRIuz " < %" PRIuz ").",
				path,
				PRAuz(vol->cached_nodes_count),
				PRAuz(cached_nodes_max));

			err = sys_calloc(sizeof(fsapi_node), &new_node);
			if(err) {
				goto out;
			}
		}

		err = refs_volume_lookup_by_posix_path(
			/* refs_volume *vol */
			vol->vol,
			/* const char *path */
			start_object_id ? lookup_path : path,
			/* size_t path_length */
			start_object_id ? lookup_path_length : path_length,
			/* const u64 *start_object_id */
			start_object_id ? &start_object_id :
			(root_node ? &root_node->directory_object_id : NULL),
			/* u64 *out_parent_directory_object_id */
			&parent_directory_object_id,
			/* u64 *out_directory_object_id */
			&directory_object_id,
			/* sys_bool *out_is_short_entry */
			&is_short_entry,
			/* u8 **out_key */
			&key,
			/* size_t *out_key_size */
			&key_size,
			/* u8 **out_record */
			&record,
			/* size_t *out_record_size */
			&record_size);
		if(err) {
			sys_log_perror(errno, "lookup error");
			goto out;
		}
		else if(!parent_directory_object_id) {
			/* Not found. */
			if(out_node) {
				*out_node = NULL;
			}

			goto out;
		}

		err = sys_strndup(path, path_length, &dup_path);
		if(err) {
			sys_log_pdebug(err, "strndup error");
			goto out;
		}

		fsapi_node_init(
			/* fsapi_node *node */
			new_node,
			/* char *path */
			dup_path,
			/* size_t path_length */
			path_length,
			/* u64 parent_directory_object_id */
			parent_directory_object_id,
			/* u64 directory_object_id */
			directory_object_id,
			/* sys_bool is_short_entry */
			is_short_entry,
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
		sys_log_debug("    parent_directory_object_id: %" PRIu64,
			PRAu64(new_node->parent_directory_object_id));
		sys_log_debug("    directory_object_id: %" PRIu64,
			PRAu64(new_node->directory_object_id));
		sys_log_debug("    key: %p", new_node->key);
		sys_log_debug("    key_size: %" PRIuz,
			PRAuz(new_node->key_size));
		sys_log_debug("    record: %p", new_node->record);
		sys_log_debug("    record_size: %" PRIuz,
			PRAuz(new_node->record_size));

		if(!rb_tree_insert(
			/* struct rb_tree *self */
			vol->cache_tree,
			/* void *value */
			new_node))
		{
			sys_log_error("Error inserting looked up entry in "
				"cache");
			err = ENOMEM;
			goto out;
		}

		cached_node = new_node;
		new_node = NULL;
	}

	if(out_node) {
		cached_node->refcount++;
		*out_node = cached_node;
	}
	else {
		fsapi_node_cache_put(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			cached_node);
	}
out:
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
		u32 file_flags,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size)
{
	static const s64 filetime_offset =
		((s64) (369 * 365 + 89)) * 24 * 3600 * 10000000;

	attrs->valid = 0;
	attrs->is_directory = is_directory;

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_MODE) {
		attrs->mode = (is_directory ? S_IFDIR : S_IFREG) | 0777;
		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_MODE;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT) {
		attrs->link_count = is_directory ? 2 /* TODO */ : 1;
		attrs->valid |= FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT;
	}

	if(attrs->requested & FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER) {
		/* st_ino cannot yet be filled in reliably */
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

static int fsapi_node_get_attributes_visit_short_entry(
		void *const context,
		const refschar *const file_name,
		const u16 file_name_length,
		const u32 file_flags,
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
	(void) file_name;
	(void) file_name_length;
	(void) object_id;
	(void) hard_link_id;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	return fsapi_fill_attributes(
		/* fsapi_node_attributes *stbuf */
		(fsapi_node_attributes*) context,
		/* sys_bool is_directory */
		(file_flags & 0x10000000UL) ? SYS_TRUE : SYS_FALSE,
		/* u32 file_flags */
		file_flags & ~((u32) 0x10000000UL),
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

static int fsapi_node_get_attributes_visit_long_entry(
		void *const context,
		const le16 *const file_name,
		const u16 file_name_length,
		const u32 file_flags,
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
		/* fsapi_node_attributes *stbuf */
		(fsapi_node_attributes*) context,
		/* sys_bool is_directory */
		SYS_FALSE,
		/* u32 file_flags */
		file_flags,
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
		void *context,
		u64 hard_link_id,
		u64 parent_id,
		u32 file_flags,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size,
		const u8 *key,
		size_t key_size,
		const u8 *record,
		size_t record_size)
{
	(void) hard_link_id;
	(void) parent_id;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	return fsapi_fill_attributes(
		/* fsapi_node_attributes *stbuf */
		(fsapi_node_attributes*) context,
		/* sys_bool is_directory */
		SYS_FALSE,
		/* u32 file_flags */
		file_flags,
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

static int fsapi_node_get_attributes_common(
		fsapi_volume *vol,
		fsapi_node *node,
		fsapi_node_attributes *attributes)
{
	static const s64 filetime_offset =
		((s64) (369 * 365 + 89)) * 24 * 3600 * 10000000;

	int err = 0;
	refs_node_crawl_context crawl_context;
	refs_node_walk_visitor visitor;

	memset(&visitor, 0, sizeof(visitor));

	crawl_context = refs_volume_init_node_crawl_context(
		/* refs_volume *vol */
		vol->vol);
	visitor.context = attributes;
	if(node->directory_object_id == 0x600) {
		/* Root directory. */
		err = fsapi_fill_attributes(
			/* fsapi_node_attributes *attrs */
		        attributes,
			/* sys_bool is_directory */
			SYS_TRUE,
			/* u32 file_flags */
			REFS_FILE_ATTRIBUTE_SYSTEM |
			REFS_FILE_ATTRIBUTE_DIRECTORY |
			REFS_FILE_ATTRIBUTE_ARCHIVE,
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

		err = parse_level3_long_value(
			/* refs_node_crawl_context *crawl_context */
			&crawl_context,
			/* refs_node_walk_visitor *visitor */
			&visitor,
			/* const char *prefix */
			"",
			/* size_t indent */
			1,
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
out:
	sys_log_debug("%s(node=%p, attributes=%p): %d (%s)",
		__FUNCTION__, node, attributes, err, strerror(err));

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

			sys_free(&buf);
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
	refs_volume *rvol = NULL;

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

	err = refs_volume_create(
		/* sys_device *dev */
		dev,
		/* refs_volume **out_vol */
		&rvol);
	if(err) {
		sys_log_perror(err, "Error while mounting volume");
		goto out;
	}

	if(out_attrs) {
		err = fsapi_volume_get_attributes_common(
			/* refs_volume *vol */
			rvol,
			/* fsapi_volume_attributes *out_attrs */
			out_attrs);
		if(err) {
			sys_log_perror(err, "Error while getting attributes "
				"for mounted volume");
			goto out;
		}
	}

	fsapi_node_init(
		/* fsapi_node *node */
		root_node,
		/* char *path */
		NULL,
		/* size_t path_length */
		0,
		/* u64 parent_directory_object_id */
		0x500, /* ? */
		/* u64 directory_object_id */
		0x600,
		/* sys_bool is_short_entry */
		SYS_TRUE, /* Technically no entry, maybe? */
		/* u8 *key */
		NULL,
		/* size_t key_size */
		0,
		/* u8 *record */
		NULL,
		/* size_t record_size */
		0,
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

		if(root_node) {
			sys_free(&root_node);
		}

		if(vol) {
			sys_free(&vol);
		}
	}
	return err;
}

int fsapi_volume_get_attributes(
		fsapi_volume *vol,
		fsapi_volume_attributes *out_attrs)
{
	int err = 0;

	err = fsapi_volume_get_attributes_common(
		/* refs_volume *vol */
		vol->vol,
		/* fsapi_volume_attributes *out_attrs */
		out_attrs);

	return err;
}

static void fsapi_volume_unmount_cache_tree_entry_destroy(
		struct rb_tree *self,
		struct rb_node *_node)
{
	fsapi_node *node = (fsapi_node*) _node->value;

	sys_log_warning("Destroying node %p (\"%" PRIbs "\") with %" PRIu64 " "
		"remaining references...",
		node, PRAbs(node->path_length, node->path),
		PRAu64(node->refcount));

	fsapi_node_destroy(
		/* fsapi_node *cached_node */
		&node);
}

int fsapi_volume_unmount(
		fsapi_volume **vol)
{
	if((*vol)->cached_nodes_list) {
		/* Iterate over cached nodes and free all resources. */
		fsapi_node *cur_node = (*vol)->cached_nodes_list;
		do {
			fsapi_node *next_node = cur_node->next;

			rb_tree_remove((*vol)->cache_tree, cur_node);

			fsapi_node_destroy(
				/* fsapi_node *cached_node */
				&cur_node);

			cur_node = next_node;
		} while(cur_node != (*vol)->cached_nodes_list);

		(*vol)->cached_nodes_count = 0;
		(*vol)->cached_nodes_list = NULL;
	}

	if((*vol)->cache_tree) {
		rb_tree_dealloc((*vol)->cache_tree,
			fsapi_volume_unmount_cache_tree_entry_destroy);
	}

	refs_volume_destroy(
		/* refs_volume **out_vol */
		&(*vol)->vol);

	sys_free(&(*vol)->root_node);
	sys_free(vol);

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

	if(child_node && out_attributes) {
		err = fsapi_node_get_attributes_common(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			child_node,
			/* fsapi_node_attributes *attributes */
			out_attributes);
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
			&child_node);
		if(release_err) {
			sys_log_perror(release_err, "Error while releasing "
				"node on cleanup");
			err = err ? err : release_err;
		}
	}

	return err;
}

int fsapi_node_release(
		fsapi_volume *vol,
		fsapi_node **node)
{
	int err = 0;

	if((*node) == vol->root_node) {
		/* Root node is not refcounted. It exists until the mount is
		 * torn down. */
		*node = NULL;
		goto out;
	}

	if(!(*node)->refcount) {
		sys_log_critical("Attempted to release node with 0 refcount!");
		err = EINVAL;
		goto out;
	}

	(*node)->refcount--;
	if(!(*node)->refcount) {
		fsapi_node_cache_put(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			*node);
	}
	*node = NULL;
out:
	return err;
}

typedef struct {
	fsapi_node_attributes *attributes;
	void *handle_dirent_context;
	int (*handle_dirent)(
		void *context,
		const char *name,
		size_t name_length,
		fsapi_node_attributes *attributes);
} fsapi_readdir_context;

static int fsapi_node_list_filldir(
		fsapi_readdir_context *context,
		const refschar *file_name,
		u16 file_name_length,
		sys_bool is_directory,
		u32 file_flags,
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

	if(context->attributes) {
		err = fsapi_fill_attributes(
			/* fsapi_node_attributes *attrs */
			context->attributes,
			/* sys_bool is_directory */
			is_directory,
			/* u32 file_flags */
			file_flags,
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

	err = context->handle_dirent(
		/* void *context */
		context->handle_dirent_context,
		/* const char *name */
		cname,
		/* size_t name_length */
		cname_length,
		/* fsapi_node_attributes *attributes */
		context->attributes);
out:
	if(cname) {
		sys_free(&cname);
	}

	return err;
}

static int fsapi_node_list_visit_short_entry(
		void *const context,
		const refschar *const file_name,
		const u16 file_name_length,
		const u32 file_flags,
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
	(void) object_id;
	(void) hard_link_id;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	return fsapi_node_list_filldir(
		/* fsapi_readdir_context *context */
		(fsapi_readdir_context*) context,
		/* const refschar *file_name */
		file_name,
		/* u16 file_name_length */
		file_name_length,
		/* sys_bool is_directory */
		SYS_TRUE,
		/* u32 file_flags */
		file_flags,
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

static int fsapi_node_list_visit_long_entry(
		void *const context,
		const le16 *const file_name,
		const u16 file_name_length,
		const u32 file_flags,
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
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	return fsapi_node_list_filldir(
		/* fsapi_readdir_context *context */
		(fsapi_readdir_context*) context,
		/* const refschar *file_name */
		file_name,
		/* u16 file_name_length */
		file_name_length,
		/* sys_bool is_directory */
		SYS_FALSE,
		/* u32 file_flags */
		file_flags,
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

	if(!directory_node->directory_object_id) {
		err = ENOTDIR;
		goto out;
	}

	readdir_context.attributes = attributes;
	readdir_context.handle_dirent_context = context;
	readdir_context.handle_dirent = handle_dirent;
	visitor.context = &readdir_context;
	visitor.node_long_entry = fsapi_node_list_visit_long_entry;
	visitor.node_short_entry = fsapi_node_list_visit_short_entry;

	err = refs_node_walk(
		/* sys_device *dev */
		vol->vol->dev,
		/* REFS_BOOT_SECTOR *bs */
		vol->vol->bs,
		/* REFS_SUPERBLOCK_HEADER **sb */
		&vol->vol->sb,
		/* REFS_LEVEL1_NODE **primary_level1_node */
		&vol->vol->primary_level1_node,
		/* REFS_LEVEL1_NODE **secondary_level1_node */
		&vol->vol->secondary_level1_node,
		/* refs_block_map **block_map */
		&vol->vol->block_map,
		/* const u64 *start_node */
		NULL,
		/* const u64 *object_id */
		&directory_node->directory_object_id,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err) {
		sys_log_perror(err, "Error while listing directory");
		goto out;
	}
out:
	return err;
}

int fsapi_node_get_attributes(
		fsapi_volume *vol,
		fsapi_node *node,
		fsapi_node_attributes *out_attributes)
{
	int err;

	err = fsapi_node_get_attributes_common(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* fsapi_node_attributes *attributes */
		out_attributes);

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
	return err;
}

typedef struct {
	refs_volume *vol;
	fsapi_iohandler *iohandler;
	size_t size;
	u64 cur_offset;
	u64 start_offset;
} fsapi_node_read_context;

static int fsapi_node_read_visit_file_extent(
		void *const _context,
		const u64 first_block,
		const u64 block_count,
		const u32 block_index_unit)
{
	fsapi_node_read_context *const context =
		(fsapi_node_read_context*) _context;
	const u64 extent_size = block_count * block_index_unit;

	int err = 0;
	size_t copy_offset_in_buffer = 0;
	u64 remaining_bytes = 0;
	u64 valid_extent_size = 0;
	u64 cur_pos = 0;
	u64 bytes_remaining = 0;
	size_t bytes_to_read = 0;

	sys_log_debug("Visiting file extent: %" PRIu64 " - %" PRIu64 " "
		"(%" PRIu64 " blocks) Position (current): %" PRIu64 " Position "
		"(start): %" PRIu64 " Remaining size: %" PRIuz,
		PRAu64(first_block), PRAu64(first_block + block_count - 1),
		PRAu64(block_count), PRAu64(context->cur_offset),
		PRAu64(context->start_offset), PRAuz(context->size));

	if(context->cur_offset + extent_size <= context->start_offset) {
		sys_log_debug("Skipping extent that precedes the start offset "
			"of the read: %" PRIu64 " <= %" PRIu64,
			PRAu64(context->cur_offset + extent_size),
			PRAu64(context->start_offset));
		context->cur_offset += extent_size;
		goto out;
	}

	copy_offset_in_buffer =
		((context->cur_offset < context->start_offset) ?
		context->start_offset - context->cur_offset : 0);
	remaining_bytes = copy_offset_in_buffer + context->size;
	valid_extent_size = sys_min(extent_size, remaining_bytes);
	valid_extent_size =
		/* Round up to the nearest sector boundary (this assumes that
		 * sector size is a power of 2!). */
		(valid_extent_size + (context->vol->sector_size - 1)) &
		~((u64) (context->vol->sector_size - 1));
	cur_pos = first_block * block_index_unit;
	bytes_remaining = valid_extent_size;
	bytes_to_read = (size_t) sys_min(bytes_remaining, context->size);

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

	if(context->start_offset >= size) {
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
	sys_bool is_short_entry = SYS_FALSE;
	fsapi_node_read_context context;
	refs_node_crawl_context crawl_context;
	refs_node_walk_visitor visitor;

	memset(&context, 0, sizeof(context));
	memset(&visitor, 0, sizeof(visitor));

	sys_log_trace("%s(vol=%p, node=%p, offset=%" PRIu64 ", "
		"size=%" PRIuz ", iohandler=%p): Entering...",
		__FUNCTION__, vol, node, PRAu64(offset), PRAuz(size),
		iohandler);

	context.vol = vol->vol;
	context.iohandler = iohandler;
	context.size = size;
	context.cur_offset = 0;
	context.start_offset = offset;

	if(is_short_entry) {
		/* Don't know how to find extents for short entries yet. These
		 * may be hard links and might need resolving in other ways. */
		goto out;
	}

	crawl_context = refs_volume_init_node_crawl_context(
		/* refs_volume *vol */
		vol->vol);
	visitor.context = &context;
	visitor.node_file_extent = fsapi_node_read_visit_file_extent;
	visitor.node_file_data = fsapi_node_read_visit_file_data;

	err = parse_level3_long_value(
		/* refs_node_crawl_context *crawl_context */
		&crawl_context,
		/* refs_node_walk_visitor *visitor */
		&visitor,
		/* const char *prefix */
		"",
		/* size_t indent */
		1,
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
out:
	sys_log_ptrace(err, "%s(vol=%p, node=%p, offset=%" PRIu64 ", "
		"size=%" PRIuz ", iohandler=%p): Leaving with",
		__FUNCTION__, vol, node, PRAu64(offset), PRAuz(size),
		iohandler);
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
	context->remaining_bytes = data_size;

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

	if(data_reference->resident) {
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
		const u64 first_block,
		const u32 block_index_unit,
		const u32 cluster_count)
{
	fsapi_node_read_extended_attribute_context *const context =
		(fsapi_node_read_extended_attribute_context*) _context;
	const u64 read_offset = first_block * block_index_unit;
	const u64 extent_size = cluster_count * context->vol->cluster_size;
	const u64 valid_extent_size =
		sys_min(extent_size, context->remaining_bytes);

	int err = 0;

	sys_log_debug("Got stream extent with stream id 0x%" PRIX64 ", first "
		"block 0x%" PRIX64 "...",
		PRAX64(stream_id), PRAX64(first_block));

	if(stream_id != context->stream_non_resident_id) {
		/* Not the stream that we are looking for. */
		goto out;
	}

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
		fsapi_iohandler *iohandler)
{
	int err = 0;

	fsapi_node_read_extended_attribute_context context;
	refs_node_crawl_context crawl_context;
	refs_node_walk_visitor visitor;

	memset(&context, 0, sizeof(context));
	memset(&crawl_context, 0, sizeof(crawl_context));
	memset(&visitor, 0, sizeof(visitor));

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
out:
	return err;
}
