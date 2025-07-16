/*-
 * refs-fuse.c - FUSE driver interface to librefs.
 *
 * Copyright (c) 2022-2025 Erik Larsson
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

/* Headers - Autoconf-generated config.h, if present. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if _WIN32
/* Fix for incompatible mode_t typedefs in mingw-w64 and Visual Studio. */
#define _MODE_T_
typedef unsigned int mode_t;
#endif

/* Headers - libfuse. */
#define FUSE_USE_VERSION 26
#if defined(__NetBSD__)
/* Work around librefuse compile error due to missing kernel types. */
#define _KERNTYPES 1
#endif
#include <fuse.h>

/* Headers - librefs. */
#include "node.h"
#include "sys.h"
#include "volume.h"

#ifndef FUSE_STAT
/* The FUSE_STAT declaration is Dokan-specific, so for non-Dokan builds we
 * simply define it to 'stat'. */
#define FUSE_STAT stat
#endif

#include "rb_tree.h"

typedef struct refs_fuse_node refs_fuse_node;

struct refs_fuse_node {
	char *path;
	size_t path_length;
	u64 parent_directory_object_id;
	u64 directory_object_id;
	sys_bool is_short_entry;
	u8 *record;
	size_t record_size;

	refs_fuse_node *prev;
	refs_fuse_node *next;
};

static struct rb_tree *cache_tree = NULL;
static size_t cached_nodes_count = 0;
static const size_t cached_nodes_max = 1024;
static refs_fuse_node *cached_nodes_list = NULL;

static void refs_fuse_add_cached_node_to_list(
		refs_fuse_node *const cached_node)
{
	cached_node->next =
		cached_nodes_list ? cached_nodes_list : cached_node;
	cached_node->prev =
		cached_nodes_list ? cached_nodes_list->prev : cached_node;
	if(cached_nodes_list) {
		cached_nodes_list->prev->next = cached_node;
		cached_nodes_list->prev = cached_node;
	}

	cached_nodes_list = cached_node;
}

static void refs_fuse_remove_cached_node_from_list(
		refs_fuse_node *const cached_node)
{
	/* Detach from the list. */
	if(cached_node == cached_node->next) {
		cached_nodes_list = NULL;
	}
	else {
		cached_node->next->prev = cached_node->prev;
		cached_node->prev->next = cached_node->next;

		/* If we're removing the head of the list, replace the head of
		 * the list with the next item. */
		if(cached_node == cached_nodes_list) {
			cached_nodes_list = cached_node->next;
		}
	}

	cached_node->next = NULL;
	cached_node->prev = NULL;
}

static int refs_fuse_lookup_by_posix_path_compare(
		struct rb_tree *tree, struct rb_node *a, struct rb_node *b)
{
	const refs_fuse_node *const a_node = (refs_fuse_node*) a->value;
	const refs_fuse_node *const b_node = (refs_fuse_node*) b->value;

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

static int refs_fuse_lookup_by_posix_path(
		refs_volume *vol,
		const char *path,
		u64 *out_parent_directory_object_id,
		u64 *out_directory_object_id,
		sys_bool *out_is_short_entry,
		const u8 **out_record,
		size_t *out_record_size)
{
	const size_t path_length = strlen(path);

	int err = 0;
	refs_fuse_node *cached_node = NULL;
	refs_fuse_node *new_node = NULL;
	u64 start_object_id = 0;
	const char *lookup_path = NULL;

	if(!cache_tree) {
		cache_tree = rb_tree_create(
			/* rb_tree_node_cmp_f cmp */
			refs_fuse_lookup_by_posix_path_compare);
	}
	else {
		refs_fuse_node search_node;

		memset(&search_node, 0, sizeof(search_node));
		search_node.path = (char*) path;
		search_node.path_length = path_length;

		cached_node = rb_tree_find(
			/* struct rb_tree *self */
			cache_tree,
			/* void *value */
			&search_node);
		if(cached_node) {
			sys_log_debug("Cache hit for path \"%s\": %p%s",
				path, cached_node,
				cached_node->parent_directory_object_id ? "" :
				" (negative)");

			/* Put the looked up node at the start of the list to
			 * indicate recent use. */
			refs_fuse_remove_cached_node_from_list(
				/* refs_fuse_node *cached_node */
				cached_node);
			refs_fuse_add_cached_node_to_list(
				/* refs_fuse_node *cached_node */
				cached_node);
		}
		else if(search_node.path_length > 1) {
			/* Check if there's a cache hit for its parent. */
			refs_fuse_node *cached_parent_node = NULL;
			size_t i;

			for(i = search_node.path_length; i > 0;) {
				if(search_node.path[--i] == '/') {
					break;
				}
			}

			search_node.path_length = i ? i : 1;

			sys_log_debug("Cache miss for path \"%s\". Attempting "
				"to find parent directory \"%.*s\" in cache...",
				path,
				(int) search_node.path_length,
				search_node.path);

			cached_parent_node = rb_tree_find(
				/* struct rb_tree *self */
				cache_tree,
				/* void *value */
				&search_node);
			if(cached_parent_node) {
				lookup_path = &path[i];
				start_object_id =
					cached_parent_node->directory_object_id;
				sys_log_debug("Cache miss for path \"%s\" but "
					"found parent directory in cache. "
					"Starting lookup at object ID "
					"0x%" PRIX64 " with subpath \"%s\"...",
					path,
					PRAu64(start_object_id),
					lookup_path);

				/* Put the looked up cached parent node at the
				 * start of the list to indicate recent use. */
				refs_fuse_remove_cached_node_from_list(
					/* refs_fuse_node *cached_node */
					cached_parent_node);
				refs_fuse_add_cached_node_to_list(
					/* refs_fuse_node *cached_node */
					cached_parent_node);
			}
			else {
				sys_log_debug("Cache miss for path \"%s\".",
					path);
			}
		}
		else {
			sys_log_debug("Cache miss for path \"%s\".",
				path);
		}
	}

	if(!cached_node) {
		if(cached_nodes_count >= cached_nodes_max) {
			/* Reuse the existing node at the tail of the list, i.e.
			 * the one that was used least recently. */
			new_node = cached_nodes_list->prev;

			sys_log_debug("Reusing node %p for \"%s\" since we "
				"reached the maximum number of cached nodes "
				"(%" PRIuz " >= %" PRIuz ").",
				new_node,
				path,
				PRAuz(cached_nodes_count),
				PRAuz(cached_nodes_max));

			/* Remove node from search tree. */
			if(!rb_tree_remove(cache_tree, new_node)) {
				sys_log_debug("Failed to remove node %p "
					"(path: \"%s\") from tree!",
					new_node, new_node->path);
			}

			refs_fuse_remove_cached_node_from_list(
				/* refs_fuse_node *cached_node */
				new_node);
			--cached_nodes_count;

			/* Free resources of existing node and zero the
			 * allocation. */
			if(new_node->record) {
				sys_log_debug("Freeing record %p.",
					 new_node->record);
				sys_free(&new_node->record);
			}
			sys_log_debug("Freeing path %p.", new_node->path);
			sys_free(&new_node->path);
			memset(new_node, 0, sizeof(*new_node));
		}
		else {
			sys_log_debug("Allocating new node for \"%s\" since "
				"we are below the maximum number of cached "
				"nodes (%" PRIuz " < %" PRIuz ").",
				path,
				PRAuz(cached_nodes_count),
				PRAuz(cached_nodes_max));

			err = sys_calloc(sizeof(refs_fuse_node), &new_node);
			if(err) {
				goto out;
			}
		}

		new_node->path = strdup(path);
		if(!new_node->path) {
			err = (err = errno) ? err : ENOMEM;
			sys_log_perror(errno, "strdup error");
			goto out;
		}

		new_node->path_length = path_length;

		err = refs_volume_lookup_by_posix_path(
			/* refs_volume *vol */
			vol,
			/* const char *path */
			start_object_id ? lookup_path : path,
			/* const u64 *start_object_id */
			start_object_id ? &start_object_id : NULL,
			/* u64 *out_parent_directory_object_id */
			&new_node->parent_directory_object_id,
			/* u64 *out_directory_object_id */
			&new_node->directory_object_id,
			/* sys_bool *out_is_short_entry */
			&new_node->is_short_entry,
			/* u8 **out_record */
			&new_node->record,
			/* size_t *out_record_size */
			&new_node->record_size);
		if(err) {
			sys_log_perror(errno, "lookup error");
			goto out;
		}

		sys_log_debug("Lookup result:");
		sys_log_debug("    parent_directory_object_id: %" PRIu64,
			PRAu64(new_node->parent_directory_object_id));
		sys_log_debug("    directory_object_id: %" PRIu64,
			PRAu64(new_node->directory_object_id));
		sys_log_debug("    record: %p", new_node->record);
		sys_log_debug("    record_size: %" PRIuz,
			PRAuz(new_node->record_size));

		if(!rb_tree_insert(
			/* struct rb_tree *self */
			cache_tree,
			/* void *value */
			new_node))
		{
			sys_log_error("insert error");
			err = ENOMEM;
			goto out;
		}

		/* Insert cached node as the head of the MRU list. */
		refs_fuse_add_cached_node_to_list(
			/* refs_fuse_node *cached_node */
			new_node);
		++cached_nodes_count;

		cached_node = new_node;
		new_node = NULL;
	}

	if(out_parent_directory_object_id) {
		*out_parent_directory_object_id =
			cached_node->parent_directory_object_id;
	}
	if(out_directory_object_id) {
		*out_directory_object_id = cached_node->directory_object_id;
	}
	if(out_is_short_entry) {
		*out_is_short_entry = cached_node->is_short_entry;
	}
	if(out_record) {
		*out_record = cached_node->record;
	}
	if(out_record_size) {
		*out_record_size = cached_node->record_size;
	}
out:
	if(new_node) {
		if(new_node->record) {
			sys_free(&new_node->record);
		}

		if(new_node->path) {
			sys_free(&new_node->path);
		}

		sys_free(&new_node);
	}

	return err;
}

static int refs_fuse_fill_stat(
		struct FUSE_STAT *stbuf,
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

	memset(stbuf, 0, sizeof(*stbuf));

	stbuf->st_mode = (is_directory ? S_IFDIR : S_IFREG) | 0777;
	stbuf->st_nlink = is_directory ? 2 /* TODO */ : 1;
	/* st_ino cannot yet be filled in reliably */
#ifdef __APPLE__
	stbuf->st_uid = 99;
	stbuf->st_gid = 99;

#define st_atim st_atimespec
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#endif
	stbuf->st_atim.tv_sec =
		(last_access_time - filetime_offset) / 10000000;
	stbuf->st_atim.tv_nsec =
		(last_access_time - filetime_offset) % 10000000;
	stbuf->st_mtim.tv_sec =
		(last_write_time - filetime_offset) / 10000000;
	stbuf->st_mtim.tv_nsec =
		(last_write_time - filetime_offset) % 10000000;
	stbuf->st_ctim.tv_sec =
		(last_mft_change_time - filetime_offset) / 10000000;
	stbuf->st_ctim.tv_nsec =
		(last_mft_change_time - filetime_offset) % 10000000;
#ifdef __APPLE__
	stbuf->st_birthtimespec.tv_sec =
		(create_time - filetime_offset) / 10000000;
	stbuf->st_birthtimespec.tv_nsec =
		(create_time - filetime_offset) % 10000000;
#else
	(void) create_time;
#endif
	stbuf->st_size = file_size;
	stbuf->st_blocks = allocated_size / 512;
#ifdef __APPLE__
	if(file_flags & REFS_FILE_ATTRIBUTE_READONLY) {
		stbuf->st_flags |= UF_IMMUTABLE;
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_HIDDEN) {
		stbuf->st_flags |= UF_HIDDEN;
	}
	if(!(file_flags & REFS_FILE_ATTRIBUTE_ARCHIVE)) {
		stbuf->st_flags |= SF_ARCHIVED;
	}
#else
	(void) file_flags;
#endif

	return 0;
}

typedef struct {
	void *dirbuf;
	fuse_fill_dir_t filler;
} refs_fuse_readdir_context;

static int refs_fuse_filldir(
		refs_fuse_readdir_context *context,
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
	struct FUSE_STAT stbuf;
	char *cname = NULL;
	size_t cname_length = 0;

	err = refs_fuse_fill_stat(
		/* struct FUSE_STAT *stbuf */
		&stbuf,
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
		fprintf(stderr, "Error: Failed to decode filename string.\n");
		goto out;
	}

	if(context->filler(
		/* void *buf */
		context->dirbuf,
		/* const char *name */
		cname,
		/* const struct FUSE_STAT *stbuf */
		&stbuf,
		/* off_t off */
		0))
	{
		err = -1;
	}
out:
	if(cname) {
		sys_free(&cname);
	}

	return err;
}

static int refs_fuse_op_getattr_visit_short_entry(
		void *context,
		const refschar *file_name,
		u16 file_name_length,
		u32 file_flags,
		u64 object_id,
		u64 hard_link_id,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size,
		const u8 *record,
		size_t record_size)
{
	(void) file_name;
	(void) file_name_length;
	(void) object_id;
	(void) hard_link_id;
	(void) record;
	(void) record_size;

	return refs_fuse_fill_stat(
		/* struct stat *stbuf */
		(struct FUSE_STAT*) context,
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

static int refs_fuse_op_getattr_visit_long_entry(
		void *context,
		const le16 *file_name,
		u16 file_name_length,
		u32 file_flags,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size,
		const u8 *record,
		size_t record_size)
{
	(void) file_name;
	(void) file_name_length;
	(void) record;
	(void) record_size;

	return refs_fuse_fill_stat(
		/* struct stat *stbuf */
		(struct FUSE_STAT*) context,
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

static int refs_fuse_op_getattr(const char *path, struct FUSE_STAT *stbuf)
{
	static const s64 filetime_offset =
		((s64) (369 * 365 + 89)) * 24 * 3600 * 10000000;

	refs_volume *const vol =
		(refs_volume*) fuse_get_context()->private_data;
	int err = 0;
	sys_bool is_short_entry = SYS_FALSE;
	const u8 *record = NULL;
	size_t record_size = 0;
	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;
	refs_node_crawl_context crawl_context;
	refs_node_walk_visitor visitor;

	memset(&visitor, 0, sizeof(visitor));

	sys_log_debug("%s(path=\"%s\", stbuf=%p)",
		__FUNCTION__, path, stbuf);

	err = refs_fuse_lookup_by_posix_path(
		/* refs_volume *vol */
		vol,
		/* const char *path */
		path,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* sys_bool *out_is_short_entry */
		&is_short_entry,
		/* const u8 **out_record */
		&record,
		/* size_t *out_record_size */
		&record_size);
	if(err) {
		sys_log_perror(err, "Error during lookup");
		goto out;
	}
	else if(!parent_directory_object_id) {
		err = ENOENT;
		goto out;
	}

	crawl_context = refs_volume_init_node_crawl_context(
		/* refs_volume *vol */
		vol);
	visitor.context = stbuf;
	if(!record && directory_object_id) {
		/* Root directory. */
		err = refs_fuse_fill_stat(
			/* struct stat *stbuf */
		        stbuf,
			/* sys_bool is_directory */
			SYS_TRUE,
			/* u32 file_flags */
			0,
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
	else if(is_short_entry) {
		visitor.node_short_entry =
			refs_fuse_op_getattr_visit_short_entry;
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
			NULL,
			/* u16 key_size */
			0,
			/* const u8 *value */
			record,
			/* u16 value_offset */
			0,
			/* u16 value_size */
			record_size,
			/* void *context */
			NULL);
	}
	else {
		visitor.node_long_entry =
			refs_fuse_op_getattr_visit_long_entry;
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
			NULL,
			/* u16 key_size */
			0,
			/* const u8 *value */
			record,
			/* u16 value_offset */
			0,
			/* u16 value_size */
			record_size,
			/* void *context */
			NULL);
	}
out:
	sys_log_debug("%s(path=\"%s\", stbuf=%p): %d (%s)",
		__FUNCTION__, path, stbuf, -err, strerror(err));

	return -err;
}

static int refs_fuse_op_open(const char *path, struct fuse_file_info *fi)
{
	refs_volume *const vol =
		(refs_volume*) fuse_get_context()->private_data;
	int err = 0;
	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;

	sys_log_debug("%s(path=\"%s\", fi=%p)",
		__FUNCTION__, path, fi);

	err = refs_fuse_lookup_by_posix_path(
		/* refs_volume *vol */
		vol,
		/* const char *path */
		path,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* sys_bool *out_is_short_entry */
		NULL,
		/* const u8 **out_record */
		NULL,
		/* size_t *out_record_size */
		NULL);
	if(err) {
		goto out;
	}
	else if(!parent_directory_object_id) {
		err = ENOENT;
		goto out;
	}
	else if(directory_object_id) {
		err = EISDIR;
		goto out;
	}
out:
	sys_log_debug("%s(path=\"%s\", fi=%p): %d (%s)",
		__FUNCTION__, path, fi, -err, strerror(err));

	return -err;
}

typedef struct {
	refs_volume *vol;
	char *buf;
	size_t size;
	off_t cur_offset;
	off_t start_offset;
} refs_fuse_op_read_context;

static int refs_fuse_op_read_visit_file_extent(
		void *const _context,
		const u64 first_block,
		const u64 block_count,
		const u32 block_index_unit)
{
	refs_fuse_op_read_context *const context =
		(refs_fuse_op_read_context*) _context;
	const u64 extent_size = block_count * block_index_unit;

	int err = 0;
	char *buf = NULL;
	u64 remaining_bytes = 0;
	u64 valid_extent_size = 0;
	u64 cur_pos = 0;
	u64 bytes_remaining = 0;
	size_t buf_size = 0;
	size_t copy_offset_in_buffer = 0;

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
	buf_size = (size_t) sys_min(valid_extent_size, 1024UL * 1024U);

	err = sys_malloc(buf_size, &buf);
	if(err) {
		sys_log_perror(err, "Error while allocating temporary "
			"buffer for printing data");
		goto out;
	}

	while(bytes_remaining) {
		const size_t bytes_to_read =
			(size_t) sys_min(bytes_remaining, buf_size);

		err = sys_device_pread(
			/* sys_device *dev */
			context->vol->dev,
			/* u64 pos */
			cur_pos,
			/* size_t count */
			bytes_to_read,
			/* void *b */
			buf);
		if(err) {
			sys_log_perror(err, "Error while reading data from "
				"device offset %" PRIu64,
				PRAu64(cur_pos));
			goto out;
		}

		if(!copy_offset_in_buffer) {
			const size_t bytes_to_copy =
				sys_min(context->size, buf_size);

			sys_log_debug("Copying %" PRIuz " bytes without "
				"offset...",
				PRAuz(bytes_to_copy));
			memcpy(context->buf, buf, bytes_to_copy);
			context->size -= bytes_to_copy;
			context->buf = &context->buf[bytes_to_copy];
		}
		else if(bytes_to_read <= copy_offset_in_buffer) {
			/* We have not yet reached the start of the copy. */
			sys_log_debug("Skipping region preceding the offset: "
				"%" PRIuz " <= %" PRIuz,
				PRAuz(bytes_to_read),
				PRAuz(copy_offset_in_buffer));
			copy_offset_in_buffer -= bytes_to_read;
		}
		else {
			/* Partial copy. */
			const size_t buf_copy_size =
				buf_size - copy_offset_in_buffer;
			const size_t bytes_to_copy =
				sys_min(context->size, buf_copy_size);

			sys_log_debug("Copying %" PRIuz " bytes with offset "
				"%" PRIuz "...",
				PRAuz(bytes_to_copy),
				PRAuz(copy_offset_in_buffer));
			memcpy(context->buf,
				&buf[copy_offset_in_buffer],
				bytes_to_copy);
			context->size -= bytes_to_copy;
			context->buf = &context->buf[bytes_to_copy];
			copy_offset_in_buffer = 0;
		}

		if(bytes_remaining == bytes_to_read) {
			break;
		}

		cur_pos += bytes_to_read;
		bytes_remaining -= bytes_to_read;
	}
out:
	if(buf) {
		sys_free(&buf);
	}

	return err;
}

static int refs_fuse_op_read_visit_file_data(
		void *const _context,
		const void *const data,
		const size_t size)
{
	refs_fuse_op_read_context *const context =
		(refs_fuse_op_read_context*) _context;

	int err = 0;
	size_t bytes_to_copy = 0;

	if(context->start_offset >= size) {
		context->cur_offset = size;
		goto out;
	}

	bytes_to_copy =
		sys_min(context->size, size - (size_t) context->start_offset);
	memcpy(context->buf,
		&((const char*) data)[(size_t) context->start_offset],
		bytes_to_copy);
	context->size -= bytes_to_copy;
	context->cur_offset = context->start_offset + bytes_to_copy;
	context->buf = &context->buf[bytes_to_copy];
out:
	return err;
}

static int refs_fuse_op_read(const char *path, char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	refs_volume *const vol =
		(refs_volume*) fuse_get_context()->private_data;
	int err = 0;
	sys_bool is_short_entry = SYS_FALSE;
	const u8 *record = NULL;
	size_t record_size = 0;
	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;
	refs_fuse_op_read_context context;
	refs_node_crawl_context crawl_context;
	refs_node_walk_visitor visitor;

	memset(&context, 0, sizeof(context));
	memset(&visitor, 0, sizeof(visitor));

	sys_log_debug("%s(path=\"%s\", buf=%p, size=%" PRIuz ", "
		"offset=%" PRId64 ", fi=%p)",
		__FUNCTION__, path, buf, PRAuz(size), PRAd64(offset), fi);

	err = refs_fuse_lookup_by_posix_path(
		/* refs_volume *vol */
		vol,
		/* const char *path */
		path,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* sys_bool *out_is_short_entry */
		&is_short_entry,
		/* const u8 **out_record */
		&record,
		/* size_t *out_record_size */
		&record_size);
	if(err) {
		goto out;
	}
	else if(!parent_directory_object_id) {
		err = ENOENT;
		goto out;
	}
	else if(directory_object_id) {
		err = EISDIR;
		goto out;
	}

	context.vol = vol;
	context.buf = buf;
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
		vol);
	visitor.context = &context;
	visitor.node_file_extent = refs_fuse_op_read_visit_file_extent;
	visitor.node_file_data = refs_fuse_op_read_visit_file_data;

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
		NULL,
		/* u16 key_size */
		0,
		/* const u8 *value */
		record,
		/* u16 value_offset */
		0,
		/* u16 value_size */
		record_size,
		/* void *context */
		NULL);
out:
	sys_log_debug("%s(path=\"%s\", buf=%p, size=%" PRIuz ", "
		"offset=%" PRId64 ", fi=%p): %" PRIdz " (%s)",
		__FUNCTION__, path, buf, PRAuz(size), PRAd64(offset), fi,
		PRAdz(err ? -err : (size - context.size)), strerror(err));

	return err ? -err : (size - context.size);
}

static int refs_fuse_op_statfs(const char *path, struct statvfs *stvbuf)
{
	int err = 0;

	sys_log_debug("%s(path=\"%s\", stvbuf=%p)",
		__FUNCTION__, path, stvbuf);

	memset(stvbuf, 0, sizeof(*stvbuf));

	sys_log_debug("%s(path=\"%s\", stvbuf=%p): %d (%s)",
		__FUNCTION__, path, stvbuf, -err, strerror(err));

	return -err;
}

static int refs_fuse_op_release(const char *path, struct fuse_file_info *fi)
{
	int err = 0;

	sys_log_debug("%s(path=\"%s\", fi=%p)",
		__FUNCTION__, path, fi);

	sys_log_debug("%s(path=\"%s\", fi=%p): %d (%s)",
		__FUNCTION__, path, fi, -err, strerror(err));

	return -err;
}

static int refs_fuse_op_readdir_visit_directory_entry(
		void *context,
		const refschar *file_name,
		u16 file_name_length,
		u32 file_flags,
		u64 object_id,
		u64 hard_link_id,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size,
		const u8 *record,
		size_t record_size)
{
	(void) object_id;
	(void) hard_link_id;
	(void) record;
	(void) record_size;

	return refs_fuse_filldir(
		/* refs_fuse_readdir_context *context */
		(refs_fuse_readdir_context*) context,
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

static int refs_fuse_op_readdir_visit_file_entry(
		void *context,
		const le16 *file_name,
		u16 file_name_length,
		u32 file_flags,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size,
		const u8 *record,
		size_t record_size)
{
	(void) record;
	(void) record_size;

	return refs_fuse_filldir(
		/* refs_fuse_readdir_context *context */
		(refs_fuse_readdir_context*) context,
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

static int refs_fuse_op_readdir(const char *path, void *dirbuf,
		fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	refs_volume *const vol =
		(refs_volume*) fuse_get_context()->private_data;
	int err = 0;
	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;
	refs_fuse_readdir_context context;
	refs_node_walk_visitor visitor;

	memset(&context, 0, sizeof(context));
	memset(&visitor, 0, sizeof(visitor));

	sys_log_debug("%s(path=\"%s\", dirbuf=%p, filler=%p, "
		"offset=%" PRId64 ", fi=%p)",
		__FUNCTION__, path, dirbuf, filler, PRAd64(offset), fi);

	err = refs_fuse_lookup_by_posix_path(
		/* refs_volume *vol */
		vol,
		/* const char *path */
		path,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* sys_bool *out_is_short_entry */
		NULL,
		/* const u8 **out_record */
		NULL,
		/* size_t *out_record_size */
		NULL);
	if(err) {
		goto out;
	}
	else if(!parent_directory_object_id) {
		err = ENOENT;
		goto out;
	}
	else if(!directory_object_id) {
		err = ENOTDIR;
		goto out;
	}

	if(filler(dirbuf, ".", NULL, 0)) {
		goto out;
	}

	if(filler(dirbuf, "..", NULL, 0)) {
		goto out;
	}

	context.dirbuf = dirbuf;
	context.filler = filler;
	visitor.context = &context;
	visitor.node_long_entry = refs_fuse_op_readdir_visit_file_entry;
	visitor.node_short_entry =
		refs_fuse_op_readdir_visit_directory_entry;

	err = refs_node_walk(
		/* sys_device *dev */
		vol->dev,
		/* REFS_BOOT_SECTOR *bs */
		vol->bs,
		/* REFS_SUPERBLOCK_HEADER **sb */
		&vol->sb,
		/* REFS_LEVEL1_NODE **primary_level1_node */
		&vol->primary_level1_node,
		/* REFS_LEVEL1_NODE **secondary_level1_node */
		&vol->secondary_level1_node,
		/* refs_block_map **block_map */
		&vol->block_map,
		/* const u64 *start_node */
		NULL,
		/* const u64 *object_id */
		&directory_object_id,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err) {
		sys_log_perror(err, "Error while listing directory");
		goto out;
	}
out:
	sys_log_debug("%s(path=\"%s\", dirbuf=%p, filler=%p, "
		"offset=%" PRId64 ", fi=%p): %d (%s)",
		__FUNCTION__, path, dirbuf, filler, PRAd64(offset), fi, -err,
		strerror(err));

	return -err;
}

#if defined(_WIN32)
static int refs_fuse_op_win_get_attributes_visit_short_entry(
		void *context,
		const refschar *file_name,
		u16 file_name_length,
		u32 file_flags,
		u64 object_id,
		u64 hard_link_id,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size,
		const u8 *record,
		size_t record_size)
{
	(void) file_name;
	(void) file_name_length;
	(void) object_id;
	(void) hard_link_id;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) file_size,
	(void) allocated_size,
	(void) record;
	(void) record_size;

	*((uint32_t*) context) =
		(file_flags & ~((uint32_t) 0x10000000UL)) |
		((file_flags & 0x10000000UL) ?
		0x10 /* FILE_ATTRIBUTE_DIRECTORY */ : 0);

	return 0;
}

static int refs_fuse_op_win_get_attributes_visit_long_entry(
		void *context,
		const le16 *file_name,
		u16 file_name_length,
		u32 file_flags,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size,
		const u8 *record,
		size_t record_size)
{
	(void) file_name;
	(void) file_name_length;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) file_size;
	(void) allocated_size;
	(void) record;
	(void) record_size;

	*((uint32_t*) context) = file_flags;

	return 0;
}

uint32_t refs_fuse_op_win_get_attributes(const char *path)
{
	refs_volume *const vol =
		(refs_volume*) fuse_get_context()->private_data;
	int err = 0;
	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;
	sys_bool is_short_entry = SYS_FALSE;
	const u8 *record = NULL;
	size_t record_size = 0;
	refs_node_crawl_context crawl_context;
	refs_node_walk_visitor visitor;
	uint32_t attributes = 0;

	memset(&visitor, 0, sizeof(visitor));

	sys_log_debug("%s(path=\"%s\")", __FUNCTION__, path);

	err = refs_fuse_lookup_by_posix_path(
		/* refs_volume *vol */
		vol,
		/* const char *path */
		path,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* sys_bool *out_is_short_entry */
		&is_short_entry,
		/* const u8 **out_record */
		&record,
		/* size_t *out_record_size */
		&record_size);
	if(err) {
		sys_log_perror(err, "Error while looking up entry by path");
		goto out;
	}
	else if(!parent_directory_object_id) {
		err = ENOENT;
		goto out;
	}

	crawl_context = refs_volume_init_node_crawl_context(
		/* refs_volume *vol */
		vol);
	visitor.context = &attributes;
	if(!record && directory_object_id) {
		/* Root directory. */
		attributes =
			0x04 /* FILE_ATTRIBUTE_SYSTEM */ |
			0x10 /* FILE_ATTRIBUTE_DIRECTORY */ |
			0x20 /* FILE_ATTRIBUTE_ARCHIVE */;
	}
	else if(is_short_entry) {
		visitor.node_short_entry =
			refs_fuse_op_win_get_attributes_visit_short_entry;
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
			NULL,
			/* u16 key_size */
			0,
			/* const u8 *value */
			record,
			/* u16 value_offset */
			0,
			/* u16 value_size */
			record_size,
			/* void *context */
			NULL);
	}
	else {
		visitor.node_long_entry =
			refs_fuse_op_win_get_attributes_visit_long_entry;
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
			NULL,
			/* u16 key_size */
			0,
			/* const u8 *value */
			record,
			/* u16 value_offset */
			0,
			/* u16 value_size */
			record_size,
			/* void *context */
			NULL);
	}

	if(err) {
		sys_log_perror(err, "Error while parsing entry data");
	}
out:
	sys_log_debug("%s(path=\"%s\"): %" PRIu32 " (%s)",
		__FUNCTION__, path, PRAu32(attributes), strerror(0));

	return attributes;
}
#endif /* defined(_WIN32) */

struct fuse_operations refs_fuse_operations = {
	/* int (*getattr) (const char *, struct FUSE_STAT *) */
	.getattr = refs_fuse_op_getattr,
	/* int (*open) (const char *, struct fuse_file_info *) */
	.open = refs_fuse_op_open,
	/* int (*read) (const char *, char *, size_t, off_t,
	 *         struct fuse_file_info *) */
	.read = refs_fuse_op_read,
	/* int (*statfs) (const char *, struct statvfs *) */
	.statfs = refs_fuse_op_statfs,
	/* int (*release) (const char *, struct fuse_file_info *) */
	.release = refs_fuse_op_release,
	/* int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t,
	 *         struct fuse_file_info *) */
	.readdir = refs_fuse_op_readdir,
#ifdef _WIN32
	/* uint32_t (*win_get_attributes) (const char *fn) */
	.win_get_attributes = refs_fuse_op_win_get_attributes,
#endif
};

int main(int argc, char **argv)
{
	int err = 0;
	sys_device *dev = NULL;
	refs_volume *vol = NULL;
	refs_fuse_node *cur_node = NULL;

	if(argc < 3) {
		fprintf(stderr, "usage: refs-fuse <device> <mountpoint> [fuse "
			"options...]\n");
		err = EINVAL;
		goto out;
	}

	err = sys_device_open(&dev, argv[1]);
	if(err) {
		sys_log_perror(err, "Error while opening device \"%s\"",
			argv[1]);
		goto out;
	}

	err = refs_volume_create(dev, &vol);
	if(err) {
		sys_log_perror(err, "Error while mounting ReFS volume \"%s\"",
			argv[1]);
		goto out;
	}

	/* Shuffle arguments around for 'fuse_main'. The mountpoint should be
	 * the first non-option argument and the device should not be passed on,
	 * but we add the '-s' switch to enforce single-threaded operation. */
	argv[1] = argv[2];
	argv[2] = "-s";

	if(fuse_main(argc, argv, &refs_fuse_operations, vol)) {
		err = EIO;
	}

	if(cached_nodes_list) {
		/* Iterate over cached nodes and free all resources. */
		cur_node = cached_nodes_list;
		do {
			refs_fuse_node *next_node = cur_node->next;

			sys_free(&cur_node->record);
			sys_free(&cur_node->path);
			sys_free(&cur_node);

			cur_node = next_node;
		} while(cur_node != cached_nodes_list);

		cached_nodes_count = 0;
		cached_nodes_list = NULL;
	}
out:
	if(vol) {
		refs_volume_destroy(&vol);
	}

	if(dev) {
		sys_device_close(&dev);
	}

	return err ? (EXIT_FAILURE) : (EXIT_SUCCESS);
}
