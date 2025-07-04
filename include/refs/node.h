/*-
 * node.h - ReFS node handling declarations.
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

#ifndef _REFS_NODE_H
#define _REFS_NODE_H

typedef struct refs_node refs_node;
typedef struct refs_block_map refs_block_map;
typedef struct refs_node_print_visitor refs_node_print_visitor;
typedef struct refs_node_walk_visitor refs_node_walk_visitor;
typedef struct refs_node_stream_data refs_node_stream_data;
typedef struct refs_node_scan_visitor refs_node_scan_visitor;
typedef struct refs_node_crawl_context refs_node_crawl_context;

#include "layout.h"
#include "sys.h"

struct refs_node_print_visitor {
	void *context;
	sys_bool verbose;

	int (*print_message)(
		void *context,
		const char *fmt,
		...)
		__attribute__((format(printf, 2, 3)));
};

struct refs_node_stream_data {
	sys_bool resident;
	union {
		const void *resident;
		struct {
			u64 stream_id;
		} non_resident;
	} data;
};

struct refs_node_walk_visitor {
	void *context;

	refs_node_print_visitor print_visitor;

	int version_major;
	int version_minor;

	int (*node_header)(
		void *context,
		u64 node_number,
		u64 node_first_cluster,
		u64 object_id,
		const u8 *data,
		size_t header_size);
	int (*node_header_entry)(
		void *context,
		const u8 *data,
		size_t entry_size);
	int (*node_allocation_entry)(
		void *context,
		const u8 *data,
		size_t entry_size);
	int (*node_regular_entry)(
		void *context,
		const u8 *data,
		size_t entry_size);
	int (*node_volume_label_entry)(
		void *context,
		const le16 *volume_label,
		u16 volume_label_length);
	int (*node_long_entry)(
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
		size_t record_size);
	int (*node_short_entry)(
		void *context,
		const le16 *file_name,
		u16 file_name_length,
		u32 file_flags,
		u64 object_id,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		const u64 file_size,
		const u64 allocated_size,
		const u8 *record,
		size_t record_size);
	int (*node_file_extent)(
		void *context,
		u64 first_block,
		u64 block_count,
		u32 block_index_unit);
	int (*node_file_data)(
		void *context,
		const void *data,
		size_t size);
	int (*node_ea)(
		void *context,
		const char *name,
		size_t name_length,
		const void *data,
		size_t data_size);
	int (*node_stream)(
		void *context,
		const char *name,
		size_t name_length,
		u64 data_size,
		const refs_node_stream_data *data_reference);
	int (*node_stream_extent)(
		void *context,
		u64 stream_id,
		u64 first_block,
		u32 block_index_unit,
		u32 cluster_count);
};

struct refs_node_crawl_context {
	sys_device *dev;
	REFS_BOOT_SECTOR *bs;
	refs_block_map *block_map;
	u32 cluster_size;
	u32 block_size;
	u32 block_index_unit;
	u8 version_major;
	u8 version_minor;
};

static inline refs_node_crawl_context refs_node_crawl_context_init(
		sys_device *const dev,
		REFS_BOOT_SECTOR *const bs,
		refs_block_map *const block_map,
		const u32 cluster_size,
		const u32 block_size,
		const u32 block_index_unit,
		const u8 version_major,
		const u8 version_minor)
{
	const refs_node_crawl_context ctx = {
		/* sys_device *dev */
		dev,
		/* REFS_BOOT_SECTOR *bs */
		bs,
		/* refs_block_map *block_map */
		block_map,
		/* u32 cluster_size */
		cluster_size,
		/* u32 block_size */
		block_size,
		/* u32 block_index_unit */
		block_index_unit,
		/* u8 version_major */
		version_major,
		/* u8 version_minor */
		version_minor
	};

	return ctx;
}

int parse_level3_long_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		void *const context);

int parse_level3_short_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		void *const context);

void refs_block_map_destroy(
		refs_block_map **block_map);

/**
 * Walk the ReFS node tree, optionally starting at a specified node.
 *
 * @param dev
 *      (in) The device containing the ReFS filesystem.
 * @param bs
 *      (in) The boot sector of the ReFS device.
 * @param sb
 *      (in/out) (optional) Pointer to a pointer that if non-@p NULL will be
 *      used as a cached copy of the superblock. If the target pointer is
 *      @p NULL, then the superblock will be read and stored in this pointer and
 *      the caller is responsible for freeing it.
 *      If there is no target pointer, and the caller is not interested in
 *      caching the superblock then this parameter should be set to @p NULL.
 * @param primary_level1_node
 *      (in/out) (optional) Pointer to a pointer that if non-@p NULL will be
 *      used as a cached copy of the primary Level 1 node. If the target pointer
 *      is @p NULL, then the primary level 1 node will be read and stored in
 *      this pointer and the caller is responsible for freeing it.
 *      If there is no target pointer, and the caller is not interested in
 *      caching the primary level 1 node then this parameter should be set to
 *      @p NULL.
 * @param secondary_level1_node
 *      (in/out) (optional) Pointer to a pointer that if non-@p NULL will be
 *      used as a cached copy of the secondary Level 1 node. If the target
 *      pointer is @p NULL, then the secondary level 1 node will be read and
 *      stored in this pointer and the caller is responsible for freeing it.
 *      If there is no target pointer, and the caller is not interested in
 *      caching the secondary level 1 node then this parameter should be set to
 *      @p NULL.
 * @param start_node
 *      (in) (optional) A pointer to the start node of the walk. This should be
 *      set to @p NULL if a start node is not specified (the walk will start
 *      from the superblock).
 * @param object_id
 *      (in) (optional) A pointer to the object ID of the node to iterate over.
 *      This should be set to @p NULL if no specific node is requested (the walk
 *      will cover the entire metadata tree).
 * @param block_map
 *      (in/out) (optional) Pointer to a pointer that if non-@p NULL will be
 *      used as a cached copy of the virtual to physical block map. If the
 *      target pointer is @p NULL, then the virtual to physical block map will
 *      be stored in this pointer and the caller is responsible for destroying
 *      it with @ref refs_block_map_destroy.
 *      If there is no target pointer, and the caller is not interested in
 *      caching the virtual to physical block map then this parameter should be
 *      set to @p NULL.
 * @param visitor
 *      Struct containing callbacks relevant for obtaining data from the node
 *      walk.
 *
 * @return
 *      0 on success and otherwise a non-0 @p errno value.
 */
int refs_node_walk(
		sys_device *dev,
		REFS_BOOT_SECTOR *bs,
		REFS_SUPERBLOCK_HEADER **sb,
		REFS_LEVEL1_NODE **primary_level1_node,
		REFS_LEVEL1_NODE **secondary_level1_node,
		refs_block_map **block_map,
		const u64 *start_node,
		const u64 *object_id,
		refs_node_walk_visitor *visitor);

struct refs_node_scan_visitor {
	void *context;

	refs_node_print_visitor print_visitor;

	int (*visit_node)(
		void *context,
		u64 cluster_number,
		u32 cluster_count,
		const REFS_V3_BLOCK_HEADER *header);
};

/**
 * Scan an entire ReFS volume for node signatures and print their physical /
 * logical block offsets and object IDs.
 */
int refs_node_scan(
		sys_device *dev,
		REFS_BOOT_SECTOR *bs,
		refs_node_scan_visitor *visitor);

#endif /* _REFS_NODE_H */
