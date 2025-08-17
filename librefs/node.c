/*-
 * node.c - ReFS node handling definitions.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "node.h"

#include "layout.h"
#include "util.h"
#include "sys.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>


/* Type declarations / definitions. */

typedef struct {
	u64 start;
	u64 length;
} block_range;

struct refs_block_map {
	block_range *entries;
	size_t length;
};

typedef struct {
	u64 *block_numbers;
	size_t block_queue_length;
	u8 elements_per_entry;
} block_queue;


/* Forward declarations. */

static int parse_attribute_leaf_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u16 entry_offset,
		const u32 entry_size,
		void *const context);

static int parse_level3_leaf_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u16 entry_offset,
		const u32 entry_size,
		void *const context);


/* Function defintions. */

static int block_queue_add(
		block_queue *const block_queue,
		const u64 block_number)
{
	const size_t new_block_queue_length =
		block_queue->block_queue_length + 1;
	const size_t element_count = block_queue->elements_per_entry;
	const size_t element_size = element_count * sizeof(u64);

	int err = 0;
	size_t i = 0;
	u64 *new_block_numbers = NULL;

	sys_log_debug("Block queue before expansion (%" PRIuz " elements):",
		PRAuz(block_queue->block_queue_length));
	for(i = 0; i < block_queue->block_queue_length; ++i) {
		sys_log_debug("\t[%" PRIuz "]: %" PRIu64,
			PRAuz(i),
			PRAu64(block_queue->block_numbers[i * element_count]));
	}

	err = sys_realloc(
		block_queue->block_numbers,
		new_block_queue_length * element_size,
		&new_block_numbers);
	if(err) {
		goto out;
	}

	memset(&new_block_numbers[block_queue->block_queue_length *
		element_count], 0, element_size);
	new_block_numbers[block_queue->block_queue_length * element_count] =
		block_number;
	block_queue->block_numbers = new_block_numbers;
	block_queue->block_queue_length = new_block_queue_length;

	sys_log_debug("Block queue after expansion (%" PRIuz " elements):",
		PRAuz(block_queue->block_queue_length));
	for(i = 0; i < block_queue->block_queue_length; ++i) {
		sys_log_debug("\t[%" PRIuz "]: %" PRIu64,
			PRAuz(i),
			PRAu64(block_queue->block_numbers[i * element_count]));
	}
out:
	return err;
}

static const char* entry_type_to_string(u16 entry_type)
{
	switch(entry_type) {
	case 0x0:
		return "metadata";
	case 0x1:
		return "long";
	case 0x2:
		return "short";
	default:
		return "unknown";
	}
}

static u64 logical_to_physical_block_number(
		refs_node_crawl_context *const crawl_context,
		const u64 logical_block_number)
{
	return refs_node_logical_to_physical_block_number(
		/* const REFS_BOOT_SECTOR *bs */
		crawl_context->bs,
		/* const refs_block_map *mapping_table */
		crawl_context->block_map,
		/* u64 logical_block_number */
		logical_block_number);
}

u64 refs_node_logical_to_physical_block_number(
		const REFS_BOOT_SECTOR *const bs,
		const refs_block_map *const mapping_table,
		const u64 logical_block_number)
{
	const u32 cluster_size =
		le32_to_cpu(bs->bytes_per_sector) *
		le32_to_cpu(bs->sectors_per_cluster);
	const u32 linear_block_count =
		(cluster_size == 4096) ? 0x10000 : 0x1000;
	const u32 blocks_per_chunk =
		(cluster_size == 4096) ? 0x4000 : 0x400;

	u64 physical_block_number = 0;

	/* This is a temporary placeholder in order to map blocks in a test
	 * image. It's likely based on an extent/run list stored somewhere
	 * mapping logical to physical ranges, but I don't know where at this
	 * point. */

	if(bs->version_major < 3 || logical_block_number < linear_block_count) {
		/* All blocks below number 4096 / 0x1000 are identity mapped.
		 * The blocks with object ID 0xB, 0xC and (apparently) 0x22 must
		 * exist within this range, as they hold the key to mapping all
		 * virtual block numbers to physical and thus cannot themselves
		 * be virtual. */
		physical_block_number = logical_block_number;
	}
	else if(!mapping_table) {
		physical_block_number = 0;
	}
	else {
		/* Find the block range in the 0xB block's range
		 * descriptions. */
		u32 cur_entry = 0;
		u64 cur_entry_index = 0;
		u64 entry_index =
			((logical_block_number / blocks_per_chunk) / 2 - 2) *
			blocks_per_chunk;
			/* (logical_block_number - 4096); */

		/* Iterate over the 'num_entries' table entries until we find
		 * the right one. */
		for(cur_entry = 0; cur_entry < mapping_table->length;
			++cur_entry)
		{
			const u64 base =
				mapping_table->entries[cur_entry].start;
			const u64 count =
				mapping_table->entries[cur_entry].length;

			sys_log_debug("Iterating over 0xB table entry "
				"%" PRIuz " (index: %" PRIu64 ") looking for "
				"block %" PRIu64 " (index: %" PRIu64 ")...",
				PRAuz(cur_entry), PRAu64(cur_entry_index),
				PRAu64(logical_block_number),
				PRAu64(entry_index));
			sys_log_debug("\tCluster base: %" PRIu64,
				PRAu64(base));
			sys_log_debug("\tCluster count: %" PRIu64,
				PRAu64(count));

			if(entry_index < cur_entry_index + count) {
				physical_block_number =
					base | (logical_block_number &
					(blocks_per_chunk - 1));

				sys_log_debug("\tFound at entry %" PRIu64 "! "
					"Logical -> physical: %" PRIu64 " -> "
					"%" PRIu64,
					PRAu64(cur_entry),
					PRAu64(logical_block_number),
					PRAu64(physical_block_number));
				break;
			}

			cur_entry_index += count;
		}

	}

	return physical_block_number;
}

static void print_file_flags(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	u32 file_flags = read_le32(value);

	print_le32_hex("File flags", prefix, indent, base, value);
	if(file_flags & REFS_FILE_ATTRIBUTE_READONLY) {
		emit(prefix, indent + 1, "READONLY");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_READONLY);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_HIDDEN) {
		emit(prefix, indent + 1, "HIDDEN");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_HIDDEN);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_SYSTEM) {
		emit(prefix, indent + 1, "SYSTEM");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_SYSTEM);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_DIRECTORY) {
		emit(prefix, indent + 1, "DIRECTORY");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_DIRECTORY);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_ARCHIVE) {
		emit(prefix, indent + 1, "ARCHIVE");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_ARCHIVE);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_DEVICE) {
		emit(prefix, indent + 1, "DEVICE");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_DEVICE);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_NORMAL) {
		emit(prefix, indent + 1, "NORMAL");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_NORMAL);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_TEMPORARY) {
		emit(prefix, indent + 1, "TEMPORARY");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_TEMPORARY);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_SPARSE_FILE) {
		emit(prefix, indent + 1, "SPARSE_FILE");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_SPARSE_FILE);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_REPARSE_POINT) {
		emit(prefix, indent + 1, "REPARSE_POINT");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_REPARSE_POINT);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_COMPRESSED) {
		emit(prefix, indent + 1, "COMPRESSED");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_COMPRESSED);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_OFFLINE) {
		emit(prefix, indent + 1, "OFFLINE");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_OFFLINE);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) {
		emit(prefix, indent + 1, "NOT_CONTENT_INDEXED");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_ENCRYPTED) {
		emit(prefix, indent + 1, "ENCRYPTED");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_ENCRYPTED);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_INTEGRITY_STREAM) {
		emit(prefix, indent + 1, "INTEGRITY_STREAM");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_INTEGRITY_STREAM);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_VIRTUAL) {
		emit(prefix, indent + 1, "VIRTUAL");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_VIRTUAL);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_NO_SCRUB_DATA) {
		emit(prefix, indent + 1, "NO_SCRUB_DATA");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_NO_SCRUB_DATA);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_EA) {
		emit(prefix, indent + 1, "EA");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_EA);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_PINNED) {
		emit(prefix, indent + 1, "PINNED");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_PINNED);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_UNPINNED) {
		emit(prefix, indent + 1, "UNPINNED");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_UNPINNED);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_RECALL_ON_OPEN) {
		emit(prefix, indent + 1, "RECALL_ON_OPEN");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_RECALL_ON_OPEN);
	}
	if(file_flags & REFS_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) {
		emit(prefix, indent + 1, "RECALL_ON_DATA_ACCESS");
		file_flags &= ~(REFS_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS);
	}
	if(file_flags) {
		emit(prefix, indent + 1, "<Unknown: 0x%" PRIX32 ">",
			PRAX32(file_flags));
	}
}

static u32 parse_superblock_v1_level1_blocks_list(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const block,
		u32 level_1_blocks_offset,
		u32 level_1_blocks_count,
		u64 *out_primary_level1_block,
		u64 *out_secondary_level1_block)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	u32 i;

	emit(prefix, indent, "Level 1 blocks (%" PRIu32 " bytes @ %" PRIu32 " / "
		"0x%" PRIX32 "):",
		PRAu32(level_1_blocks_count * 8),
		PRAu32(level_1_blocks_offset),
		PRAX32(level_1_blocks_offset));
	for(i = 0; i < level_1_blocks_count; ++i) {
		const u64 block_number =
			read_le64(&block[level_1_blocks_offset + i * 8]);
		emit(prefix, indent + 1, "[%" PRIu32 "] %" PRIu64,
			PRAu32(i),
			PRAu64(block_number));
		if(i == 0) {
			*out_primary_level1_block = block_number;
		}
		else if(i == 1) {
			*out_secondary_level1_block = block_number;
		}
	}

	return i * 8;
}

static void parse_extent_v1(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const base,
		const u8 *const data)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	print_le64_dec("Start block", prefix, indent,
		base,
		&data[0]);
	print_le64_hex("Flags(?)", prefix, indent,
		base,
		&data[8]);
	print_le64_hex("Checksum(?)", prefix, indent,
		base,
		&data[16]);
}

static void parse_extent_v3(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const base,
		const u8 *const data)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	print_le64_dechex("Block number 1", prefix, indent,
		base,
		&data[0]);
	print_le64_dechex("Block number 2", prefix, indent,
		base,
		&data[8]);
	print_le64_dechex("Block number 3", prefix, indent,
		base,
		&data[16]);
	print_le64_dechex("Block number 4", prefix, indent,
		base,
		&data[24]);
	print_le64_hex("Flags(?)", prefix, indent,
		base,
		&data[32]);
	print_le64_hex("Checksum(?)", prefix, indent,
		base,
		&data[40]);
}

static void parse_extent(
		refs_node_walk_visitor *const visitor,
		const sys_bool is_v3,
		const char *const prefix,
		const size_t indent,
		const u8 *const base,
		const u8 *const data)
{
	if(is_v3) {
		parse_extent_v3(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *base */
			base,
			/* const u8 *data */
			data);
	}
	else {
		parse_extent_v1(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *base */
			base,
			/* const u8 *data */
			data);
	}
}

static u32 parse_extents_list_v1(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const char *const list_name,
		const u8 *const block,
		const size_t block_size,
		const u32 *const self_extents_offsets,
		u32 self_extents_size,
		u64 *out_extents)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	u32 total_size = 0;
	u32 i;

	emit(prefix, indent - 1, "%s (%" PRIu32 " bytes @ %" PRIu32 " / "
		"0x%" PRIX32 "):",
		list_name,
		PRAu32(self_extents_size),
		PRAu32(self_extents_offsets[0]),
		PRAX32(self_extents_offsets[0]));
	for(i = 0; i + 24 <= self_extents_size; i += 24) {
		const u32 extent_index = i / 24;
		const u32 self_extents_offset =
			self_extents_offsets[extent_index];


		if(i && self_extents_offset >
			self_extents_offsets[extent_index - 1] + 24)
		{
			const u32 prev_extent_end =
				self_extents_offsets[extent_index - 1] + 24;

			/* Print padding / data in between extents. */
			print_data_with_base(prefix, indent, prev_extent_end,
				block_size,
				&block[prev_extent_end],
				self_extents_offset - prev_extent_end);
			total_size += self_extents_offset - prev_extent_end;
		}

		emit(prefix, indent, "[%" PRIu32 "] @ %" PRIu32 " / "
			"0x%" PRIX32 ":",
			PRAu32(extent_index),
			PRAu32(self_extents_offset),
			PRAX32(self_extents_offset));
		parse_extent_v1(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const u8 *base */
			&block[self_extents_offset],
			/* const u8 *data */
			&block[self_extents_offset]);
		if(out_extents) {
			out_extents[extent_index * 3 + 0] =
				read_le64(&block[self_extents_offset + 0]);
			out_extents[extent_index * 3 + 1] =
				read_le64(&block[self_extents_offset + 8]);
			out_extents[extent_index * 3 + 2] =
				read_le64(&block[self_extents_offset + 16]);
		}

		total_size += 24;
	}

	return total_size;
}

static u32 parse_extents_list_v3(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const char *const list_name,
		const u8 *const block,
		const size_t block_size,
		const u32 *const self_extents_offsets,
		u32 self_extents_size,
		u64 *out_extents)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	u32 total_size = 0;
	u32 i;

	emit(prefix, indent - 1, "%s (%" PRIu32 " bytes @ %" PRIu32 " / "
		"0x%" PRIX32 "):",
		list_name,
		PRAu32(self_extents_size),
		PRAu32(self_extents_offsets[0]),
		PRAX32(self_extents_offsets[0]));
	for(i = 0; i + 48 <= self_extents_size; i += 48) {
		const u32 extent_index = i / 48;
		const u32 self_extents_offset =
			self_extents_offsets[extent_index];

		if(i && self_extents_offset >
			self_extents_offsets[extent_index - 1] + 48)
		{
			const u32 prev_extent_end =
				self_extents_offsets[extent_index - 1] + 48;

			/* Print padding / data in between extents. */
			print_data_with_base(prefix, indent - 1,
				prev_extent_end, block_size,
				&block[prev_extent_end],
				self_extents_offset - prev_extent_end);
			total_size += self_extents_offset - prev_extent_end;
		}

		emit(prefix, indent, "[%" PRIu32 "] @ %" PRIu32 " / "
			"0x%" PRIX32 ":",
			PRAu32(extent_index),
			PRAu32(self_extents_offset),
			PRAX32(self_extents_offset));
		parse_extent_v3(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const u8 *base */
			&block[self_extents_offset],
			/* const u8 *data */
			&block[self_extents_offset]);
		if(out_extents) {
			out_extents[extent_index * 6 + 0] =
				read_le64(&block[self_extents_offset + 0]);
			out_extents[extent_index * 6 + 1] =
				read_le64(&block[self_extents_offset + 8]);
			out_extents[extent_index * 6 + 2] =
				read_le64(&block[self_extents_offset + 16]);
			out_extents[extent_index * 6 + 3] =
				read_le64(&block[self_extents_offset + 24]);
			out_extents[extent_index * 6 + 4] =
				read_le64(&block[self_extents_offset + 32]);
			out_extents[extent_index * 6 + 5] =
				read_le64(&block[self_extents_offset + 40]);
		}

		total_size += 48;
	}

	return total_size;
}

static int parse_block_header(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 level,
		const u8 *const block,
		const u32 block_size,
		const u64 cluster_number,
		const u64 block_number,
		const u64 block_queue_index,
		sys_bool *const out_is_valid,
		sys_bool *const out_is_v3,
		u32 *const out_header_size,
		u64 *const out_object_id)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const char *const block_signature = (level == 1) ? "CHKP" : "MSB+";

	int err = 0;
	const u8 *header = NULL;
	u32 i = 0;
	sys_bool is_v3 = SYS_FALSE;
	u64 object_id = 0;

	if(block_size < 512) {
		sys_log_warning("Ignoring block with unreasonable block "
			"size: %" PRIu32, PRAu32(block_size));
		if(out_is_valid) {
			*out_is_valid = SYS_FALSE;
		}

		goto out;
	}

	if(!memcmp(&block[0x0], block_signature, 4)) {
		header = &block[0x20];
		object_id = read_le64(&header[0x28]);
		i = 0x20;
		is_v3 = SYS_TRUE;
	}
	else {
		header = &block[0x0];
		object_id = read_le64(&header[0x18]);
		i = 0x0;
	}

	if(visitor && visitor->node_header) {
		err = visitor->node_header(
			/* void *context */
			visitor->context,
			/* u64 node_number */
			block_number,
			/* u64 node_first_cluster */
			cluster_number,
			/* u64 object_id */
			object_id,
			/* const u8 *data */
			block,
			/* size_t data_size */
			block_size,
			/* size_t header_offset */
			is_v3 ? 0x20U : 0x00U,
			/* size_t header_size */
			i);
		if(err) {
			goto out;
		}
	}

	if(level == 1) {
		emit(prefix, indent, "%s level 1 block (%" PRIu64 "):",
			(block_queue_index == 0) ? "Primary" : "Secondary",
			PRAu64(block_number));
	}
	else {
		emit(prefix, indent, "Level %" PRIu8 " block %" PRIu64 " "
			"(logical block %" PRIu64 " / 0x%" PRIX64 ", physical "
			"block "
			"%" PRIu64 " / 0x%" PRIX64"):",
			PRAu8(level),
			PRAu64(block_queue_index),
			PRAu64(block_number),
			PRAX64(block_number),
			PRAu64(cluster_number),
			PRAX64(cluster_number));
	}

	emit(prefix, indent + 1, "Block header:");
	if(is_v3) {
		emit(prefix, indent + 2, "Signature @ %" PRIuz " / "
			"0x%" PRIXz ": \"%" PRIbs "\"",
			PRAuz(0x0),
			PRAXz(0x0),
			PRAbs(4, &block[0x0]));
		print_unknown32(prefix, indent + 2, block, &block[0x4]);
		print_unknown32(prefix, indent + 2, block, &block[0x8]);
		print_unknown32(prefix, indent + 2, block, &block[0xC]);
		print_le64_dechex("Checkpoint number", prefix, indent + 2,
			block, &block[0x10]);
		print_unknown64(prefix, indent + 2, block, &block[0x18]);
	}

	/* This is the 48/80 byte block header. */
	print_le64_dechex(is_v3 ? "Block number 1" : "Block number", prefix,
		indent + 2, block, &header[0x0]);

	if(block_number != read_le64(&header[0x0])) {
		sys_log_warning("Ignoring block with mismatching block "
			"number.");
		if(out_is_valid) {
			*out_is_valid = SYS_FALSE;
		}

		goto out;
	}

	if(!is_v3) {
		print_unknown64(prefix, indent + 2, block, &header[0x8]);
		print_unknown64(prefix, indent + 2, block, &header[0x10]);
		emit(prefix, indent + 2, "Object ID @ %" PRIuz " / "
			"0x%" PRIXz ": %" PRIu64 " / 0x%" PRIX64,
			PRAuz(((size_t) header - (size_t) block) + 0x18),
			PRAXz(((size_t) header - (size_t) block) + 0x18),
			PRAu64(read_le64(&header[0x18])),
			PRAX64(read_le64(&header[0x18])));
	}
	else {
		print_le64_dechex("Block number 2", prefix, indent + 2, block,
			&header[0x8]);
		print_le64_dechex("Block number 3", prefix, indent + 2, block,
			&header[0x10]);
		print_le64_dechex("Block number 4", prefix, indent + 2, block,
			&header[0x18]);
	}
	print_unknown64(prefix, indent + 2, block, &header[0x20]);
	if(!is_v3) {
		print_unknown64(prefix, indent + 2, block, &header[0x28]);
	}
	else {
		emit(prefix, indent + 2, "Object ID @ %" PRIuz " / "
			"0x%" PRIXz ": %" PRIu64 " / 0x%" PRIX64,
			PRAuz(((size_t) header - (size_t) block) + 0x28),
			PRAXz(((size_t) header - (size_t) block) + 0x28),
			PRAu64(read_le64(&header[0x28])),
			PRAX64(read_le64(&header[0x28])));
	}

	i += 0x30;

	if(out_is_valid) {
		*out_is_valid = SYS_TRUE;
	}

	if(out_is_v3) {
		*out_is_v3 = is_v3;
	}

	if(out_header_size) {
		*out_header_size = i;
	}

	if(out_object_id) {
		*out_object_id = object_id;
	}
out:
	return err;
}

static void parse_superblock_v1(
		refs_node_walk_visitor *const visitor,
		const u8 *const block,
		size_t block_size,
		u64 *out_primary_level1_block,
		u64 *out_secondary_level1_block)
{
	static const char *const prefix = "\t";
	static const size_t indent = 0;

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const REFS_V1_SUPERBLOCK_HEADER *const header =
		(const REFS_V1_SUPERBLOCK_HEADER*) block;

	u32 level_1_blocks_offset = 0;
	u32 level_1_blocks_count = 0;
	u32 self_extents_offset = 0;
	u32 self_extents_size = 0;
	size_t i = 0;

	emit(prefix, indent, "Self block index: %" PRIu64 " / 0x%" PRIX64,
		PRAu64(le64_to_cpu(header->self_block_index)),
		PRAX64(le64_to_cpu(header->self_block_index)));
	print_unknown64(prefix, indent, block, &header->reserved8);
	print_unknown64(prefix, indent, block, &header->reserved16);
	print_unknown64(prefix, indent, block, &header->reserved24);
	print_unknown64(prefix, indent, block, &header->reserved32);
	print_unknown64(prefix, indent, block, &header->reserved40);
	emit(prefix, indent, "GUID @ %" PRIuz " / 0x%" PRIXz ": %" PRIGUID,
		PRAuz(offsetof(REFS_V1_SUPERBLOCK_HEADER, self_extents_offset)),
		PRAXz(offsetof(REFS_V1_SUPERBLOCK_HEADER, self_extents_offset)),
		PRAGUID(header->block_guid));
	print_unknown64(prefix, indent, block, &header->reserved64);
	print_unknown64(prefix, indent, block, &header->reserved72);
	level_1_blocks_offset = le32_to_cpu(header->level1_blocks_offset);
	emit(prefix, indent, "Offset of level 1 block references @ %" PRIuz " "
		"/ 0x%" PRIXz ": "
		"%" PRIu64,
		PRAuz(offsetof(REFS_V1_SUPERBLOCK_HEADER, level1_blocks_offset)),
		PRAXz(offsetof(REFS_V1_SUPERBLOCK_HEADER, level1_blocks_offset)),
		PRAu64(level_1_blocks_offset));
	level_1_blocks_count = le32_to_cpu(header->level1_blocks_count);
	emit(prefix, indent, "Number of level 1 block references @ %" PRIuz " "
		"/ 0x%" PRIXz ": "
		"%" PRIu64,
		PRAuz(offsetof(REFS_V1_SUPERBLOCK_HEADER, level1_blocks_count)),
		PRAXz(offsetof(REFS_V1_SUPERBLOCK_HEADER, level1_blocks_count)),
		PRAu64(level_1_blocks_count));
	self_extents_offset = le32_to_cpu(header->self_extents_offset);
	emit(prefix, indent, "Offset of self reference @ %" PRIuz " / "
		"0x%" PRIXz ": %" PRIu64,
		PRAuz(offsetof(REFS_V1_SUPERBLOCK_HEADER, self_extents_offset)),
		PRAXz(offsetof(REFS_V1_SUPERBLOCK_HEADER, self_extents_offset)),
		PRAu64(self_extents_offset));
	self_extents_size = le32_to_cpu(header->self_extents_size);
	emit(prefix, indent, "Size of self reference @ %" PRIuz " / "
		"0x%" PRIXz ": %" PRIu64,
		PRAuz(offsetof(REFS_V1_SUPERBLOCK_HEADER, self_extents_size)),
		PRAXz(offsetof(REFS_V1_SUPERBLOCK_HEADER, self_extents_size)),
		PRAu64(self_extents_size));

	if(sys_min(level_1_blocks_offset, self_extents_offset) > 96) {
		print_data_with_base(prefix, indent, 96, block_size, &block[96],
			sys_min(level_1_blocks_offset, self_extents_offset) -
			96);
	}

	/* TODO: Validate contents past first self extents element based on
	 * prior observations and fail if it deviates. This may be a description
	 * of a fragmented superblock, but we have not seen those yet so we
	 * don't quite know what to expect. */

	if(level_1_blocks_offset < self_extents_offset) {
		i = level_1_blocks_offset;
		i += parse_superblock_v1_level1_blocks_list(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const u8 *const block */
			block,
			/* u32 level_1_blocks_offset */
			level_1_blocks_offset,
			/* u32 level_1_blocks_count */
			level_1_blocks_count,
			/* u64 *out_primary_level1_block */
			out_primary_level1_block,
			/* u64 *out_secondary_level1_block */
			out_secondary_level1_block);
	}
	else {
		i = self_extents_offset;
		i += parse_extents_list_v1(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self extents",
			/* const u8 *const block */
			block,
			/* const size_t block_size */
			block_size,
			/* u32 self_extents_offset */
			&self_extents_offset,
			/* u32 self_extents_size */
			(self_extents_size > 24) ? 24 : self_extents_size,
			/* u64 *out_extents */
			NULL);
	}

	if(sys_max(level_1_blocks_offset, self_extents_offset) > i) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			sys_min(level_1_blocks_offset, self_extents_offset) -
			i);
	}

	if(level_1_blocks_offset < self_extents_offset) {
		i = self_extents_offset;
		i += parse_extents_list_v1(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self extents",
			/* const u8 *const block */
			block,
			/* const size_t block_size */
			block_size,
			/* const u32 *self_extents_offsets */
			&self_extents_offset,
			/* u32 self_extents_size */
			(self_extents_size > 24) ? 24 : self_extents_size,
			/* u64 *out_extents */
			NULL);
	}
	else {
		i = level_1_blocks_offset;
		i += parse_superblock_v1_level1_blocks_list(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const u8 *const block */
			block,
			/* u32 level_1_blocks_offset */
			level_1_blocks_offset,
			/* u32 level_1_blocks_count */
			level_1_blocks_count,
			/* u64 *out_primary_level1_block */
			out_primary_level1_block,
			/* u64 *out_secondary_level1_block */
			out_secondary_level1_block);
	}

	if(i < block_size) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			block_size - i);
	}
}

static void parse_superblock_v3(
		refs_node_walk_visitor *const visitor,
		const u8 *const block,
		const size_t block_size,
		u64 *const out_primary_level1_block,
		u64 *const out_secondary_level1_block)
{
	static const char *const prefix = "\t";
	static size_t indent = 0;

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	u32 level_1_blocks_offset = 0;
	u32 level_1_blocks_count = 0;
	u32 self_extents_offset = 0;
	u32 self_extents_size = 0;
	u32 i;

	const REFS_V3_SUPERBLOCK_HEADER *const sb =
		(const REFS_V3_SUPERBLOCK_HEADER*) block;

	emit(prefix, indent, "Signature: \"%" PRIbs "\"",
		PRAbs(4, sb->signature));
	print_unknown32(prefix, indent, sb, &sb->reserved4);
	print_unknown32(prefix, indent, sb, &sb->reserved8);
	print_unknown32(prefix, indent, sb, &sb->reserved12);
	emit(prefix, indent, "Unknown @ 16:");
	print_data(prefix, indent + 1, sb->reserved16,
		sizeof(sb->reserved16));
	emit(prefix, indent, "Self block index: %" PRIu64 " / 0x%" PRIX64,
		PRAu64(le64_to_cpu(sb->self_block_index)),
		PRAX64(le64_to_cpu(sb->self_block_index)));
	emit(prefix, indent, "Unknown @ 40:");
	print_data(prefix, indent + 1, sb->reserved40,
		sizeof(sb->reserved40));
	emit(prefix, indent, "GUID: %" PRIGUID,
		PRAGUID(sb->block_guid));
	print_unknown64(prefix, indent, sb, &sb->reserved96);
	print_unknown64(prefix, indent, sb, &sb->reserved104);
	level_1_blocks_offset = le32_to_cpu(sb->reserved112);
	emit(prefix, indent, "Offset of level 1 block references: %" PRIu64,
		PRAu64(level_1_blocks_offset));
	level_1_blocks_count = le32_to_cpu(sb->reserved116);
	emit(prefix, indent, "Number of level 1 block references: %" PRIu64,
		PRAu64(level_1_blocks_count));
	self_extents_offset = le32_to_cpu(sb->reserved120);
	emit(prefix, indent, "Offset of self reference: %" PRIu64,
		PRAu64(self_extents_offset));
	self_extents_size = le32_to_cpu(sb->reserved124);
	emit(prefix, indent, "Size of self reference: %" PRIu64,
		PRAu64(self_extents_size));
	if(sys_min(level_1_blocks_offset, self_extents_offset) > 128) {
		print_data_with_base(prefix, indent, 96, block_size,
			&block[128],
			sys_min(level_1_blocks_offset, self_extents_offset) -
			128);
	}

	/* TODO: Validate contents past first self extents element based on
	 * prior observations and fail if it deviates. This may be a description
	 * of a fragmented superblock, but we have not seen those yet so we
	 * don't quite know what to expect. */

	if(level_1_blocks_offset < self_extents_offset) {
		i = level_1_blocks_offset;
		i += parse_superblock_v1_level1_blocks_list(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const u8 *block */
			block,
			/* u32 level_1_blocks_offset */
			level_1_blocks_offset,
			/* u32 level_1_blocks_count */
			level_1_blocks_count,
			/* u64 *out_primary_level1_block */
			out_primary_level1_block,
			/* u64 *out_secondary_level1_block */
			out_secondary_level1_block);
	}
	else {
		i = self_extents_offset;
		i += parse_extents_list_v3(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self extents",
			/* const u8 *block */
			block,
			/* size_t block_size */
			block_size,
			/* const u32 *self_extents_offsets */
			&self_extents_offset,
			/* u32 self_extents_size */
			(self_extents_size > 48) ? 48 : self_extents_size,
			/* u64 *out_extents */
			NULL);
	}

	if(sys_max(level_1_blocks_offset, self_extents_offset) > i) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			sys_min(level_1_blocks_offset, self_extents_offset) -
			i);
	}

	if(level_1_blocks_offset < self_extents_offset) {
		i = self_extents_offset;
		i += parse_extents_list_v3(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self extents",
			/* const u8 *block */
			block,
			/* size_t block_size */
			block_size,
			/* const u32 *self_extents_offsets */
			&self_extents_offset,
			/* u32 self_extents_size */
			(self_extents_size > 48) ? 48 : self_extents_size,
			/* u64 *out_extents */
			NULL);
	}
	else {
		i = level_1_blocks_offset;
		i += parse_superblock_v1_level1_blocks_list(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const u8 *const block */
			block,
			/* u32 level_1_blocks_offset */
			level_1_blocks_offset,
			/* u32 level_1_blocks_count */
			level_1_blocks_count,
			/* u64 *out_primary_level1_block */
			out_primary_level1_block,
			/* u64 *out_secondary_level1_block */
			out_secondary_level1_block);
	}

	if(i < block_size) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			block_size - i);
	}
}

static int parse_level1_block_level2_blocks_list(
		refs_node_crawl_context *const context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const block,
		u32 block_size,
		u32 extents_list_offset,
		u32 **const out_extents_list,
		u32 *const out_extents_count,
		u32 *const out_end_offset)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 offset = extents_list_offset;
	u32 extents_count;
	size_t extents_size = 0;
	size_t extents_list_inset = 0;
	u32 *extents_list = NULL;
	u32 i;

	extents_count = read_le32(&block[offset]);
	emit(prefix, indent, "Level 2 blocks count @ %" PRIuz " / "
		"0x%" PRIXz ": %" PRIu64 " / 0x%" PRIX64,
		PRAuz(extents_list_offset),
		PRAXz(extents_list_offset),
		PRAu64(extents_count),
		PRAX64(extents_count));
	offset += sizeof(le32);
	extents_size = extents_count * sizeof(le32);
	if(extents_size > block_size - extents_list_offset) {
		sys_log_warning("Invalid extents list: Overflows end of "
			"block.");
		*out_extents_list = NULL;
		*out_extents_count = 0;
		goto out;
	}

	if(REFS_VERSION_MIN(context->version_major, context->version_minor, 3,
		14))
	{
		sys_log_debug("Insetting extents list by 5 elements on ReFS "
			"3.14 and later.");
		/* Not sure what these 5 elements are in version 3.14,
		 * investigating is TODO. */
		extents_list_inset = 5 * sizeof(le32);
	}

	if(extents_list_inset) {
		/* Note: The offset (from the start of the node) of the level 2
		 * block list appears to be stored at the first offset in ReFS
		 * 3.14. Not sure what the other numbers are yet. */
		const u32 level2_block_list_start = read_le32(&block[offset]);

		emit(prefix, indent, "Level 2 blocks start offset @ "
			"%" PRIu32 " / 0x%" PRIX32 ": %" PRIu32 " / 0x%" PRIX32,
			PRAu32(offset),
			PRAX32(offset),
			PRAu32(level2_block_list_start),
			PRAX32(level2_block_list_start));

		print_data_with_base(prefix, indent,
			extents_list_offset + sizeof(le32) * 2, block_size,
			&block[extents_list_offset + sizeof(le32) * 2],
			extents_list_inset - sizeof(le32));
		offset += extents_list_inset;
	}

	err = sys_malloc(extents_size, &extents_list);
	if(err) {
		sys_log_perror(err, "Error while allocating %" PRIuz " bytes "
			"for extents list",
			PRAuz(extents_size));
		goto out;
	}

	for(i = 0; i < extents_count; ++i) {
		extents_list[i] = read_le32(&block[offset]);
		emit(prefix, indent, "Level 2 blocks offset (%" PRIu32 ") @ "
			"%" PRIu32 " / 0x%" PRIX32 ": %" PRIu32 " / 0x%" PRIX32,
			PRAu32(i),
			PRAu32(offset),
			PRAX32(offset),
			PRAu32(extents_list[i]),
			PRAX32(extents_list[i]));
		offset += sizeof(le32);
	}

	*out_extents_list = extents_list;
	*out_extents_count = extents_count;
	*out_end_offset = offset;
out:
	return err;
}

static int parse_level1_block(
		refs_node_crawl_context *const context,
		refs_node_walk_visitor *const visitor,
		const u64 cluster_number,
		const u64 block_number,
		const u64 block_queue_index,
		const u8 *const block,
		const size_t block_size,
		u64 **const out_level2_extents,
		size_t *const out_level2_extents_count)
{
	static const char *const prefix = "\t";
	static const size_t indent = 0;

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	sys_bool is_valid = SYS_FALSE;
	sys_bool is_v3 = SYS_FALSE;
	const u8 *header = NULL;
	u32 i = 0;
	u64 object_id = 0;
	u32 self_extents_offset = 0 ;
	u32 self_extents_size = 0;
	u32 level2_extents_count = 0;
	u32 *level2_extents_offsets = NULL;
	u64 level2_extents_size = 0;
	u32 level2_extents_end_offset = 0;
	u64 *level2_extents = NULL;

	err = parse_block_header(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const char *prefix */
		"",
		/* size_t indent */
		indent,
		/* u8 level */
		1,
		/* const u8 *block */
		block,
		/* u32 block_size */
		block_size,
		/* u64 cluster_number */
		cluster_number,
		/* u64 block_number */
		block_number,
		/* u64 block_queue_index */
		block_queue_index,
		/* sys_bool *out_is_valid */
		&is_valid,
		/* sys_bool *out_is_v3 */
		&is_v3,
		/* u32 *out_header_size */
		&i,
		/* u64 *out_object_id */
		&object_id);
	if(err || !is_valid) {
		goto out;
	}

	i -= 0x30;
	header = &block[i];

	print_unknown32(prefix, indent, block, &header[0x30]);
	print_unknown16(prefix, indent, block, &header[0x34]);
	print_unknown16(prefix, indent, block, &header[0x36]);
	self_extents_offset = read_le32(&header[0x38]);
	emit(prefix, indent, "Offset of self reference: %" PRIu64,
		PRAu64(self_extents_offset));
	self_extents_size = read_le32(&header[0x3C]);
	emit(prefix, indent, "Size of self reference: %" PRIu64,
		PRAu64(self_extents_size));
	print_le64_dechex("Checkpoint number", prefix, indent, block,
		&header[0x40]);
	print_le64_dechex("First checkpoint number (?)", prefix, indent, block,
		&header[0x48]);
	print_unknown32(prefix, indent, block, &header[0x50]);
	print_unknown32(prefix, indent, block, &header[0x54]);
	i += 0x58;

	if(is_v3) {
		print_unknown32(prefix, indent, block, &header[0x58]);
		print_unknown32(prefix, indent, block, &header[0x5C]);
		print_unknown32(prefix, indent, block, &header[0x60]);
		print_unknown32(prefix, indent, block, &header[0x64]);
		print_unknown32(prefix, indent, block, &header[0x68]);
		print_unknown32(prefix, indent, block, &header[0x6C]);
		i += 0x18;
	}

	err = parse_level1_block_level2_blocks_list(
		/* refs_node_crawl_context *context */
		context,
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const char *prefix */
		prefix,
		/* size_t indent */
		indent,
		/* const u8 *block */
		block,
		/* u32 block_size */
		block_size,
		/* u32 extents_list_offset */
		i,
		/* u32 **out_extents_list */
		&level2_extents_offsets,
		/* u32 *out_extents_count */
		&level2_extents_count,
		/* u32 *out_end_offset */
		&level2_extents_end_offset);
	if(err) {
		sys_log_perror(err, "Error while parsing level 2 blocks list");
		goto out;
	}

	i = level2_extents_end_offset;

	if(self_extents_offset > i) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			sys_min(self_extents_offset, block_size) - i);
	}

	i = self_extents_offset;

	/* TODO: Validate contents past first self extents element based on
	 * prior observations and fail if it deviates. This may be a description
	 * of a fragmented level 1 node, but we have not seen those yet so we
	 * don't quite know what to expect. */
	if(self_extents_offset >= block_size) {
		sys_log_warning("Self extents offset exceeds block size: "
			"%" PRIu32 " != %" PRIuz,
			PRAu32(self_extents_offset), PRAuz(block_size));
	}
	else if(is_v3) {
		i += parse_extents_list_v3(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self extents",
			/* const u8 *const block */
			block,
			/* size_t block_size */
			block_size,
			/* const u32 *self_extents_offsets */
			&self_extents_offset,
			/* u32 self_extents_size */
			(self_extents_size > 48) ? 48 : self_extents_size,
			/* u64 *out_extents */
			NULL);
	}
	else {
		i += parse_extents_list_v1(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self extents",
			/* const u8 *const block */
			block,
			/* size_t block_size */
			block_size,
			/* const u32 *self_extents_offsets */
			&self_extents_offset,
			/* u32 self_extents_size */
			(self_extents_size > 24) ? 24 : self_extents_size,
			/* u64 *out_extents */
			NULL);
	}

	if(!level2_extents_offsets) {
		sys_log_warning("No level 2 extents offsets!");
	}
	else if(level2_extents_offsets[0] < i) {
		sys_log_warning("First level 2 extent offset precedes end of "
			"extent list: %" PRIu32 " < %" PRIu32,
			PRAu32(level2_extents_offsets[0]), PRAu32(i));
	}
	else {
		if(level2_extents_offsets[0] > i) {
			print_data_with_base(prefix, 0, i, block_size,
				&block[i],
				sys_min(level2_extents_offsets[0], block_size) -
				i);
		}

		level2_extents_size =
			level2_extents_count * (size_t) (is_v3 ? 48 : 24);
		err = sys_malloc(level2_extents_size, &level2_extents);
		if(err) {
			sys_log_perror(err, "Error while allocating "
				"%" PRIuz "-byte extents array",
				PRAuz(level2_extents_size));
			goto out;
		}

		i = level2_extents_offsets[0];
		if(is_v3) {
			i += parse_extents_list_v3(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent + 1,
				/* const char *list_name */
				"Level 2 blocks",
				/* const u8 *const block */
				block,
				/* size_t block_size */
				block_size,
				/* const u32 *self_extents_offsets */
				level2_extents_offsets,
				/* u32 self_extents_size */
				level2_extents_size,
				/* u64 *out_extents */
				level2_extents);
		}
		else {
			i += parse_extents_list_v1(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent + 1,
				/* const char *list_name */
				"Level 2 blocks",
				/* const u8 *const block */
				block,
				/* size_t block_size */
				block_size,
				/* const u32 *self_extents_offsets */
				level2_extents_offsets,
				/* u32 self_extents_size */
				level2_extents_size,
				/* u64 *out_extents */
				level2_extents);
		}
	}

	if(i < block_size) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			block_size - i);
	}

	*out_level2_extents_count = level2_extents_count;
	*out_level2_extents = level2_extents;
out:
	if(level2_extents_offsets) {
		sys_free(&level2_extents_offsets);
	}

	return err;
}

static int parse_block_header_entry(
		refs_node_walk_visitor *const visitor,
		const size_t indent,
		const u8 *const entry,
		const u32 entry_size)
{
	static const char *const prefix = "\t";

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 i;

	emit(prefix, indent, "Size: %" PRIu64,
		PRAu64(entry_size));
	emit(prefix, indent, "Header data offset?: %" PRIu64,
		PRAu64(read_le16(&entry[0x4])));
	print_unknown16(prefix, indent, entry, &entry[6]);
	i = 0x8;

	if(entry_size - i >= 0x8) {
		i += print_unknown32(prefix, indent, entry, &entry[i]);
		i += print_unknown32(prefix, indent, entry, &entry[i]);
	}

	if(entry_size - i >= 0x8) {
		i += print_unknown32(prefix, indent, entry, &entry[i]);
		i += print_unknown32(prefix, indent, entry, &entry[i]);
	}

	if(entry_size - i >= 0x8) {
		i += print_unknown64(prefix, indent, entry, &entry[i]);
	}

	if(entry_size - i >= 0x8) {
		i += print_unknown64(prefix, indent, entry, &entry[i]);
	}

	print_data_with_base(prefix, indent, i, 0, &entry[i], entry_size - i);

	return err;
}

static int parse_block_allocation_entry(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const sys_bool is_v3,
		const u8 *const entry,
		const u32 entry_size,
		const u32 entry_offset,
		u32 *const out_flags,
		u32 *const out_value_offsets_start,
		u32 *const out_value_offsets_end,
		u32 *const out_value_count)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 i = 0;

	print_le32_dechex("Size", prefix, indent, entry, &entry[0x0]);
	print_le32_dechex("Free space offset", prefix, indent, entry,
		&entry[0x4]);
	emit(prefix, indent + 1, "-> Real offset: %" PRIu64 " / 0x%" PRIX64,
		PRAu64(read_le32(&entry[0x4]) + entry_offset),
		PRAX64(read_le32(&entry[0x4]) + entry_offset));
	print_le32_dechex("Free space size", prefix, indent, entry,
		&entry[0x8]);

	print_le32_dechex("Flags?", prefix, indent, entry, &entry[0xC]);
	if(out_flags) {
		*out_flags = read_le32(&entry[0xC]);
	}

	print_le32_dechex("Value offsets array start offset", prefix, indent,
		entry, &entry[0x10]);
	emit(prefix, indent + 1, "-> Real offset: %" PRIu64 " / 0x%" PRIX64,
		PRAu64(read_le32(&entry[0x10]) + entry_offset),
		PRAX64(read_le32(&entry[0x10]) + entry_offset));
	if(out_value_offsets_start) {
		*out_value_offsets_start = read_le32(&entry[0x10]);
	}

	print_le32_dec("Number of values", prefix, indent, entry,
		&entry[0x14]);
	if(out_value_count) {
		*out_value_count = read_le32(&entry[0x14]);
	}

	if(is_v3) {
		print_unknown32(prefix, indent, entry, &entry[0x18]);
	}
	else {
		print_le32_dechex("Value offsets array end offset", prefix,
			indent, entry, &entry[0x18]);
		emit(prefix, indent + 1, "-> Real offset: %" PRIu64 " / "
			"0x%" PRIX64,
			PRAu64(read_le32(&entry[0x18]) + entry_offset),
			PRAX64(read_le32(&entry[0x18]) + entry_offset));
		if(out_value_offsets_end) {
			*out_value_offsets_end = read_le32(&entry[0x18]);
		}
	}
	print_unknown32(prefix, indent, entry, &entry[0x1C]);
	i = 0x20;

	if(entry_size >= 0x24) {
		if(is_v3) {
			print_le32_dechex("Value offsets array end offset",
				prefix, indent, entry, &entry[0x20]);
			emit(prefix, indent + 1, "-> Real offset: %" PRIu64 " "
				"/ 0x%" PRIX64,
				PRAu64(read_le32(&entry[0x20]) + entry_offset),
				PRAX64(read_le32(&entry[0x20]) + entry_offset));
			if(out_value_offsets_end) {
				*out_value_offsets_end =
					read_le32(&entry[0x20]);
			}
		}
		else {
			print_unknown32(prefix, indent, entry, &entry[0x20]);
		}

		i += 4;
	}

	if(entry_size >= 0x28) {
		print_unknown32(prefix, indent, entry, &entry[0x24]);
		i += 4;
	}

	if(i < entry_size) {
		print_data_with_base(prefix, indent, i, 0, &entry[i],
			entry_size - i);
	}

	return err;
}

static int parse_level2_block_unknown_table_entry(
		refs_node_walk_visitor *const visitor,
		const u8 *const entry,
		const u32 entry_size,
		const u32 entry_offset,
		const u32 entry_index)
{
	static const char *const prefix = "\t";
	static const size_t indent = 1;

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;

	emit(prefix, 0, "Entry %" PRIu32 " (%s) @ %" PRIu32 " / 0x%" PRIX32 ":",
		PRAu32(entry_index),
		(entry_index == 0) ? "table header" :
		((entry_index == 1) ? "allocation entry" : "regular entry"),
		PRAu32(entry_offset),
		PRAX32(entry_offset));
	emit(prefix, indent, "Size: %" PRIu64,
		PRAu64(entry_size));

	print_data_with_base(prefix, indent, 0x0, 0, &entry[0x0],
		entry_size - 0x0);

	return err;
}

static void parse_index_value(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const sys_bool is_v3,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		u64 *const out_next_level_block_number)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	size_t j = 0x0;

	emit(prefix, indent - 1, "Value (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"index", PRAu16(value_offset), PRAX16(value_offset));

	if(value_size >= j + (is_v3 ? 0x30 : 0x18)) {
		/* Note: Technically the extent contains 4 values (v3 only),
		 * describing 4 block numbers.
		 * For 64k cluster ReFS volumes the other 3 values are empty,
		 * but 4k ReFS volumes have 4 individual cluster numbers
		 * indicating that a block could in theory be fragmented when 4k
		 * clusters are used. Right now we ignore this and assume that a
		 * block is always contiguous on disk. */
		parse_extent(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* sys_bool is_v3 */
			is_v3,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *base */
			value,
			/* const u8 *data */
			&value[j]);

		if(out_next_level_block_number) {
			*out_next_level_block_number = read_le64(&value[j]);
			sys_log_debug("Parsed block number: %" PRIu64,
				PRAu64(*out_next_level_block_number));
		}

		j += (is_v3 ? 0x30 : 0x18);
	}

	if(value_size > j) {
		print_data_with_base(prefix, indent, j, value_size,
			&value[j], value_size - j);
	}
}

static int parse_unknown_key(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const sys_bool is_v3,
		const sys_bool is_index,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u32 entry_size,
		void *const context)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	(void) crawl_context;
	(void) object_id;
	(void) is_v3;
	(void) is_index;
	(void) context;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"unknown", PRAu16(key_offset), PRAX16(key_offset));

	print_data_with_base(prefix, indent, 0, entry_size, key, key_size);

	return 0;
}

static int parse_unknown_leaf_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u16 entry_offset,
		const u32 entry_size,
		void *const context)
{
	const u32 block_index_unit = crawl_context->block_index_unit;
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	(void) object_id;
	(void) block_index_unit;
	(void) is_v3;
	(void) key;
	(void) key_offset;
	(void) key_size;
	(void) entry_offset;
	(void) context;

	emit(prefix, indent - 1, "Value (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"unknown", PRAu16(value_offset), PRAX16(value_offset));

	print_data_with_base(prefix, indent, 0, entry_size, value, value_size);

	return 0;
}

static int parse_generic_entry(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u32 block_index_unit,
		const sys_bool is_v3,
		const sys_bool is_index,
		const u8 *const entry,
		const u32 entry_size,
		const u16 entry_offset,
		const u32 entry_index,
		void *const context,
		int (*const parse_key)(
			refs_node_crawl_context *crawl_context,
			refs_node_walk_visitor *visitor,
			const char *prefix,
			size_t indent,
			u64 object_id,
			sys_bool is_v3,
			sys_bool is_index,
			const u8 *key,
			u16 key_offset,
			u16 key_size,
			u32 entry_size,
			void *context),
		int (*const parse_leaf_value)(
			refs_node_crawl_context *crawl_context,
			refs_node_walk_visitor *visitor,
			const char *prefix,
			size_t indent,
			u64 object_id,
			const u8 *key,
			u16 key_offset,
			u16 key_size,
			const u8 *value,
			u16 value_offset,
			u16 value_size,
			u16 entry_offset,
			u32 entry_size,
			void *context),
		u64 *const out_next_level_block_number)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 i = 0;
	u16 key_offset = 0;
	u16 key_size = 0;
	const u8 *key = NULL;
	u16 value_offset = 0;
	u16 value_size = 0;

	(void) block_index_unit;

	if(entry_size < 0x10) {
		sys_log_warning("Unexpected size for node entry: %" PRIu32 " "
			"Printing raw data...", PRAu32(entry_size));
		parse_level2_block_unknown_table_entry(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const u8 *entry */
			entry,
			/* u32 entry_size */
			entry_size,
			/* size_t entry_offset */
			entry_offset,
			/* u32 entry_index */
			entry_index);
		goto out;
	}

	emit(prefix, indent, "Entry %" PRIu32 " (%s) @ %" PRIu32 " / "
		"0x%" PRIX32 ":",
		PRAu32(entry_index),
		"regular entry",
		PRAu32(entry_offset),
		PRAX32(entry_offset));

	print_le16_dechex("Size", prefix, indent + 1, entry, &entry[0x0]);
	print_le16_dechex("Key offset", prefix, indent + 1, entry, &entry[0x4]);
	key_offset = read_le16(&entry[0x4]);
	print_le16_dechex("Key size", prefix, indent + 1, entry, &entry[0x6]);
	key_size = read_le16(&entry[0x6]);
	print_le16_dechex("Flags?", prefix, indent + 1, entry, &entry[0x8]);
	value_offset = read_le16(&entry[0xA]);
	print_le16_dechex("Value offset", prefix, indent + 1, entry,
		&entry[0xA]);
	value_size = read_le16(&entry[0xC]);
	print_le16_dechex("Value size", prefix, indent + 1, entry, &entry[0xC]);
	print_unknown16(prefix, indent + 1, entry, &entry[0xE]);

	i = 0x10;

	if(key_size && key_offset >= 0x10 && key_offset < entry_size &&
		(entry_size - key_offset) >= key_size &&
		(key_offset + key_size) <= value_offset)
	{
		if(i < key_offset) {
			print_data_with_base(prefix, indent + 1, i, entry_size,
				&entry[i], key_offset - i);
			i = key_offset;
		}

		key = &entry[i];

		err = (parse_key ? parse_key : parse_unknown_key)(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 2,
			/* u64 object_id */
			object_id,
			/* sys_bool is_v3 */
			is_v3,
			/* sys_bool is_index */
			is_index,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
		if(err) {
			goto out;
		}

		i += key_size;
	}

	if(i < value_offset) {
		print_data_with_base(prefix, indent + 1, i, entry_size,
			&entry[i], value_offset - i);
		i = value_offset;
	}

	if(is_index && value_offset < entry_size &&
		value_size <= entry_size - value_offset)
	{
		parse_index_value(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 2,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *value */
			&entry[value_offset],
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u64 *out_next_level_block_number */
			out_next_level_block_number);
	}
	else {
		err = (parse_leaf_value ? parse_leaf_value :
			parse_unknown_leaf_value)(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 2,
			/* u64 object_id */
			object_id,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key ? key_size : 0,
			/* const u8 *value */
			&entry[value_offset],
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u16 entry_offset */
			entry_offset,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
out:
	return err;
}

static int parse_generic_block(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const size_t indent,
		const u64 cluster_number,
		const u64 block_number,
		const u64 block_queue_index,
		const u8 level,
		const u8 *const block,
		const u32 block_size,
		block_queue *const block_queue,
		const sys_bool add_subnodes_in_offsets_order,
		void *const context,
		int (*const parse_key)(
			refs_node_crawl_context *crawl_context,
			refs_node_walk_visitor *visitor,
			const char *prefix,
			size_t indent,
			u64 object_id,
			sys_bool is_index,
			sys_bool is_v3,
			const u8 *key,
			u16 key_offset,
			u16 key_size,
			u32 entry_size,
			void *context),
		int (*const parse_leaf_value)(
			refs_node_crawl_context *crawl_context,
			refs_node_walk_visitor *visitor,
			const char *prefix,
			size_t indent,
			u64 object_id,
			const u8 *key,
			u16 key_offset,
			u16 key_size,
			const u8 *value,
			u16 value_offset,
			u16 value_size,
			u16 entry_offset,
			u32 entry_size,
			void *context),
		int (*const leaf_entry_handler)(
			void *context,
			const u8 *data,
			u32 data_size,
			u32 node_type))
{
	static const char *const prefix = "\t";

	const u32 block_index_unit = crawl_context->block_index_unit;

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 i = 0;
	sys_bool is_valid = SYS_FALSE;
	sys_bool is_v3 = SYS_FALSE;
	u64 object_id = 0;
	const u8 *entry = NULL;
	u32 entry_size = 0;
	u32 first_table_entry_end = 0;
	u32 flags = 0;
	u32 value_offsets_start = 0;
	u32 value_offsets_end = 0;
	u32 values_count = 0;
	u16 *value_offsets = NULL;
	sys_bool is_index_node = SYS_FALSE;
	u32 value_offsets_start_real = 0;
	u32 value_offsets_end_real = 0;
	u32 j = 0;

	if(block_size < 512) {
		/* It doesn't make sense to have blocks less than a sector, and
		 * the smallest sector size that we support is 512 bytes.
		 * In reality blocks are in all observed cases 16k - 64k. */

		sys_log_error("Unsupported block size: %" PRIuz,
			PRAuz(block_size));
	}

	err = parse_block_header(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const char *prefix */
		"",
		/* size_t indent */
		indent,
		/* u8 level */
		level,
		/* const u8 *block */
		block,
		/* u32 block_size */
		block_size,
		/* u64 cluster_number */
		cluster_number,
		/* u64 block_number */
		block_number,
		/* u64 block_queue_index */
		block_queue_index,
		/* sys_bool *out_is_valid */
		&is_valid,
		/* sys_bool *out_is_v3 */
		&is_v3,
		/* u32 *out_header_size */
		&i,
		/* u64 *out_object_id */
		&object_id);
	if(err || !is_valid) {
		goto out;
	}

	entry = &block[i];
	entry_size = read_le32(entry);
	emit(prefix, indent, "Entry %" PRIu32 " (%s) @ %" PRIu32 " / "
		"0x%" PRIX32 ":",
		PRAu32(0),
		"table header",
		PRAu32(i),
		PRAX32(i));
	err = parse_block_header_entry(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* size_t indent */
		indent + 1,
		/* const u8 *entry */
		entry,
		/* u32 entry_size */
		entry_size);
	if(err) {
		goto out;
	}

	if(visitor && visitor->node_header_entry) {
		err = visitor->node_header_entry(
			/* void *context */
			visitor->context,
			/* const u8 *data */
			entry,
			/* size_t entry_size */
			entry_size);
		if(err) {
			goto out;
		}
	}

	i += entry_size;
	first_table_entry_end = i;

	entry = &block[i];
	entry_size = read_le32(entry);
	emit(prefix, indent, "Entry %" PRIu32 " (%s) @ %" PRIu32 " / "
		"0x%" PRIX32 ":",
		PRAu32(1),
		"allocation entry",
		PRAu32(i),
		PRAX32(i));
	err = parse_block_allocation_entry(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const char *prefix */
		prefix,
		/* size_t indent */
		indent + 1,
		/* sys_bool is_v3 */
		is_v3,
		/* const u8 *entry */
		entry,
		/* u32 entry_size */
		entry_size,
		/* u32 entry_offset */
		i,
		/* u32 *out_flags */
		&flags,
		/* u32 *out_value_offsets_start */
		&value_offsets_start,
		/* u32 *out_value_offsets_end */
		&value_offsets_end,
		/* u32 *out_value_count */
		&values_count);
	if(err) {
		goto out;
	}

	if(visitor && visitor->node_allocation_entry) {
		err = visitor->node_allocation_entry(
			/* void *context */
			visitor->context,
			/* const u8 *data */
			entry,
			/* size_t entry_size */
			entry_size);
		if(err) {
			goto out;
		}
	}

	/* The 0x301 value seems to be a sure marker that this is an index node.
	 * There are however other values that also seem to indicate an index
	 * node, but not reliably so.
	 * Well actually this may be a misinterpretation. Some values in nodes
	 * with flags 0x0 have block references with an Object ID key, but I
	 * think those are in fact subdirectory references.
	 * In fact the 0x2 tree seems to be the tree mapping object IDs to
	 * root nodes of directories (?). Then the directory trees can also have
	 * index nodes but the leaf nodes have mixed values... e.g. the first
	 * entry seems to be an $I30 index in each directory, then there are
	 * file/directory entries, etc. */
	if(flags == 0x301 || flags == 0x302 || flags == 0x101) {
		is_index_node = SYS_TRUE;
	}

	i += entry_size;

	/* Sanity checks. */
	if(!value_offsets_start || !value_offsets_end ||
		first_table_entry_end + value_offsets_start < i ||
		value_offsets_end < value_offsets_start ||
		values_count > (value_offsets_end - value_offsets_start) / 4)
	{
		sys_log_warning("Unexpected value offsets (start: "
			"%" PRIu32 " end: %" PRIu32 " count: "
			"%" PRIu32 "). Ignoring values...",
			PRAu32(value_offsets_start),
			PRAu32(value_offsets_end),
			PRAu32(values_count));
		err = EIO;
		goto out;
	}

	value_offsets_start_real =
		first_table_entry_end + value_offsets_start;
	value_offsets_end_real =
		first_table_entry_end + value_offsets_end;

	err = sys_malloc(sizeof(u16) * values_count, &value_offsets);
	if(err) {
		goto out;
	}

	sys_log_debug("First table entry end: %" PRIu16,
		PRAu16(first_table_entry_end));

	/* Start by reading and validating the value offsets. */
	for(j = value_offsets_start_real; j < value_offsets_end_real; j += 4) {
		const u32 cur_index = (j - value_offsets_start_real) / 4;
		const u16 cur_offset =
			first_table_entry_end + read_le16(&block[j]);
		u64 next_level_block_number = 0;

		sys_log_debug("Offset (relative): %" PRIu16,
			PRAu16(read_le16(&block[j])));
		sys_log_debug("Offset (real): %" PRIu16, PRAu16(cur_offset));

		if(((u32) cur_offset) + 4 > value_offsets_start_real) {
			sys_log_warning("Invalid value offset at index "
				"%" PRIu32 " in value offsets array: "
				"%" PRIu16 " / 0x%" PRIX16 " (value offsets "
				"array start: %" PRIu32 ", node size: "
				"%" PRIu32 ")",
				PRAu32(cur_index),
				PRAu16(cur_offset),
				PRAX16(cur_offset),
				PRAu32(value_offsets_start_real),
				PRAu32(block_size));
			err = EIO;
			goto out;
		}

		entry = &block[cur_offset];
		entry_size = read_le32(&entry[0]);
		if(cur_offset + entry_size > value_offsets_start_real) {
			sys_log_warning("Invalid size for value at offset "
				"%" PRIu32 " (index %" PRIu32 " in value "
				"offsets array): %" PRIu32 " / 0x%" PRIX32 " "
				"(value offsets array start: %" PRIu32 ", node "
				"size: %" PRIu32 ")",
				PRAu32(cur_offset),
				PRAu32(cur_index),
				PRAu32(entry_size),
				PRAX32(entry_size),
				PRAu32(value_offsets_start_real),
				PRAu32(block_size));
			err = EIO;
			goto out;
		}

		err = parse_generic_entry(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			!((print_visitor && print_visitor->print_message) ||
			!add_subnodes_in_offsets_order) ? visitor : NULL,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* u32 block_index_unit */
			block_index_unit,
			/* sys_bool is_v3 */
			is_v3,
			/* sys_bool is_index */
			is_index_node,
			/* const u8 *entry */
			entry,
			/* u32 entry_size */
			entry_size,
			/* u16 entry_offset */
			cur_offset,
			/* u32 entry_index */
			cur_index,
			/* void *context */
			context,
			/* int (*parse_key)(
			 *      refs_node_crawl_context *crawl_context,
			 *      refs_node_walk_visitor *visitor,
			 *      const char *prefix,
			 *      size_t indent,
			 *      u64 object_id,
			 *      sys_bool is_v3,
			 *      sys_bool is_index,
			 *      const u8 *key,
			 *      u16 key_offset,
			 *      u16 key_size,
			 *      void *context) */
			parse_key,
			/* int (*parse_leaf_value)(
			 *      refs_node_crawl_context *crawl_context,
			 *      refs_node_walk_visitor *visitor,
			 *      const char *prefix,
			 *      size_t indent,
			 *      u64 object_id,
			 *      const u8 *key,
			 *      u16 key_offset,
			 *      u16 key_size,
			 *      const u8 *value,
			 *      u16 value_offset,
			 *      u16 value_size,
			 *      u16 entry_offset,
			 *      u32 entry_size,
			 *      void *context) */
			parse_leaf_value,
			/* u64 *out_next_level_block_number */
			!add_subnodes_in_offsets_order ? NULL:
			&next_level_block_number);
		if(err) {
			goto out;
		}

		if(!is_index_node) {
			if(leaf_entry_handler) {
				err = leaf_entry_handler(
					/* void *context */
					context,
					/* u8 *data */
					entry,
					/* u32 data_size */
					entry_size,
					/* u32 node_type */
					flags);
				if(err) {
					goto out;
				}
			}

			if(visitor && visitor->node_regular_entry) {
				err = visitor->node_regular_entry(
					/* void *context */
					visitor->context,
					/* const u8 *data */
					entry,
					/* size_t entry_size */
					entry_size);
				if(err) {
					goto out;
				}
			}
		}
		else if(add_subnodes_in_offsets_order) {
			/* Add the next level block number parsed from the value
			 * to the block queue. */
			sys_log_debug("next_level_block_number: %" PRIu64,
				PRAu64(next_level_block_number));
			if(next_level_block_number && block_queue) {
				err = block_queue_add(
					/* block_queue *block_queue */
					block_queue,
					/* u64 block_number */
					next_level_block_number);
				if(err) {
					goto out;
				}
			}
			else if(block_queue) {
				sys_log_warning("No next level block number "
					"found for index node entry.");
			}
		}

		value_offsets[cur_index] = cur_offset;
	}

	if((print_visitor && print_visitor->print_message) ||
		!add_subnodes_in_offsets_order)
	{
		/* We have already read the value offsets, now read each
		 * value in the order that it appears and advance pointer. */

		for(j = 0; j < values_count; ++j) {
			/* Look up the next offset in the value offsets
			 * array. */
			u32 entryno = 0;
			u16 smallest_matching_offset = 0;
			u32 smallest_matching_entryno = 0;
			u64 next_level_block_number = 0;

			for(entryno = 0; entryno < values_count; ++entryno) {
				const u16 cur_offset = value_offsets[entryno];

				if(cur_offset >= i &&
					(!smallest_matching_offset ||
					cur_offset < smallest_matching_offset))
				{
					smallest_matching_offset = cur_offset;
					smallest_matching_entryno = entryno;
				}
			}

			if(!smallest_matching_offset) {
				/* The offsets array was validated earlier, so
				 * this should not be possible. */
				sys_log_critical("Unexpected: No smallest "
					"matching offset found for "
					"%" PRIu32 ".",
					PRAu32(i));
				err = ENXIO;
			}

			if(i < smallest_matching_offset) {
				print_data_with_base(prefix, indent, i,
					block_size, &block[i],
					smallest_matching_offset - i);
			}

			i = smallest_matching_offset;
			entry = &block[i];
			entry_size = read_le32(entry);

			err = parse_generic_entry(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* u64 object_id */
				object_id,
				/* u32 block_index_unit */
				block_index_unit,
				/* sys_bool is_v3 */
				is_v3,
				/* sys_bool is_index */
				is_index_node,
				/* const u8 *entry */
				entry,
				/* u32 entry_size */
				entry_size,
				/* u16 entry_offset */
				i,
				/* u32 entry_index */
				2 + smallest_matching_entryno,
				/* void *context */
				context,
				/* int (*parse_key)(
				 *      refs_node_crawl_context *crawl_context,
				 *      refs_node_walk_visitor *visitor,
				 *      const char *prefix,
				 *      const size_t indent,
				 *      u64 object_id,
				 *      sys_bool is_v3,
				 *      sys_bool is_index,
				 *      const u8 *key,
				 *      u16 key_size,
				 *      u32 entry_size,
				 *      void *context) */
				parse_key,
				/* int (*parse_leaf_value)(
				 *      refs_node_walk_visitor *visitor,
				 *      const char *prefix,
				 *      const size_t indent,
				 *      u64 object_id,
				 *      u16 entry_offset,
				 *      u32 block_index_unit,
				 *      sys_bool is_v3,
				 *      const u8 *key,
				 *      u16 key_offset,
				 *      u16 key_size,
				 *      const u8 *value,
				 *      u16 value_size,
				 *      void *context) */
				parse_leaf_value,
				/* u64 *out_next_level_block_number */
				add_subnodes_in_offsets_order ? NULL:
				&next_level_block_number);
			if(err) {
				goto out;
			}

			if(is_index_node && !add_subnodes_in_offsets_order) {
				/* Add the next level block number parsed from
				 * the value to the block queue. */
				sys_log_debug("next_level_block_number: "
					"%" PRIu64,
					PRAu64(next_level_block_number));
				if(next_level_block_number && block_queue) {
					err = block_queue_add(
						/* block_queue *block_queue */
						block_queue,
						/* u64 block_number */
						next_level_block_number);
					if(err) {
						goto out;
					}
				}
				else if(block_queue) {
					sys_log_warning("No next level block "
						"number found for index node "
						"entry.");
				}
			}

			i += entry_size;

		}

		if(i < value_offsets_start_real) {
			print_data_with_base(prefix, indent, i, block_size,
				&block[i],
				value_offsets_start_real - i);
		}

		emit(prefix, indent, "Value offsets @ %" PRIu32 " / "
			"0x%" PRIX32 ":",
			PRAu32(value_offsets_start_real),
			PRAX32(value_offsets_start_real));
		i = value_offsets_start_real;
		for(; i < value_offsets_end_real; i += 4) {
			emit(prefix, indent + 1, "[%" PRIuz "] @ %" PRIu32 " / "
				"0x%" PRIX32 ": %" PRIu16 " / "
				"0x%" PRIX16 " (absolute: %" PRIu32 " / "
				"0x%" PRIX32 ") flags / unknown: "
				"0x%" PRIX16,
				PRAuz((i - value_offsets_start_real) /
				4),
				PRAu32(i),
				PRAX32(i),
				PRAu16(read_le16(&block[i])),
				PRAX16(read_le16(&block[i])),
				PRAu32(first_table_entry_end +
				read_le16(&block[i])),
				PRAX32(first_table_entry_end +
				read_le16(&block[i])),
				PRAX16(read_le16(&block[i + 2])));
		}
	}


	i = first_table_entry_end + value_offsets_end;
out:
	if(i < block_size) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			block_size - i);
	}

	if(value_offsets) {
		sys_free(&value_offsets);
	}

	return err;
}

static int parse_level2_0x2_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"object ID", PRAu16(key_offset), PRAX16(key_offset));

	if(key_size == 16 && read_le16(&key[0x0]) == 0x0) {
		print_le16_dechex("Key type", prefix, indent, key, &key[0x0]);
		print_unknown16(prefix, indent, key, &key[0x2]);
		print_unknown32(prefix, indent, key, &key[0x4]);
		print_le64_dechex("Object ID", prefix, indent, key, &key[0x8]);
	}
	else {
		print_data_with_base(prefix, indent, 0x0, 0, key, key_size);
	}

	return 0;
}

typedef struct {
	sys_bool is_mapping;
	union {
		struct {
			u64 block_number;
			u64 object_id;
		} mapping;
		block_queue *level3_block_queue;
	} u;
} level2_0x2_leaf_parse_context;

static int parse_level2_0x2_leaf_value(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const sys_bool is_v3,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		void *const _context)
{
	/* The 0x2 tree maps parent directory object IDs to their virtual
	 * block numbers (ReFS 3.x) / physical block numbers (ReFS 1.x).
	 * It's a flat mapping that doesn't reveal anything about the directory
	 * hierarchy. The hierarchy is mapped in the 0x3 tree. */

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	level2_0x2_leaf_parse_context *const context =
		(level2_0x2_leaf_parse_context*) _context;

	int err = 0;
	size_t i = 0x0;
	u64 block_number = 0;

	(void) key;
	(void) key_offset;
	(void) key_size;

	emit(prefix, indent - 1, "Value (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"directory node reference",
		PRAu16(value_offset),
		PRAX16(value_offset));

	if(is_v3 && value_size >= 0x20) {
		print_unknown64(prefix, indent, value, &value[0x0]);
		print_unknown32(prefix, indent, value, &value[0x8]);
		print_unknown32(prefix, indent, value, &value[0xC]);
		print_unknown32(prefix, indent, value, &value[0x10]);
		print_unknown32(prefix, indent, value, &value[0x14]);
		print_unknown32(prefix, indent, value, &value[0x18]);
		print_unknown32(prefix, indent, value, &value[0x1C]);
		i += 0x20;
	}

	if(value_size >= i + (is_v3 ? 0x30 : 0x18)) {
		block_number = read_le64(&value[i]);
		parse_extent(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* sys_bool is_v3 */
			is_v3,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *base */
			value,
			/* const u8 *data */
			&value[i]);

		i += (is_v3 ? 0x30 : 0x18);
	}

	if(value_size >= i + 0x18) {
		print_unknown64(prefix, indent, value, &value[i + 0x0]);
		print_unknown32(prefix, indent, value, &value[i + 0x8]);
		print_unknown32(prefix, indent, value, &value[i + 0xC]);
		print_unknown64(prefix, indent, value, &value[i + 0x10]);
		i += 0x18;
	}

	if(value_size > i) {
		print_data_with_base(prefix, indent, i, value_size,
			&value[i], value_size - i);
	}

	if(context) {
		if(context->is_mapping) {
			const u64 object_id =
				(key_size >= 0x10) ? read_le64(&key[0x8]) : 0;

			if(object_id &&
				context->u.mapping.object_id == object_id)
			{
				context->u.mapping.block_number = block_number;
			}
		}
		else if(context->u.level3_block_queue) {
			err = block_queue_add(
				/* block_queue *block_queue */
				context->u.level3_block_queue,
				/* u64 block_number */
				block_number);
		}
	}

	return err;
}

static int parse_level2_0x3_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"object ID pair", PRAu16(key_offset), PRAX16(key_offset));

	if(key_size == 32) {
		print_unknown64(prefix, indent, key, &key[0x0]);
		print_le64_dechex("Object ID", prefix, indent, key,
			&key[0x8]);
		print_unknown64(prefix, indent, key, &key[0x10]);
		print_le64_dechex("Next object ID?", prefix, indent, key,
			&key[0x18]);
	}
	else {
		print_data_with_base(prefix, indent, 0x0, 0, key, key_size);
	}

	return 0;
}

static int parse_level2_0x4_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"object ID", PRAu16(key_offset), PRAX16(key_offset));

	if(key_size == 16) {
		print_unknown64(prefix, indent, key, &key[0x0]);
		print_le64_dechex("Object ID", prefix, indent, key,
			&key[0x8]);
	}
	else {
		print_data_with_base(prefix, indent, 0x0, 0, key, key_size);
	}

	return 0;
}

static int parse_level2_0x3_leaf_value(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const sys_bool is_v3,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u32 entry_size,
		void *const context)
{
	/* The 0x3 tree maps parent directory object IDs to subdirectory object
	 * IDs. It describes the volume directory hierarchy without having to
	 * read the whole node contents.
	 * I'm not sure of the use case for this tree since you need to read the
	 * directory node to gain any useful info about the contents of the
	 * directory (lookups, directory listings). */
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	u16 i = 0;

	(void) object_id;
	(void) is_v3;
	(void) key_offset;
	(void) context;

	emit(prefix, indent - 1, "%s (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		(key == value && key_size == value_size) ? "Key/value" :
		"Value",
		"subdirectory object ID mapping", PRAu16(value_offset),
		PRAX16(value_offset));

	if(value_size >= 0x20) {
		i += print_unknown64(prefix, indent, value, &value[0x0]);
		i += print_le64_dechex("Parent directory object ID", prefix,
			indent, value, &value[0x8]);
		i += print_unknown64(prefix, indent, value, &value[0x10]);
		i += print_le64_dechex("Child directory object ID", prefix,
			indent, value, &value[0x18]);
	}

	if(i < value_size) {
		print_data_with_base(prefix, indent, i, entry_size, &value[i],
			value_size - i);
	}

	return 0;
}

static int parse_level2_0x4_leaf_value(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const sys_bool is_v3,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u32 entry_size,
		void *const context)
{
	/* The 0x3 tree maps object IDs to virtual block addresses in clusters
	 * of 4. The exact purpose is a bit unclear. */
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	u16 i = 0;

	(void) object_id;
	(void) is_v3;
	(void) key_offset;
	(void) context;

	emit(prefix, indent - 1, "%s (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		(key == value && key_size == value_size) ? "Key/value" :
		"Value", "unknown", PRAu16(value_offset), PRAX16(value_offset));

	if(value_size >= 0x8) {
		i += print_unknown64(prefix, indent, value, &value[0x0]);
	}
	if(value_size >= 0xC) {
		i += print_unknown32(prefix, indent, value, &value[0x8]);
	}
	if(value_size >= 0x10) {
		i += print_unknown32(prefix, indent, value, &value[0xC]);
	}
	if(value_size >= 0x18) {
		i += print_unknown64(prefix, indent, value, &value[0x10]);
	}
	if(value_size >= 0x20) {
		i += print_unknown64(prefix, indent, value, &value[0x18]);
	}
	if(value_size >= 0x28) {
		i += print_le64_dechex("Block number 1", prefix, indent, value,
			&value[0x20]);
	}
	if(value_size >= 0x30) {
		i += print_le64_dechex("Block number 2", prefix, indent, value,
			&value[0x28]);
	}
	if(value_size >= 0x38) {
		i += print_le64_dechex("Block number 3", prefix, indent, value,
			&value[0x30]);
	}
	if(value_size >= 0x40) {
		i += print_le64_dechex("Block number 4", prefix, indent, value,
			&value[0x38]);
	}
	if(value_size >= 0x44) {
		i += print_unknown32(prefix, indent, value, &value[0x40]);
	}
	if(value_size >= 0x48) {
		i += print_unknown32(prefix, indent, value, &value[0x44]);
	}
	if(value_size >= 0x50) {
		i += print_le64_hex("Checksum", prefix, indent, value,
			&value[0x48]);
	}
	if(value_size >= 0x58) {
		i += print_unknown64(prefix, indent, value, &value[0x50]);
	}

	if(i < value_size) {
		print_data_with_base(prefix, indent, i, entry_size, &value[i],
			value_size - i);
	}

	return 0;
}

static int parse_0xB_0xC_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const sys_bool is_v3,
		const sys_bool is_index,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u32 entry_size,
		void *const context)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	(void) object_id;
	(void) is_v3;
	(void) context;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		is_index ? "index" : "leaf", PRAu16(key_offset),
		PRAX16(key_offset));

	if(key_size >= 0x8) {
		print_unknown64(prefix, indent, key, &key[0x0]);
	}
	if(key_size >= 0xC) {
		print_unknown32(prefix, indent, key, &key[0x8]);
	}
	if(key_size >= 0x10) {
		print_unknown32(prefix, indent, key, &key[0xC]);
	}
	if(key_size > 0x10) {
		print_data_with_base(prefix, indent, 0x10, entry_size,
			&key[0x10], key_size - 0x10);
	}

	return 0;
}

static void parse_level2_block_0xB_0xC_table_leaf_value(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u32 entry_size,
		u64 *const out_block_range_start,
		u64 *const out_block_range_length)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	u16 i = 0;

	emit(prefix, indent - 1, "Value (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"leaf", PRAu16(value_offset), PRAX16(value_offset));

	print_unknown64(prefix, indent, value, &value[0x0]);
	print_unknown32(prefix, indent, value, &value[0x8]);
	print_unknown32(prefix, indent, value, &value[0xC]);
	print_unknown32(prefix, indent, value, &value[0x10]);
	print_unknown32(prefix, indent, value, &value[0x14]);
	print_unknown64(prefix, indent, value, &value[0x18]);
	print_unknown64(prefix, indent, value, &value[0x20]);
	print_unknown64(prefix, indent, value, &value[0x28]);
	print_unknown32(prefix, indent, value, &value[0x30]);
	print_unknown32(prefix, indent, value, &value[0x34]);

	i = 0x40;

	if(value_size >= 0x50) {
		print_unknown64(prefix, indent, value, &value[0x40]);
		print_unknown32(prefix, indent, value, &value[0x48]);
		print_unknown32(prefix, indent, value, &value[0x4C]);

		i = 0x50;

		if(value_size - i > 0x10) {
			print_data_with_base(prefix, indent, i, value_size,
				&value[i], (value_size - i) - 0x10);
			print_le64_dechex("Block range start", prefix, indent,
				value, &value[value_size - 0x10]);
			if(out_block_range_start) {
				*out_block_range_start =
					read_le64(&value[value_size - 0x10]);
			}
			print_le64_dechex("Block range length", prefix, indent,
				value, &value[value_size - 0x8]);
			if(out_block_range_length) {
				*out_block_range_length =
					read_le64(&value[value_size - 0x8]);
			}
			i = value_size;
		}
	}

	if(i < value_size) {
		print_data_with_base(prefix, indent, i, entry_size, &value[i],
			value_size - i);
	}
}

static int parse_level2_block_0xB_0xC_leaf_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u16 entry_offset,
		const u32 entry_size,
		void *const context)
{
#if 0
	const u32 block_index_unit = crawl_context->block_index_unit;
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
#endif
	block_range *const range = (block_range*) context;

	int err = 0;

	(void) crawl_context;
	(void) object_id;
	(void) key;
	(void) key_offset;
	(void) key_size;
	(void) entry_offset;

	parse_level2_block_0xB_0xC_table_leaf_value(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const char *prefix */
		prefix,
		/* size_t indent */
		indent,
		/* const u8 *value */
		value,
		/* u16 value_offset */
		value_offset,
		/* u16 value_size */
		value_size,
		/* u32 entry_size */
		entry_size,
		/* u64 *out_block_range_start */
		range ? &range->start : NULL,
		/* u64 *out_block_range_length */
		range ? &range->length : NULL);

	return err;
}

static int parse_level2_0xB_leaf_value_add_mapping(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u16 entry_offset,
		const u32 entry_size,
		void *const context)
{
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	refs_block_map *const mappings = (refs_block_map*) context;

	int err = 0;
	block_range leaf_range;

	(void) object_id;
	(void) key_offset;
	(void) is_v3;
	(void) key;
	(void) key_size;
	(void) entry_offset;

	memset(&leaf_range, 0, sizeof(leaf_range));

	parse_level2_block_0xB_0xC_table_leaf_value(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const char *prefix */
		prefix,
		/* size_t indent */
		indent,
		/* const u8 *value */
		value,
		/* u16 value_offset */
		value_offset,
		/* u16 value_size */
		value_size,
		/* u32 entry_size */
		entry_size,
		/* u64 *out_block_range_start */
		&leaf_range.start,
		/* u64 *out_block_range_length */
		&leaf_range.length);

	{
		/* If this is a leaf node in the 0xB
		 * table, then add the leaf entries to
		 * the mapping table. */
		block_range *new_mapping_table_entries = NULL;

		err = sys_realloc(
			mappings->entries,
			(mappings->length + 1) * sizeof(mappings->entries[0]),
			&new_mapping_table_entries);
		if(err) {
			goto out;
		}

		new_mapping_table_entries[mappings->length] = leaf_range;

		mappings->entries = new_mapping_table_entries;
		++mappings->length;
	}
out:
	return err;
}

#if 0
static int parse_level2_block_0xD_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const size_t key_size)
{

	return 0;
}

static int parse_level2_block_0xD_table_entry(
		refs_node_walk_visitor *const visitor,
		const u8 *const entry,
		const u32 entry_size,
		const u32 entry_offset,
		const u32 entry_index)
{
	static const char *const prefix = "\t";

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;

	if(entry_size != 200) {
		sys_log_warning("Unexpected size for 0xD entry: %" PRIu32 " "
			"Printing raw data...", PRAu32(entry_size));
		parse_level2_block_unknown_table_entry(
			visitor,
			entry,
			entry_size,
			entry_offset,
			entry_index);
		goto out;
	}

	emit("%sEntry %" PRIu32 " (%s) @ %" PRIu32 " / 0x%" PRIX32 ":",
		prefix,
		PRAu32(entry_index),
		"regular entry",
		PRAu32(entry_offset),
		PRAX32(entry_offset));
	emit("%s\tSize: %" PRIu64 " / 0x%" PRIX64,
		prefix,
		PRAu64(entry_size),
		PRAX64(entry_size));
	print_le16_dechex("Key offset", prefix, "\t", entry, &entry[0x4]);
	print_le16_dechex("Key size", prefix, "\t", entry, &entry[0x6]);
	print_le16_dechex("Flags?", prefix, "\t", entry, &entry[0x8]);
	print_le16_dechex("Value offset", prefix, "\t", entry, &entry[0xA]);
	print_le16_dechex("Value size", prefix, "\t", entry, &entry[0xC]);
	print_unknown16(prefix, "\t", entry, &entry[0xE]);
	print_unknown32(prefix, "\t", entry, &entry[0xC]);
	print_unknown64(prefix, "\t", entry, &entry[0x10]);
	print_unknown64(prefix, "\t", entry, &entry[0x18]);
	print_unknown32(prefix, "\t", entry, &entry[0x20]);
	print_unknown32(prefix, "\t", entry, &entry[0x24]);
	print_unknown32(prefix, "\t", entry, &entry[0x28]);
	print_unknown32(prefix, "\t", entry, &entry[0x2C]);
	print_unknown32(prefix, "\t", entry, &entry[0x30]);
	print_unknown32(prefix, "\t", entry, &entry[0x34]);
	print_unknown64(prefix, "\t", entry, &entry[0x38]);
	print_unknown32(prefix, "\t", entry, &entry[0x40]);
	print_unknown32(prefix, "\t", entry, &entry[0x44]);

	print_data_with_base(prefix, "\t", 0x48, 0, &entry[0x48],
		entry_size - 0x48);
out:
	return err;
}

static int parse_level2_block_0xE_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const size_t key_size)
{

	return 0;
}

static int parse_level2_block_0xE_table_entry(
		refs_node_walk_visitor *const visitor,
		const size_t indent,
		const u8 *const entry,
		const u32 entry_size,
		const u32 entry_offset,
		const u32 entry_index)
{
	static const char *const prefix = "\t";

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;

	if(entry_size != 88) {
		sys_log_warning("Unexpected size for 0xE entry: %" PRIu32 " "
			"Printing raw data...", PRAu32(entry_size));
		parse_level2_block_unknown_table_entry(
			visitor,
			entry,
			entry_size,
			entry_offset,
			entry_index);
		goto out;
	}

	emit(prefix, 0, "Entry %" PRIu32 " (%s) @ %" PRIu32 " / "
		"0x%" PRIX32 ":",
		PRAu32(entry_index),
		"regular entry",
		PRAu32(entry_offset),
		PRAX32(entry_offset));
	emit(prefix, indent, "Size: %" PRIu64 " / 0x%" PRIX64,
		PRAu64(entry_size),
		PRAX64(entry_size));
	print_le16_dechex("Key offset", prefix, indent, entry, &entry[0x4]);
	print_le16_dechex("Key size", prefix, indent, entry, &entry[0x6]);
	print_le16_dechex("Flags?", prefix, indent, entry, &entry[0x8]);
	print_le16_dec("Value offset", prefix, indent, entry, &entry[0xA]);
	print_le16_dec("Value size", prefix, indent, entry, &entry[0xC]);
	print_unknown16(prefix, indent, entry, &entry[0xE]);
	print_unknown64(prefix, indent, entry, &entry[0x10]);
	/* This field has the value 0x4D000 / 315392, which is pretty close to
	 * the max number of metadata blocks for a 5232394240 B volume. This may
	 * be coincidental. */
	print_unknown64(prefix, indent, entry, &entry[0x18]);
	print_unknown32(prefix, indent, entry, &entry[0x20]);
	print_unknown32(prefix, indent, entry, &entry[0x24]);
	print_unknown32(prefix, indent, entry, &entry[0x28]);
	print_unknown32(prefix, indent, entry, &entry[0x2C]);
	print_unknown32(prefix, indent, entry, &entry[0x30]);
	print_unknown32(prefix, indent, entry, &entry[0x34]);
	print_unknown64(prefix, indent, entry, &entry[0x38]);
	print_unknown32(prefix, indent, entry, &entry[0x40]);
	print_unknown32(prefix, indent, entry, &entry[0x44]);
	print_unknown64(prefix, indent, entry, &entry[0x48]);
	print_unknown64(prefix, indent, entry, &entry[0x50]);
out:
	return err;
}
#endif

static int parse_level2_0x21_leaf_value(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const sys_bool is_v3,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u32 entry_size,
		void *const context)
{
	/* The 0x21 tree maps something to virtual block addresses in clusters
	 * of 4. The exact purpose is a bit unclear. */
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	u16 i = 0;

	(void) is_v3;
	(void) object_id;
	(void) key_offset;
	(void) context;

	emit(prefix, indent - 1, "%s (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		(key == value && key_size == value_size) ? "Key/value" :
		"Value", "unknown", PRAu16(value_offset), PRAX16(value_offset));

	if(value_size >= 0x8) {
		i += print_le64_dechex("Block number 1", prefix, indent, value,
			&value[0x0]);
	}
	if(value_size >= 0x10) {
		i += print_le64_dechex("Block number 2", prefix, indent, value,
			&value[0x8]);
	}
	if(value_size >= 0x18) {
		i += print_le64_dechex("Block number 3", prefix, indent, value,
			&value[0x10]);
	}
	if(value_size >= 0x20) {
		i += print_le64_dechex("Block number 4", prefix, indent, value,
			&value[0x18]);
	}
	if(value_size >= 0x24) {
		i += print_unknown32(prefix, indent, value, &value[0x20]);
	}
	if(value_size >= 0x28) {
		i += print_unknown32(prefix, indent, value, &value[0x24]);
	}
	if(value_size >= 0x30) {
		i += print_le64_hex("Checksum", prefix, indent, value,
			&value[0x28]);
	}

	if(i < value_size) {
		print_data_with_base(prefix, indent, i, entry_size, &value[i],
			value_size - i);
	}

	return 0;
}

#if 0
static int parse_level2_block_0x22_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const size_t key_size)
{

	return 0;
}

static int parse_level2_block_0x22_table_entry(
		refs_node_walk_visitor *const visitor,
		const size_t indent,
		const u8 *const entry,
		const u32 entry_size,
		const u32 entry_offset,
		const u32 entry_index)
{
	static const char *const prefix = "\t";

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;

	emit(prefix, indent - 1, "Entry %" PRIu32 " (%s) @ %" PRIu32 " / "
		"0x%" PRIX32 ":",
		PRAu32(entry_index),
		"regular entry",
		PRAu32(entry_offset),
		PRAX32(entry_offset));
	emit(prefix, indent, "Size: %" PRIu64 " / 0x%" PRIX64,
		PRAu64(entry_size),
		PRAX64(entry_size));

	if(entry_size >= 0x30) {
		print_le16_dechex("Key offset", prefix, indent, entry,
			 &entry[0x4]);
		print_le16_dechex("Key size", prefix, indent, entry,
			&entry[0x6]);
		print_le16_dechex("Flags?", prefix, indent, entry,
			&entry[0x8]);
		print_le16_dechex("Value offset", prefix, indent, entry,
			&entry[0xA]);
		print_le16_dechex("Value size", prefix, indent, entry,
			&entry[0xC]);
		print_unknown16(prefix, indent, entry, &entry[0xA]);
		print_unknown32(prefix, indent, entry, &entry[0xC]);
		print_unknown64(prefix, indent, entry, &entry[0x10]);
		print_unknown64(prefix, indent, entry, &entry[0x18]);
		print_unknown16(prefix, indent, entry, &entry[0x20]);
		print_unknown16(prefix, indent, entry, &entry[0x22]);
		print_unknown16(prefix, indent, entry, &entry[0x24]);
		print_unknown16(prefix, indent, entry, &entry[0x26]);
		print_unknown32(prefix, indent, entry, &entry[0x28]);
		print_unknown32(prefix, indent, entry, &entry[0x2C]);
		if(entry_size > 0x30) {
			print_data_with_base(prefix, indent, 0x30, entry_size,
				&entry[0x30], entry_size - 0x30);
		}
	}
	else {
		sys_log_warning("Unexpected size for 0x22 entry: %" PRIu32 " "
			"Printing raw data...", PRAu32(entry_size));
		parse_level2_block_unknown_table_entry(
			visitor,
			indent,
			entry,
			entry_size,
			entry_offset,
			entry_index);
		goto out;
	}
out:
	return err;
}
#endif

static int parse_level2_key(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const sys_bool is_v3,
		const sys_bool is_index,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u32 entry_size,
		void *const context)
{
	int err = 0;

	(void) crawl_context;

	if(object_id == 0x2) {
		err = parse_level2_0x2_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size);
	}
	else if(object_id == 0x3) {
		err = parse_level2_0x3_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size);
	}
	else if(object_id == 0x4) {
		err = parse_level2_0x4_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size);
	}
	else if(object_id == 0xB) {
		err = parse_0xB_0xC_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* sys_bool is_v3 */
			is_v3,
			/* sys_bool is_index */
			is_index,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
	else if(object_id == 0xC) {
		err = parse_0xB_0xC_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* sys_bool is_v3 */
			is_v3,
			/* sys_bool is_index */
			is_index,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
#if 0
	else if(object_id == 0xD) {
		err = parse_level2_block_0xD_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size);
	}
	else if(object_id == 0xE) {
		err = parse_level2_block_0xE_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size);
	}
	else if(object_id == 0x22) {
		err = parse_level2_block_0x22_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size);
	}
#endif
	else {
		err = parse_unknown_key(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* sys_bool is_v3 */
			is_v3,
			/* sys_bool is_index */
			is_index,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}

	return err;
}

static int parse_level2_leaf_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u16 entry_offset,
		const u32 entry_size,
		void *const context)
{
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;

	int err = 0;

	if(object_id == 0x2) {
		err = parse_level2_0x2_leaf_value(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* void *context */
			context);
	}
	else if(object_id == 0x3) {
		err = parse_level2_0x3_leaf_value(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
	else if(object_id == 0x4) {
		err = parse_level2_0x4_leaf_value(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
	else if(object_id == 0xB) {
		err = parse_level2_block_0xB_0xC_leaf_value(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u16 entry_offset */
			entry_offset,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
	else if(object_id == 0xC) {
		err = parse_level2_block_0xB_0xC_leaf_value(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u16 entry_offset */
			entry_offset,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
#if 0
	else if(object_id == 0xD) {
		err = parse_level2_block_0xD_value(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* u32 block_index_unit */
			block_index_unit,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
	else if(object_id == 0xE) {
		err = parse_level2_block_0xE_value(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* u32 block_index_unit */
			block_index_unit,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
#endif
	else if(object_id == 0x21) {
		err = parse_level2_0x21_leaf_value(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
#if 0
	else if(object_id == 0x22) {
		err = parse_level2_block_0x22_value(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* u32 block_index_unit */
			block_index_unit,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
#endif
	else {
		err = parse_unknown_leaf_value(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 object_id */
			object_id,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u16 entry_offset */
			entry_offset,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}

	return err;
}

static int parse_level2_block(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const u64 cluster_number,
		const u64 block_number,
		const u64 block_queue_index,
		const u8 *const block,
		const u32 block_size,
		u64 *const object_id_mapping,
		sys_bool *const object_id_mapping_found,
		u64 **const level2_queue,
		size_t *const level2_queue_length,
		u64 **const level3_queue,
		size_t *const level3_queue_length)
{
	int err = 0;
	block_queue level2_block_queue;
	block_queue level3_block_queue;
	sys_bool is_valid = SYS_FALSE;
	sys_bool is_v3 = SYS_FALSE;
	u64 object_id = 0;
	level2_0x2_leaf_parse_context context;

	memset(&level2_block_queue, 0, sizeof(level2_block_queue));
	memset(&level3_block_queue, 0, sizeof(level3_block_queue));
	memset(&context, 0, sizeof(context));

	err = parse_block_header(
		/* refs_node_walk_visitor *visitor */
		NULL,
		/* const char *prefix */
		"",
		/* size_t indent */
		0,
		/* u8 level */
		2,
		/* const u8 *block */
		block,
		/* u32 block_size */
		block_size,
		/* u64 cluster_number */
		cluster_number,
		/* u64 block_number */
		block_number,
		/* u64 block_queue_index */
		block_queue_index,
		/* sys_bool *out_is_valid */
		&is_valid,
		/* sys_bool *out_is_v3 */
		&is_v3,
		/* u32 *out_header_size */
		NULL,
		/* u64 *out_object_id */
		&object_id);
	if(err || !is_valid) {
		goto out;
	}

	level2_block_queue.block_numbers = *level2_queue;
	level2_block_queue.block_queue_length = *level2_queue_length;
	level2_block_queue.elements_per_entry = is_v3 ? 6 : 3;

	if(level3_queue) {
		level3_block_queue.block_numbers = *level3_queue;
		level3_block_queue.block_queue_length = *level3_queue_length;
		level3_block_queue.elements_per_entry = 1;
	}

	if(object_id_mapping) {
		context.is_mapping = SYS_TRUE;
		context.u.mapping.object_id = *object_id_mapping;
	}
	else {
		context.is_mapping = SYS_FALSE;
		context.u.level3_block_queue = &level3_block_queue;
	}

	err = parse_generic_block(
		/* refs_node_crawl_context *crawl_context */
		crawl_context,
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* size_t indent */
		0,
		/* u64 cluster_number */
		cluster_number,
		/* u64 block_number */
		block_number,
		/* u64 block_queue_index */
		block_queue_index,
		/* u8 level */
		2,
		/* const u8 *block */
		block,
		/* u32 block_size */
		block_size,
		/* block_queue *block_queue */
		(object_id != 0xB && object_id != 0xC) ? &level2_block_queue :
		NULL,
		/* sys_bool add_subnodes_in_offsets_order */
		SYS_TRUE,
		/* void *context */
		(object_id == 0x2) ? &context : NULL,
		/* int (*parse_key)(
		 *      refs_node_crawl_context *crawl_context,
		 *      refs_node_walk_visitor *visitor,
		 *      const char *prefix,
		 *      size_t indent,
		 *      u64 object_id,
		 *      sys_bool is_v3,
		 *      sys_bool is_index,
		 *      const u8 *key,
		 *      u16 key_offset,
		 *      u16 key_size,
		 *      u32 entry_size,
		 *      void *context) */
		parse_level2_key,
		/* int (*parse_leaf_value)(
		 *      refs_node_crawl_context *crawl_context,
		 *      refs_node_walk_visitor *visitor,
		 *      const char *prefix,
		 *      size_t indent,
		 *      u64 object_id,
		 *      const u8 *key,
		 *      u16 key_size,
		 *      const u8 *value,
		 *      u16 value_offset,
		 *      u16 value_size,
		 *      u16 entry_offset,
		 *      u32 entry_size,
		 *      void *context) */
		parse_level2_leaf_value,
		/* int (*leaf_entry_handler)(
		 *      void *context,
		 *      const u8 *data,
		 *      u32 data_size,
		 *      u32 node_type) */
		NULL);
	if(err) {
		goto out;
	}

	{
		size_t i;

		sys_log_debug("Level 2 block queue after processing block "
			"(%" PRIuz " elements):",
			PRAuz(level2_block_queue.block_queue_length));
		for(i = 0; i < level2_block_queue.block_queue_length; ++i) {
			sys_log_debug("\t[%" PRIuz "]: %" PRIu64,
				PRAuz(i),
				PRAu64(level2_block_queue.block_numbers[i *
				level2_block_queue.elements_per_entry]));
		}
	}

	if(level3_queue) {
		size_t i;

		sys_log_debug("Level 3 block queue after processing block "
			"(%" PRIuz " elements):",
			PRAuz(level3_block_queue.block_queue_length));
		for(i = 0; i < level3_block_queue.block_queue_length; ++i) {
			sys_log_debug("\t[%" PRIuz "]: %" PRIu64,
				PRAuz(i),
				PRAu64(level3_block_queue.block_numbers[i *
				level3_block_queue.elements_per_entry]));
		}
	}

	if(object_id_mapping && context.u.mapping.block_number) {
		*object_id_mapping = context.u.mapping.block_number;
		*object_id_mapping_found = SYS_TRUE;
	}

	*level2_queue = level2_block_queue.block_numbers;
	*level2_queue_length = level2_block_queue.block_queue_length;
	if(level3_queue) {
		*level3_queue = level3_block_queue.block_numbers;
		*level3_queue_length = level3_block_queue.block_queue_length;
	}
out:
	return err;
}

#if 0
static size_t parse_level3_extent_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const size_t key_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	size_t i = 0;

	if(key_size < 0xE) {
		return 0;
	}

	i += print_unknown64(prefix, indent, key, &key[0x0]);
	i += print_unknown32(prefix, indent, key, &key[0x8]);
	i += print_unknown16(prefix, indent, key, &key[0xC]);

	return i;
}

static size_t parse_level3_extent_value(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u32 block_index_unit,
		const sys_bool is_v3,
		const u8 *const value,
		const size_t value_size,
		u64 *const out_first_block,
		u64 *const out_block_count)
{
	const size_t block_count_offset = (is_v3 ? 0xE4 : 0xE0) - 0x10;
	const size_t first_block_offset = (is_v3 ? 0xD0 : 0xE8) - 0x10;

	u64 first_block = 0;
	u64 block_count = 0;

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	size_t i = 0;

	if(value_size < 0x4E - 0x10) {
		return 0;
	}

	i += print_unknown32(prefix, indent, value, &value[i]); /* 0x10 */
	i += print_unknown32(prefix, indent, value, &value[i]); /* 0x14 */
	i += print_unknown32(prefix, indent, value, &value[i]); /* 0x18 */
	i += print_unknown32(prefix, indent, value, &value[i]); /* 0x1C */
	i += print_unknown32(prefix, indent, value, &value[i]); /* 0x20 */
	i += print_unknown32(prefix, indent, value, &value[i]); /* 0x24 */
	i += print_unknown64(prefix, indent, value, &value[i]); /* 0x28 */
	i += print_unknown64(prefix, indent, value, &value[i]); /* 0x30 */
	i += print_unknown64(prefix, indent, value, &value[i]); /* 0x38 */
	i += print_unknown32(prefix, indent, value, &value[i]); /* 0x40 */
	i += print_unknown16(prefix, indent, value, &value[i]); /* 0x44 */

	if(i + 2 <= value_size) {
		i += print_le16_dechex("Number of clusters", prefix, indent,
			value, &value[i]); /* 0x46 */
	}
	/* 0x48:
	 * After this, the first block offset and the block count offset
	 * will differ depending on whether it's v1 or v3 and they won't even
	 * appear in the same order, so the code to print them is a bit
	 * convoluted. */
	if(i < value_size) {
		const size_t data_size =
			sys_min(value_size,
			sys_min(block_count_offset, first_block_offset)) - i;
		print_data_with_base(prefix, indent, i,
			value_size,
			&value[i], data_size);
		i += data_size;
	}
	if(block_count_offset < first_block_offset && i + 8 <= value_size) {
		block_count = read_le64(&value[block_count_offset]);
		emit(prefix, indent, "Block count @ %" PRIuz " / "
			"0x%" PRIXz ": %" PRIu64 " / 0x%" PRIX64 " "
			"(%" PRIu64 " bytes)",
			PRAuz(i),
			PRAXz(i),
			PRAu64(block_count),
			PRAX64(block_count),
			PRAu64(block_count * block_index_unit));
		i += 8;
	}
	if(i < first_block_offset) {
		print_data_with_base(prefix, indent, i, value_size,
			&value[i], first_block_offset - i);
		i = first_block_offset;
	}
	if(i + 8 <= value_size) {
		first_block = read_le64(&value[first_block_offset]);
		emit(prefix, indent, "First block @ %" PRIuz " / 0x%" PRIXz ": "
			"%" PRIu64 " / 0x%" PRIX64 " (%" PRIu64 " bytes)",
			PRAuz(i),
			PRAXz(i),
			PRAu64(first_block),
			PRAX64(first_block),
			PRAu64(first_block * block_index_unit));
		i += 8;
	}
	if(i < block_count_offset) {
		print_data_with_base(prefix, indent, i, value_size,
			&value[i], block_count_offset - i);
		i = block_count_offset;
	}
	if(block_count_offset > first_block_offset && i + 8 <= value_size) {
		block_count = read_le32(&value[block_count_offset]);
		emit(prefix, indent, "Block count @ %" PRIuz " / "
			"0x%" PRIXz ": %" PRIu32 " / 0x%" PRIX32 " "
			"(%" PRIu64 " bytes)",
			PRAuz(i),
			PRAXz(i),
			PRAu32(block_count),
			PRAX32(block_count),
			PRAu64(((u64) block_count) * block_index_unit));
		i += 4;
	}

	*out_first_block = first_block;
	*out_block_count = block_count;

	return i;
}

static size_t parse_level3_extent_attribute(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u32 block_index_unit,
		const sys_bool is_v3,
		const u8 *const attribute,
		const size_t attribute_size,
		u64 *const out_first_block,
		u64 *const out_block_count)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	size_t i = 0x8;

	if(attribute_size < 0x56) {
		return 0;
	}

	i += parse_level3_extent_key(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const char *prefix */
		prefix,
		/* size_t indent */
		indent,
		/* const u8 *key */
		&attribute[0x10],
		/* size_t key_size */
		attribute_size - 0x10);

	/* XXX: This might be padding between key and value. */
	i += print_unknown16(prefix, indent, attribute, &attribute[0x1E]);

	i += parse_level3_extent_value(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const char *prefix */
		prefix,
		/* size_t indent */
		indent,
		/* u32 block_index_unit */
		block_index_unit,
		/* sys_bool is_v3 */
		is_v3,
		/* const u8 *value */
		&attribute[0x20],
		/* size_t value_size */
		attribute_size - 0x20,
		/* u64 *out_first_block */
		out_first_block,
		/* u64 *out_block_count */
		out_block_count);

	return i;
}
#endif

static int parse_level3_filename_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u16 dirent_type = 0;
	char *cstr = NULL;
	size_t cstr_length = 0;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"filename", PRAu16(key_offset), PRAX16(key_offset));

	print_le16_dechex("Key type", prefix, indent, key, &key[0]);
	dirent_type = read_le16(&key[2]);
	emit(prefix, indent, "Dirent type: 0x%" PRIX64 " (%s)",
		PRAX64(dirent_type),
		entry_type_to_string(dirent_type));

	err = sys_unistr_decode(
		(const refschar*) &key[4],
		(key_size - 4) / sizeof(refschar),
		&cstr,
		&cstr_length);
	if(err) {
		goto out;
	}

	emit(prefix, indent, "Filename: %" PRIbs,
		PRAbs(cstr_length, cstr));
out:
	if(cstr) {
		sys_free(&cstr);
	}

	return err;
}

static int parse_level3_object_id_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		void *const context)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;

	(void) key_size;
	(void) context;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"object ID", PRAu16(key_offset), PRAX16(key_offset));

	print_le16_dechex("Key type", prefix, indent, key, &key[0]);
	print_unknown16(prefix, indent, key, &key[2]);
	print_unknown32(prefix, indent, key, &key[4]);
	print_le64_dechex("Object ID", prefix, indent, key, &key[8]);

	return err;
}

static int parse_level3_hardlink_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		void *const context)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	size_t i = 0;

	(void) context;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"hard link", PRAu16(key_offset), PRAX16(key_offset));

	i += print_le16_dechex("Key type", prefix, indent, key, &key[i]);
	i += print_unknown16(prefix, indent, key, &key[i]);
	i += print_unknown32(prefix, indent, key, &key[i]);
	i += print_le64_dechex("Hard link ID", prefix, indent, key, &key[i]);
	i += print_le64_dechex("Parent directory ID", prefix, indent, key,
		&key[i]);

	if(i < key_size) {
		print_data_with_base(prefix, indent, i, key_size, &key[i],
			key_size - i);
		i = key_size;
	}

	return err;
}

static int parse_level3_reparse_point_key(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		void *const context)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	size_t i = 0;

	(void) context;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"reparse point", PRAu16(key_offset), PRAX16(key_offset));

	i += print_le16_dechex("Key type", prefix, indent, key, &key[i]);
	i += print_unknown16(prefix, indent, key, &key[i]);

	if(i < key_size) {
		print_data_with_base(prefix, indent, i, key_size, &key[i],
			key_size - i);
		i = key_size;
	}

	return err;
}

static int parse_level3_unknown_key(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u32 entry_size,
		void *const context)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;

	(void) crawl_context;
	(void) context;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"unknown", PRAu16(key_offset), PRAX16(key_offset));

	print_le16_dechex("Key type", prefix, indent, key, &key[0]);
	emit(prefix, indent, "Key data:");
	print_data_with_base(prefix, indent, 0, entry_size, key, key_size);

	return err;
}

static int parse_level3_key(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const sys_bool is_v3,
		const sys_bool is_index,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u32 entry_size,
		void *const context)
{
	int err = 0;

	(void) object_id;
	(void) is_v3;
	(void) is_index;

	if(key_size > 4 && key[0] == 0x30 && key[1] == 0x00) {
		err = parse_level3_filename_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size);
	}
	else if(key_size == 16 && read_le64(&key[0]) == 0x0) {
		err = parse_level3_object_id_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* void *context */
			context);
	}
	else if(key_size >= 24 && read_le16(&key[0]) == 0x40) {
		err = parse_level3_hardlink_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* void *context */
			context);
	}
	else if(key_size >= 4 && read_le16(&key[0]) == 0x10) {
		err = parse_level3_reparse_point_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* void *context */
			context);
	}
	else {
		err = parse_level3_unknown_key(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_offset */
			key_offset,
			/* u16 key_size */
			key_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}

	return err;
}

static int parse_attribute_data_key(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const key,
		const u16 key_size,
		u16 *const jp)
{
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 j_start = *jp;
	const u16 key_end = j_start + key_size;

	u16 j = j_start;

	/* v1/v3: 0x10 */
	if(j + 8 <= key_end) {
		j += print_unknown64(prefix, indent, key, &key[j]);
	}
	/* v1/v3: 0x18 */
	if(is_v3 && j + 2 <= key_end) {
		j += print_unknown16(prefix, indent, key, &key[j]);
	}
	/* v1/v3: 0x1A */
	if(is_v3 && j + 2 <= key_end) {
		j += print_unknown16(prefix, indent, key, &key[j]);
	}
	/* v1: 0x18 v3: 0x1C */
	if(j + 2 <= key_end) {
		j += print_le16_hex("Attribute type (unnamed $DATA)", prefix,
			indent, key, &key[j]);
	}
	/* v1: 0x1A */
	if(!is_v3 && j + 2 <= key_end) {
		j += print_unknown16(prefix, indent, key, &key[j]);
	}
	/* v1: 0x1C */
	if(!is_v3 && j + 2 <= key_end) {
		j += print_unknown16(prefix, indent, key, &key[j]); /* 0x1A */
	}
	/* v1/v3: 0x1E */
	if(j + 2 <= key_end) {
		j += print_unknown16(prefix, indent, key, &key[j]); /* 0x1E */
	}
	if(is_v3 && j + 8 <= key_end) {
		j += print_unknown64(prefix, indent, key, &key[j]); /* 0x20 */
	}
	if(is_v3 && j + 8 <= key_end) {
		j += print_unknown64(prefix, indent, key, &key[j]); /* 0x28 */
	}
	if(is_v3 && j + 8 <= key_end) {
		j += print_unknown64(prefix, indent, key, &key[j]); /* 0x30 */
	}

	*jp = j;

	return 0;
}

static int parse_attribute_ea_key(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const data,
		const u16 key_size,
		u16 *const jp)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 j_start = *jp;
	const u16 key_end = j_start + key_size;

	u16 j = j_start;

	(void) crawl_context;

	/* 0x10 */
	if(key_end - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x14 */
	if(key_end - j >= 2) {
		j += print_unknown16(prefix, indent, data, &data[j]);
	}
	/* 0x16 */
	if(key_end - j >= 2) {
		j += print_unknown16(prefix, indent, data, &data[j]);
	}
	/* 0x18 */
	if(key_end - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x1C */
	if(key_end - j >= 4) {
		j += print_le16_dechex("Stream type ($EA)", prefix, indent,
			data, &data[j]);
	}
	/* 0x1E */
	if(key_end - j >= 2) {
		j += print_unknown16(prefix, indent, data, &data[j]);
	}

	*jp = j;

	return 0;
}

static int parse_attribute_named_stream_key(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const attribute,
		const u16 key_size,
		u16 *const jp,
		char **const out_cstr,
		size_t *const out_cstr_length)
{
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 j_start = *jp;
	const u16 key_end = j_start + key_size;
	const u16 name_start = j_start + (is_v3 ? 0x10 : 0xC);

	int err = 0;
	u16 j = j_start;
	char *cstr = NULL;
	size_t cstr_length = 0;

	/* 0x00 */
	if(key_end - j >= 4) {
		j += print_le32_dechex("Value size (2)", prefix, indent,
			attribute, &attribute[j]);
	}
	/* 0x04 */
	if(key_end - j >= 2) {
		j += print_unknown16(prefix, indent, attribute,
			&attribute[j]);
	}
	/* 0x06 */
	if(key_end - j >= 2) {
		j += print_unknown16(prefix, indent, attribute,
			&attribute[j]);
	}
	/* 0x08 */
	if(is_v3 && key_end - j >= 4) {
		j += print_unknown32(prefix, indent, attribute,
			&attribute[j]);
	}
	/* 0x0C */
	if(key_end - j >= 4) {
		j += print_le16_dechex("Stream type (named $DATA)",
			prefix, indent, attribute, &attribute[j]);
	}
	/* 0x0E */
	if(key_end - j >= 2) {
		j += print_unknown16(prefix, indent, attribute, &attribute[j]);
	}

	if(j < name_start) {
		const u32 print_end = sys_min(name_start, key_end);

		print_data_with_base(prefix, indent, j, print_end,
			&attribute[j], print_end - j);
		j = print_end;
	}

	if(key_end >= name_start) {
		err = sys_unistr_decode(
			/* const refschar *ins */
			(const refschar*) &attribute[name_start],
			/* size_t ins_len */
			(key_end - name_start) / sizeof(refschar),
			/* char **outs */
			&cstr,
			/* size_t *outs_len */
			&cstr_length);
		if(err) {
			sys_log_perror(err, "Error while decoding stream name");
			goto out;
		}

		emit(prefix, indent, "Name @ %" PRIuz " / 0x%" PRIXz " "
			"(length: %" PRIuz "):",
			PRAuz(j), PRAXz(j), PRAuz(cstr_length));
		emit(prefix, indent + 1, "%" PRIbs, PRAbs(cstr_length, cstr));
		j += key_end - name_start;
	}

	*jp = j;

	if(out_cstr) {
		*out_cstr = cstr;
		cstr = NULL;
	}

	if(out_cstr_length) {
		*out_cstr_length = cstr_length;
	}
out:
	if(cstr) {
		sys_free(&cstr);
	}

	return err;
}

static int parse_attribute_named_stream_extent_key(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const data,
		const u16 key_size,
		u16 *const jp,
		u64 *const out_stream_id)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 j_start = *jp;

	int err = 0;
	u16 j = j_start;
	u64 stream_id = 0;

	(void) crawl_context;

	/* 0x10 */
	if(key_size - j >= 4) {
		j += print_le32_dechex("Value size (2)", prefix, indent, data,
			&data[j]);
	}
	/* 0x14 */
	if(key_size - j >= 2) {
		j += print_unknown16(prefix, indent, data, &data[j]);
	}
	/* 0x16 */
	if(key_size - j >= 2) {
		j += print_unknown16(prefix, indent, data, &data[j]);
	}
	/* 0x18 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x1C */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x20 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x24 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x28 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x2C */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x30 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x34 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x38 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x3C */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x40 */
	if(key_size - j >= 4) {
		stream_id = read_le64(&data[j]);
		j += print_le32_dechex("Stream ID", prefix, indent, data,
			&data[j]);
	}
	/* 0x44 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x48 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x4C */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x50 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x54 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x58 */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x5C */
	if(key_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}

	*jp = j;
	if(out_stream_id) {
		*out_stream_id = stream_id;
	}

	return err;
}

static int parse_attribute_key(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const sys_bool is_v3,
		const sys_bool is_index,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u32 entry_size,
		void *const context)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 attribute_type_offset = is_v3 ? 0x0C : 0x08;
	const u16 attribute_type =
		(key_size >= attribute_type_offset + 2) ?
		read_le16(&key[attribute_type_offset]) : 0;

	int err = 0;
	u16 j = 0;
	char *cstr = NULL;

	(void) object_id;
	(void) is_v3;
	(void) is_index;
	(void) entry_size;
	(void) context;

	emit(prefix, indent - 1, "Key (attribute) @ %" PRIu16 " / "
		"0x%" PRIX16 ":",
		PRAu16(key_offset), PRAX16(key_offset));

#if 0
	if(attribute_index - 1 == 1 &&
		key_size >= j + 0x08)
	{
#if 1
		/* This has the same layout as the allocation entry in a
		 * node. */
		err = parse_block_allocation_entry(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* size_t indent */
			indent,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *entry */
			&key[j],
			/* u32 entry_size */
			key_size,
			/* u32 entry_offset */
			offset_in_value,
			/* u32 *out_flags */
			NULL,
			/* u32 *out_value_offsets_start */
			NULL,
			/* u32 *out_value_offsets_end */
			NULL,
			/* u32 *out_value_count */
			&number_of_attributes);
		if(err) {
			goto out;
		}

		j += key_size;
#else
		j += print_unknown32(prefix, indent, key,
			&key[j]);
		number_of_attributes = read_le16(&key[j]);
		j += print_le16_dechex("Number of attributes", prefix,
			indent, key, &key[j]);
		j += print_unknown16(prefix, indent, key,
			&key[j]);
		j += print_unknown64(prefix, indent, key,
			&key[j]);
		if(key_size - j >= 0x8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]);
		}
		if(key_size - j >= 0x8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]);
		}
#endif
	}
	else
#endif
	if(attribute_type == 0x0080) {
		/* Data stream. */
#if 0
		u32 number_of_extents = 0;
		u32 k;
#endif

		sys_log_debug("Parsing data stream attribute key.");

#if 1
		err = parse_attribute_data_key(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* u16 key_size */
			key_size,
			/* u16 *jp */
			&j);
		if(err) {
			goto out;
		}
#else
		j += print_unknown64(prefix, indent, key, &key[j]); /* 0x10 */
		j += print_unknown16(prefix, indent, key, &key[j]); /* 0x18 */
		j += print_unknown16(prefix, indent, key, &key[j]); /* 0x1A */
		j += print_le16_hex("Attribute type (unnamed $DATA)", prefix,
			indent, key, &key[j]); /* 0x1C */
		j += print_unknown16(prefix, indent, key, &key[j]); /* 0x1E */
		j += print_unknown64(prefix, indent, key, &key[j]); /* 0x20 */
		j += print_unknown64(prefix, indent, key, &key[j]); /* 0x28 */
		j += print_unknown64(prefix, indent, key, &key[j]); /* 0x30 */
		/* Key ends here. */
#endif
#if 0
		j += print_unknown32(prefix, indent, key,
			&key[j]); /* 0x38 */
		j += print_unknown32(prefix, indent, key,
			&key[j]); /* 0x3C */
		j += print_unknown32(prefix, indent, key,
			&key[j]); /* 0x40 */
		j += print_unknown32(prefix, indent, key,
			&key[j]); /* 0x44 */
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x48 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x4C */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x4E */
		}
		if(key_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]); /* 0x50 */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Number of clusters",
				prefix, indent,
				key, &key[j]); /* 0x58 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x60 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x64 */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Allocated size (1)",
				prefix, indent,
				key, &key[j]); /* 0x68 */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Allocated size (2)",
				prefix, indent,
				key, &key[j]); /* 0x70 */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Allocated size (3)",
				prefix, indent,
				key, &key[j]); /* 0x78 */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Allocated size (4)",
				prefix, indent,
				key, &key[j]); /* 0x80 */
		}
		if(key_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]); /* 0x88 */
		}
		if(key_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]); /* 0x90 */
		}
		if(key_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]); /* 0x98 */
		}
		if(key_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]); /* 0xA0 */
		}
		if(key_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]); /* 0xA8 */
		}
		if(key_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]); /* 0xB0 */
		}
		if(key_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]); /* 0xB8 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xC0 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xC4 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xC8 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xCC */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xD0 */
		}
		if(key_size - j >= 4) {
			number_of_extents = read_le32(&key[j]);
			j += print_le32_dechex("Number of extents",
				prefix, indent,
				key, &key[j]); /* 0xD4 */
		}
		if(key_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]); /* 0xD8 */
		}
		if(key_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]); /* 0xE0 */
		}

		for(k = 0; k < number_of_extents; ++k) {
			u64 first_block = 0;
			u32 block_count = 0;

			emit(prefix, indent, "Extent %" PRIu32 "/"
				"%" PRIu32 ":",
				PRAu32(k + 1),
				PRAu32(number_of_extents));
			if(key_size - j >= 8) {
				first_block =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					read_le64(&key[j]));
				j += print_le64_dechex("Extent start "
					"physical block value", prefix,
					indent + 1, key,
					&key[j]);
				emit(prefix, indent + 3, "Actual "
					"physical block: %" PRIu64 " / "
					"0x%" PRIX64 " (byte offset: "
					"%" PRIu64 ")",
					PRAu64(first_block),
					PRAX64(first_block),
					PRAu64(first_block *
					block_index_unit));
			}
			else {
				break;
			}

			if(key_size - j >= 4) {
				j += print_le32_dechex("Flags (?)",
					prefix, indent + 1, key,
					&key[j]);
			}
			else {
				break;
			}

			if(key_size - j >= 8) {
				/* XXX: Misaligned? */
				j += print_le64_dechex("Extent start "
					"logical block", prefix,
					indent + 1, key,
					&key[j]);
			}
			else {
				break;
			}

			if(key_size - j >= 4) {
				block_count = read_le32(&key[j]);
				j += print_le32_dechex("Extent block "
					"count (?)", prefix, indent + 1,
					key, &key[j]);
			}
			else {
				break;
			}

			if(first_block && block_count && visitor &&
				visitor->node_file_extent)
			{
				err = visitor->node_file_extent(
					/* void *context */
					visitor->context,
					/* u64 first_block */
					first_block,
					/* u64 block_count */
					block_count,
					/* u32 block_index_unit */
					block_index_unit);
				if(err) {
					goto out;
				}
			}
		}

		if(number_of_extents) {
			if(key_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					key, &key[j]);
			}
			if(key_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					key, &key[j]);
			}
			if(key_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					key, &key[j]);
			}
			if(key_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					key, &key[j]);
			}
			if(key_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					key, &key[j]);
			}
			if(key_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					key, &key[j]);
			}
		}
#endif
	}
#if 0
	else if(key_offset == 0x0010 && key_size == 0x000E) {
		/* This attribute type seems to hold extent info. */
#if 0
		u64 first_block = 0;
		u64 block_count = 0;
#endif

		j += parse_level3_extent_key(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *key */
			key,
			/* size_t key_size */
			key_size);
	}
	else if(key_offset == 0x0010 && key_size == 0x0010 &&
		stream_type == 0x0080)
	{
		/* This attribute type appears to be inline data for the
		 * data stream. */
		u64 file_size = 0;

		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x10 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x14 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x18 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x1A */
		}
		if(key_size - j >= 4) {
			j += print_le32_dechex("Attribute type (unnamed $DATA)",
				prefix, indent, key, &key[j]); /* 0x1C */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x20 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x24 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x28 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x2C */
		}
		if(key_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]); /* 0x30 */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Allocated size 1",
				prefix, indent,
				key, &key[j]); /* 0x38 */
		}
		if(key_size - j >= 8) {
			file_size = read_le64(&key[j]);
			j += print_le64_dechex("Logical size 1",
				prefix, indent,
				key, &key[j]); /* 0x40 */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Logical size 2",
				prefix, indent,
				key, &key[j]); /* 0x48 */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Allocated size 2",
				prefix, indent,
				key, &key[j]); /* 0x50 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x58 */
		}

		if(visitor && visitor->node_file_data) {
			err = visitor->node_file_data(
				/* void *context */
				visitor->context,
				/* const void *data */
				&key[j],
				/* size_t size */
				file_size);
			if(err) {
				goto out;
			}
		}
	}
#endif
	else if(attribute_type == 0x00E0) {
		/* This attribute type appears to be inline data for the
		 * EA stream. Likely same format as the above. */
		sys_log_debug("Parsing $EA attribute key.");

#if 0
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x10 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x14 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x16 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x18 */
		}
		if(key_size - j >= 4) {
			j += print_le32_dechex("Stream type ($EA)",
				prefix, indent,
				key, &key[j]); /* 0x1C */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x20 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x24 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x28 */
		}

		/* After this, the EA list starts. */
		while(key_size - j >= 8) {
			u32 offset_to_next_ea = 0;
			u32 ea_end_offset = 0;
			u8 name_length = 0;
			u16 data_length = 0;
			const char *name = NULL;
			const void *data = NULL;

			if(key_size - j >= 4) {
				offset_to_next_ea =
					read_le32(&key[j]);
				ea_end_offset = j + offset_to_next_ea;
				j += print_le32_dechex("Offset to next "
					"EA", prefix, indent,
					key, &key[j]);
				if(ea_end_offset > key_size) {
					sys_log_warning("Offset to "
						"next EA is outside "
						"the bounds of the "
						"attribute: "
						"%" PRIu32 " > "
						"%" PRIu32,
						PRAu32(ea_end_offset),
						PRAu32(key_size));
					ea_end_offset = key_size;
				}
				else if(ea_end_offset <= j) {
					break;
				}
			}
			if(ea_end_offset - j >= 1) {
				j += print_u8_dechex("Flags", prefix,
					indent,
					key, &key[j]);
			}
			if(ea_end_offset - j >= 1) {
				name_length = key[j];
				j += print_u8_dechex("Name length",
					prefix, indent,
					key, &key[j]);
			}
			if(name_length > ea_end_offset - j) {
				sys_log_warning("Name length exceeds "
					"EA bounds: %" PRIu8 " > "
					"%" PRIu32,
					PRAu8(name_length),
					PRAu32(ea_end_offset - j));
			}
			if(ea_end_offset - j >= 2) {
				data_length = read_le16(&key[j]);
				j += print_le16_dechex("Data length",
					prefix, indent,
					key, &key[j]);
			}
			name = (const char*) &key[j];
			emit(prefix, indent, "Name @ %" PRIuz " / "
				"0x%" PRIXz ": %" PRIbs,
				PRAuz(j), PRAXz(j),
				PRAbs(sys_min(ea_end_offset - j,
				name_length), &key[j]));
			if(ea_end_offset - j < name_length) {
				break;
			}
			j += name_length;
			if(ea_end_offset - j < 1) {
				break;
			}
			print_u8_hex("Null terminator", prefix,
				indent, key, &key[j]);
			++j;
			if(data_length > ea_end_offset - j) {
				sys_log_warning("data length exceeds "
					"EA bounds: %" PRIu8 " > "
					"%" PRIu32,
					PRAu8(data_length),
					PRAu32(ea_end_offset - j));
			}
			data = &key[j];
			emit(prefix, indent, "Data @ %" PRIuz " / "
				"0x%" PRIXz ":",
				PRAuz(j), PRAXz(j));
			print_data_with_base(prefix, indent + 1, 0,
				data_length, &key[j],
				sys_min(ea_end_offset - j,
				data_length));
			if(visitor && visitor->node_ea) {
				err = visitor->node_ea(
					/* void *context */
					visitor->context,
					/* const char *name */
					name,
					/* size_t name_length */
					name_length,
					/* const void *data */
					data,
					/* size_t data_size */
					data_length);
				if(err) {
					goto out;
				}
			}
			if(ea_end_offset - j < data_length) {
				break;
			}
			j += data_length;

			if(j < ea_end_offset) {
				print_data_with_base(prefix, indent,
					j, ea_end_offset,
					&key[j],
					ea_end_offset - j);
				j = ea_end_offset;
			}
		}
#endif
		err = parse_attribute_ea_key(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *data */
			key,
			/* u16 key_size */
			key_size,
			/* u16 *jp */
			&j);
		if(err) {
			goto out;
		}
	}
	else if(attribute_type == 0x00B0) {
#if 0
		const u16 name_start = 0x10;
		const u16 name_end = key_size;
#if 0
		u16 value_offset = 0;
		u32 value_size = 0;
#endif
		size_t cstr_length = 0;
#if 0
		u32 data_size = 0;
		sys_bool non_resident = SYS_FALSE;
#endif
#endif

		/* This attribute type contains data about alternate data
		 * streams. */

		sys_log_debug("Parsing named stream key.");

#if 0
		j += parse_level3_attribute_header(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* size_t remaining_in_value */
			remaining_in_value,
			/* const u8 *attribute */
			key,
			/* u16 attribute_size */
			entry_size,
			/* u16 attribute_index */
			attribute_index);
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x08 */
		}
		if(key_size - j >= 2) {
			value_offset = read_le16(&key[j]);
			j += print_le16_dechex("Value offset", prefix,
				indent, key,
				&key[j]); /* 0x0A */
		}
		if(key_size - j >= 4) {
			value_size = read_le32(&key[j]);
			j += print_le32_dechex("Value size (1)", prefix,
				indent, key,
				&key[j]); /* 0x0C */
		}
#endif
#if 1
		err = parse_attribute_named_stream_key(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *attribute */
			key,
			/* u16 key_size */
			key_size,
			/* u16 *jp */
			&j,
			/* char **out_cstr */
			NULL,
			/* size_t *out_cstr_length */
			NULL);
		if(err) {
			goto out;
		}
#else
		if(key_size - j >= 4) {
			j += print_le32_dechex("Value size (2)", prefix,
				indent, key,
				&key[j]); /* 0x10 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x14 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x16 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x18 */
		}
		if(key_size - j >= 4) {
			j += print_le32_dechex("Stream type (named $DATA)",
				prefix, indent, key, &key[j]); /* 0x1C */
		}

#if 1 /* Not possible. Disable when confident. */
		if(j < name_start) {
			const u32 print_end =
				sys_min(name_start,
				key_size);
			print_data_with_base(prefix, indent, j,
				print_end, &key[j],
				print_end - j);
			j = print_end;
		}
#endif

		if(key_size - j >= name_end - name_start) {
			const u16 name_length =
				(name_end - name_start) / sizeof(refschar);
			err = sys_unistr_decode(
				/* const refschar *ins */
				(const refschar*) &key[name_start],
				/* size_t ins_len */
				name_length,
				/* char **outs */
				&cstr,
				/* size_t *outs_len */
				&cstr_length);
			if(err) {
				sys_log_perror(err, "Error while decoding name "
					"in attribute key");
				goto out;
			}

			emit(prefix, indent, "Name @ %" PRIuz " / 0x%" PRIXz " "
				"(length: %" PRIuz "):",
				PRAuz(j), PRAXz(j), PRAuz(cstr_length));
			emit(prefix, indent + 1, "%" PRIbs,
				PRAbs(cstr_length, cstr));
			j += name_length * sizeof(refschar);
		}

		if(j < key_size) {
			print_data_with_base(prefix, indent, j, key_size,
				&key[j], key_size - j);
			j = key_size;
		}

#if 0
		emit(prefix, indent, "Value @ %" PRIuz " / "
			"0x%" PRIXz " (size: %" PRIuz " / "
			"0x%" PRIXz "):",
			PRAuz(j), PRAXz(j), PRAuz(value_size),
			PRAXz(value_size));

		{
			const u8 *const value = &key[j];
			const u32 true_value_size =
				sys_min(key_size - j,
				value_size);
			u16 k = 0;

			if(true_value_size - k >= 4) {
				u32 flags;

				flags = read_le32(&value[k]);
				k += print_le32_dechex("Flags", prefix,
					indent + 1, value,
					&value[k]);

				if(flags & 0x10000000UL) {
					flags &= ~0x10000000UL;
					emit(prefix, indent + 3,
						"NON_RESIDENT%s",
						flags ? " |" : "");
					non_resident = SYS_TRUE;
				}
				if(flags) {
					emit(prefix, indent + 3,
						"<unknown: "
						"0x%" PRIu32 ">",
						PRAu32(flags));
				}
			}
			if(true_value_size - k >= 4) {
				k += print_unknown32(prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_unknown32(prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_unknown32(prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_unknown32(prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_unknown32(prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_le32_dechex("Allocated size "
					"(1)", prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_unknown32(prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				data_size = read_le32(&value[k]);
				k += print_le32_dechex("Attribute size "
					"(1)", prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_unknown32(prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_le32_dechex("Attribute size "
					"(2)", prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_unknown32(prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_le32_dechex("Allocated size "
					"(2)", prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_unknown32(prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k >= 4) {
				k += print_unknown32(prefix, indent + 1,
					value, &value[k]);
			}
			if(true_value_size - k > 0 && !non_resident) {
				const u32 data_limit =
					sys_min(data_size,
					value_size - k);
				refs_node_stream_data data;

				memset(&data, 0, sizeof(data));

				emit(prefix, indent + 1, "Resident "
					"data @ %" PRIuz " / "
					"0x%" PRIXz " (length: "
					"%" PRIuz "):",
					PRAuz(k), PRAXz(k),
					PRAuz(data_size));

				data.resident = SYS_TRUE;
				data.data.resident = &value[k];

				if(visitor && visitor->node_stream) {
					err = visitor->node_stream(
						/* void *context */
						visitor->context,
						/* const char *name */
						cstr,
						/* size_t name_length */
						cstr_length,
						/* u64 data_size */
						data_size,
						/* const
						 * refs_node_stream_data
						 * *data_reference */
						&data);
					if(err) {
						goto out;
					}
				}

				print_data_with_base(prefix, indent + 3,
					k, k + data_limit, &value[k],
					data_limit);
				k += data_limit;
			}
			else if(non_resident) {
				u64 stream_id = 0;

				emit(prefix, indent + 1, "Non-resident "
					"data @ %" PRIuz " / "
					"0x%" PRIXz " (length: "
					"%" PRIuz "):",
					PRAuz(k), PRAXz(k),
					PRAuz(data_size));
				if(true_value_size - k >= 4) {
					stream_id =
						read_le64(&value[k]);
					k += print_le64_dechex("Stream "
						"ID", prefix,
						indent + 3, value,
						&value[k]);
				}

				if(visitor && visitor->node_stream &&
					stream_id)
				{
					refs_node_stream_data data;

					memset(&data, 0, sizeof(data));

					data.resident = SYS_FALSE;
					data.data.non_resident.stream_id
						= stream_id;

					err = visitor->node_stream(
						/* void *context */
						visitor->context,
						/* const char *name */
						cstr,
						/* size_t name_length */
						cstr_length,
						/* u64 data_size */
						data_size,
						/* const
						 * refs_node_stream_data
						 * *data_reference */
						&data);
					if(err) {
						goto out;
					}
				}
				if(true_value_size - k >= 4) {
					k += print_unknown32(prefix,
						indent + 3, value,
						&value[k]);
				}
			}

			if(k < true_value_size) {
				print_data_with_base(prefix, indent + 1,
					k, true_value_size, &value[k],
					true_value_size - k);
				k = true_value_size;
			}

			j += k;
		}
#endif
#endif
	}
	else if(key_offset == 0x0010 && key_size == 0x50) {
#if 0
		u64 stream_id = 0;
		u32 num_extents = 0;
		u32 k;
#endif

		sys_log_debug("Parsing named stream extent key.");

#if 0
		j += parse_level3_attribute_header(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* size_t remaining_in_value */
			remaining_in_value,
			/* const u8 *attribute */
			key,
			/* u16 attribute_size */
			entry_size,
			/* u16 attribute_index */
			attribute_index);
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x08 */
		}
		if(key_size - j >= 2) {
			j += print_le16_dechex("Value offset", prefix,
				indent, key,
				&key[j]); /* 0x0A */
		}
		if(key_size - j >= 4) {
			j += print_le32_dechex("Value size (1)", prefix,
				indent, key,
				&key[j]); /* 0x0C */
		}
#endif
#if 1
		if(key_size - j >= 4) {
			err = parse_attribute_named_stream_extent_key(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* const u8 *attribute */
				key,
				/* u16 value_size */
				key_size,
				/* u16 *jp */
				&j,
				/* u64 *out_stream_id */
				NULL);
			if(err) {
				goto out;
			}
		}
#else
		if(key_size - j >= 4) {
			j += print_le32_dechex("Value size (2)", prefix,
				indent, key,
				&key[j]); /* 0x10 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x14 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x16 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x18 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x1C */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x20 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x24 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x28 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x2C */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x30 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x34 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x38 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x3C */
		}
		if(key_size - j >= 4) {
			stream_id = read_le64(&key[j]);
			j += print_le32_dechex("Stream ID",
				prefix, indent,
				key, &key[j]); /* 0x40 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x44 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x48 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x4C */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x50 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x54 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x58 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x5C */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x60 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x64 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x68 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x6C */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x70 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x74 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x78 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x7C */
		}
		if(key_size - j >= 4) {
			j += print_le32_dechex("Number of extents",
				prefix, indent,
				key, &key[j]); /* 0x80 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x84 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x88 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x8C */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Allocated size (1)",
				prefix, indent,
				key, &key[j]); /* 0x90 */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Allocated size (2)",
				prefix, indent,
				key, &key[j]); /* 0x98 */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Allocated size (3)",
				prefix, indent,
				key, &key[j]); /* 0xA0 */
		}
		if(key_size - j >= 8) {
			j += print_le64_dechex("Allocated size (4)",
				prefix, indent,
				key, &key[j]); /* 0xA8 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xB0 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xB4 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xB8 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xBC */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xC0 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xC4 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xC8 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xCC */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xD0 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xD4 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xD8 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xDC */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xE0 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xE4 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xE8 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xEC */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xF0 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xF4 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0xF8 */
		}
		if(key_size - j >= 4) {
			num_extents = read_le32(&key[j]);
			j += print_le32_dechex("Number of extents (2)",
				prefix, indent,
				key, &key[j]); /* 0xFC */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x100 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x104 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x108 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x10C */
		}

		/* Iterate over extents in stream. */
		for(k = 0; k < num_extents &&
			(key_size - j) >= 24; ++k)
		{
			const u64 first_physical_block =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					read_le64(&key[j]));
			/* TODO: Guessing that this is the number of
			 * clusters in the extent. Not sure about it. */
			const u32 cluster_count =
				read_le32(&key[j + 20]);

			emit(prefix, indent, "Extent %" PRIu32 "/"
				"%" PRIu32 ":",
				PRAu32(k + 1), PRAu32(num_extents));

			j += print_le64_dechex("First block", prefix,
				indent + 1,
				key, &key[j]); /* 0x110 */
			emit(prefix, indent + 2,
				"-> Physical block: %" PRIu64 " / "
				"0x%" PRIX64 " (byte offset: "
				"%" PRIu64 ")",
				PRAu64(first_physical_block),
				PRAX64(first_physical_block),
				PRAu64(first_physical_block *
				block_index_unit));
			if(visitor && visitor->node_stream_extent) {
				err = visitor->node_stream_extent(
					/* void *context */
					visitor->context,
					/* u64 stream_id */
					stream_id,
					/* u64 first_block */
					first_physical_block,
					/* u32 block_index_unit */
					block_index_unit,
					/* u32 cluster_count */
					cluster_count);
				if(err) {
					goto out;
				}
			}

			j += print_unknown32(prefix, indent + 1,
				key, &key[j]); /* 0x118 */

			j += print_unknown32(prefix, indent + 1,
				key, &key[j]); /* 0x11C */

			j += print_unknown32(prefix, indent + 1,
				key, &key[j]); /* 0x120 */

			j += print_le32_dechex("Number of clusters in "
				"extent (?)", prefix, indent + 1,
				key, &key[j]); /* 0x124 */
		}
#endif
	}
#if 0
	else if(key_offset == 0x10 && key_size == 0x00) {
		/* This appears to contain an independently allocated
		 * (non-resident) attribute list. */
		u64 logical_blocks[4] = { 0, 0, 0, 0 };
		u64 physical_blocks[4] = { 0, 0, 0, 0 };

#if 0
		j += parse_level3_attribute_header(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* size_t remaining_in_value */
			remaining_in_value,
			/* const u8 *attribute */
			key,
			/* u16 attribute_size */
			entry_size,
			/* u16 attribute_index */
			attribute_index);
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x08 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x0A */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x0C */
		}
#endif
		if(key_size - j >= 8) {
			logical_blocks[0] = read_le64(&key[j]);
			physical_blocks[0] =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					logical_blocks[0]);

			j += print_le64_dechex("Block number 1", prefix,
				indent,
				key, &key[j]); /* 0x10 */
			emit(prefix, indent + 1,
				"-> Physical block: %" PRIu64 " / "
				"0x%" PRIX64 " (byte offset: "
				"%" PRIu64 ")",
				PRAu64(physical_blocks[0]),
				PRAX64(physical_blocks[0]),
				PRAu64(physical_blocks[0] *
				block_index_unit));
		}
		if(key_size - j >= 8) {
			logical_blocks[1] = read_le64(&key[j]);
			physical_blocks[1] =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					logical_blocks[1]);

			j += print_le64_dechex("Block number 2", prefix,
				indent,
				key, &key[j]); /* 0x18 */
			emit(prefix, indent + 1,
				"-> Physical block: %" PRIu64 " / "
				"0x%" PRIX64 " (byte offset: "
				"%" PRIu64 ")",
				PRAu64(physical_blocks[1]),
				PRAX64(physical_blocks[1]),
				PRAu64(physical_blocks[1] *
				block_index_unit));
		}
		if(key_size - j >= 8) {
			logical_blocks[2] = read_le64(&key[j]);
			physical_blocks[2] =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					logical_blocks[2]);

			j += print_le64_dechex("Block number 3", prefix,
				indent,
				key, &key[j]); /* 0x20 */
			emit(prefix, indent + 1,
				"-> Physical block: %" PRIu64 " / "
				"0x%" PRIX64 " (byte offset: "
				"%" PRIu64 ")",
				PRAu64(physical_blocks[2]),
				PRAX64(physical_blocks[2]),
				PRAu64(physical_blocks[2] *
				block_index_unit));
		}
		if(key_size - j >= 8) {
			logical_blocks[3] = read_le64(&key[j]);
			physical_blocks[3] =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					logical_blocks[3]);

			j += print_le64_dechex("Block number 4", prefix,
				indent,
				key, &key[j]); /* 0x28 */
			emit(prefix, indent + 1,
				"-> Physical block: %" PRIu64 " / "
				"0x%" PRIX64 " (byte offset: "
				"%" PRIu64 ")",
				PRAu64(physical_blocks[3]),
				PRAX64(physical_blocks[3]),
				PRAu64(physical_blocks[3] *
				block_index_unit));
		}
		if(key_size - j >= 8) {
			j += print_le64_hex("Flags", prefix,
				indent,
				key, &key[j]); /* 0x30 */
		}
		if(key_size - j >= 8) {
			j += print_le64_hex("Checksum", prefix,
				indent,
				key, &key[j]); /* 0x38 */
		}

		if(logical_blocks[0]) {
			const size_t bytes_per_read =
				sys_min(crawl_context->cluster_size,
				crawl_context->block_size);

			u8 *block = NULL;
			size_t bytes_read = 0;
			u8 i = 0;

			err = sys_malloc(crawl_context->block_size,
				&block);
			if(err) {
				sys_log_perror(err, "Error while "
					"allocating %" PRIu32 " byte "
					"block",
					PRAu32(crawl_context->
					block_size));
				goto out;
			}

			while(bytes_read < crawl_context->block_size) {
				sys_log_debug("Reading logical block "
					"%" PRIu64 " / physical block "
					"%" PRIu64 " into "
					"%" PRIuz "-byte buffer %p at "
					"buffer offset %" PRIuz,
					PRAu64(logical_blocks[i]),
					PRAu64(physical_blocks[i]),
					PRAuz(crawl_context->
					block_size),
					block,
					PRAuz(bytes_read));
				err = sys_device_pread(
					/* sys_device *dev */
					crawl_context->dev,
					/* u64 pos */
					physical_blocks[i] *
					block_index_unit,
					/* size_t count */
					bytes_per_read,
					/* void *b */
					&block[bytes_read]);
				if(err) {
					break;
				}

				bytes_read += bytes_per_read;
				++i;
			}
			if(err) {
				sys_log_pwarning(err, "Error while "
					"reading %" PRIuz " bytes from "
					"attribute block %" PRIu64 " "
					"(offset %" PRIu64 ")",
					PRAuz(crawl_context->
					block_size),
					PRAu64(physical_blocks[i]),
					PRAu64(physical_blocks[i] *
					block_index_unit));
				goto out;
			}

			err = parse_generic_block(
				/* refs_node_crawl_context
				 *     *crawl_context */
				crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* size_t indent */
				indent + 1,
				/* u64 cluster_number */
				physical_blocks[0],
				/* u64 block_number */
				logical_blocks[0],
				/* u64 block_queue_index */
				0 /* Different block queue... */,
				/* u8 level */
				4,
				/* const u8 *block */
				block,
				/* u32 block_size */
				crawl_context->block_size,
				/* block_queue *block_queue */
				NULL,
				/* sys_bool
				 *     add_subnodes_in_offsets_order */
				SYS_TRUE,
				/* void *context */
				context,
				/* int (*parse_key)(
				 *      refs_node_crawl_context *crawl_context,
				 *      refs_node_walk_visitor *visitor,
				 *      const char *prefix,
				 *      size_t indent,
				 *      u64 object_id,
				 *      sys_bool is_index,
				 *      sys_bool is_v3,
				 *      const u8 *key,
				 *      u16 key_offset,
				 *      u16 key_size,
				 *      u32 entry_size,
				 *      void *context) */
				parse_attribute_key,
				/* int (*parse_leaf_value)(
				 *      refs_node_crawl_context
				 *          *crawl_context,
				 *      refs_node_walk_visitor *visitor,
				 *      const char *prefix,
				 *      size_t indent,
				 *      u64 object_id,
				 *      const u8 *key,
				 *      u16 key_size,
				 *      const u8 *value,
				 *      u16 value_offset,
				 *      u16 value_size,
				 *      u16 entry_offset,
				 *      u32 entry_size,
				 *      void *context) */
				parse_level3_leaf_value,
				/* int (*leaf_entry_handler)(
				 *      void *context,
				 *      const u8 *data,
				 *      u32 data_size,
				 *      u32 node_type) */
				NULL);
			if(err) {
				sys_log_pwarning(err, "Error while "
					"parsing non-resident "
					"attribute list");
				goto out;
			}
		}
	}
#endif
	else {
		/* Unknown type, but assume it conforms to the same initial key
		 * structure as we've seen in the past. */
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x10 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x14 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x18 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x1A */
		}
		if(key_size - j >= 4) {
			j += print_le32_dechex("Attribute type (unknown)",
				prefix, indent,
				key, &key[j]); /* 0x1C */
		}
	}
out:
	if(j < key_size) {
		print_data_with_base(prefix, indent, j, key_size, &key[j],
			key_size - j);
	}

	if(cstr) {
		sys_free(&cstr);
	}

	return err;
}

static int parse_attribute_non_resident_data_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const value,
		const u16 value_size,
		u16 *const jp)
{
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	const u32 block_index_unit = crawl_context->block_index_unit;
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 j_start = *jp;
	const u16 value_end = j_start + value_size;

	int err = 0;
	u16 j = *jp;
	u32 number_of_extents = 0;
	u32 k;

	/* 0x00 */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* 0x04 */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* 0x08 */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* 0x0C */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* 0x10 */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* 0x14 */
	if(value_end - j >= 2) {
		j += print_unknown16(prefix, indent, value, &value[j]);
	}
	/* 0x16 */
	if(value_end - j >= 2) {
		j += print_unknown16(prefix, indent, value, &value[j]);
	}
	/* 0x18 */
	if(value_end - j >= 8) {
		j += print_unknown64(prefix, indent, value, &value[j]);
	}
	/* v1: 0x20 */
	if(!is_v3 && value_end - j >= 8) {
		j += print_unknown64(prefix, indent, value, &value[j]);
	}
	/* v1: 0x28 v3: 0x20 */
	if(value_end - j >= 8) {
		j += print_le64_dechex("Number of clusters", prefix, indent,
			value, &value[j]);
	}
	/* v1: 0x30 v3: 0x28 */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* v3: 0x2C */
	if(is_v3 && value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* v1: 0x34 v3: 0x30 */
	if(value_end - j >= 8) {
		j += print_le64_dechex("Allocated size (1)", prefix, indent,
			value, &value[j]);
	}
	/* v1: 0x3C v3: 0x38 */
	if(value_end - j >= 8) {
		j += print_le64_dechex("Logical size (1)", prefix, indent,
			value, &value[j]);
	}
	/* v1: 0x44 v3: 0x40 */
	if(value_end - j >= 8) {
		j += print_le64_dechex("Logical size (2)", prefix, indent,
			value, &value[j]);
	}
	/* v1: 0x4C v3: 0x48 */
	if(value_end - j >= 8) {
		j += print_le64_dechex("Allocated size? (2)", prefix, indent,
			value, &value[j]);
	}
	/* v1: 0x54 v3: 0x50 */
	if(value_end - j >= 8) {
		j += print_unknown64(prefix, indent, value, &value[j]);
	}
	/* v1: 0x5C v3: 0x58 */
	if(value_end - j >= 8) {
		j += print_unknown64(prefix, indent, value, &value[j]);
	}
	/* v1: 0x64 v3: 0x60 */
	if(value_end - j >= 8) {
		j += print_unknown64(prefix, indent, value, &value[j]);
	}
	/* v1: 0x64 v3: 0x60 */
	if(value_end - j >= 8) {
		j += print_unknown64(prefix, indent, value, &value[j]);
	}
	/* 0xA8 */
	if(value_end - j >= 8) {
		j += print_unknown64(prefix, indent, value, &value[j]);
	}
	/* 0xB0 */
	if(value_end - j >= 8) {
		j += print_unknown64(prefix, indent, value, &value[j]);
	}
	/* 0xB8 */
	if(value_end - j >= 8) {
		j += print_unknown64(prefix, indent, value, &value[j]);
	}
	/* 0xC0 */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* 0xC4 */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* 0xC8 */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* 0xCC */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* 0xD0 */
	if(is_v3 && value_end - j >= 4) {
		j += print_unknown32(prefix, indent, value, &value[j]);
	}
	/* 0xD4 */
	if(value_end - j >= 4) {
		number_of_extents = read_le32(&value[j]);
		j += print_le32_dechex("Number of extents", prefix, indent,
			value, &value[j]);
	}
	/* 0xD8 */
	if(value_end - j >= 8) {
		j += print_unknown64(prefix, indent, value, &value[j]);
	}
	/* 0xE0 */
	if(is_v3 && value_end - j >= 8) {
		j += print_unknown64(prefix, indent, value, &value[j]);
	}

	for(k = 0; k < number_of_extents; ++k) {
		u64 first_physical_block = 0;
		u64 first_logical_block = 0;
		u32 block_count = 0;

		emit(prefix, indent, "Extent %" PRIu32 "/%" PRIu32 ":",
			PRAu32(k + 1),
			PRAu32(number_of_extents));

		if(is_v3);
		else if(value_end - j >= 4) {
			j += print_unknown32(prefix, indent + 1, value,
				&value[j]);
		}
		else {
			break;
		}

		if(is_v3);
		else if(value_end - j >= 4) {
			j += print_unknown32(prefix, indent + 1, value,
				&value[j]);
		}
		else {
			break;
		}

		if(is_v3);
		else if(value_end - j >= 4) {
			j += print_unknown32(prefix, indent + 1, value,
				&value[j]);
		}
		else {
			break;
		}

		if(is_v3);
		else if(value_end - j >= 4) {
			j += print_unknown32(prefix, indent + 1, value,
				&value[j]);
		}
		else {
			break;
		}

		if(is_v3);
		else if(value_end - j >= 8) {
			first_logical_block = read_le64(&value[j]);
			j += print_le64_dechex("Extent start logical block",
				prefix, indent + 1, value, &value[j]);
		}
		else {
			break;
		}

		if(is_v3);
		else if(value_end - j >= 8) {
			block_count = read_le64(&value[j]);
			j += print_le64_dechex("Extent block count (?)", prefix,
				indent + 1, value, &value[j]);
		}
		else {
			break;
		}

		if(value_end - j >= 8) {
			first_physical_block =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					read_le64(&value[j]));
			j += print_le64_dechex("Extent start physical block "
				"value",
				prefix, indent + 1, value, &value[j]);
			emit(prefix, indent + 2, "Actual physical block: "
				"%" PRIu64 " / 0x%" PRIX64 " (byte offset: "
				"%" PRIu64 ")",
				PRAu64(first_physical_block),
				PRAX64(first_physical_block),
				PRAu64(first_physical_block *
				block_index_unit));
		}
		else {
			break;
		}

		if(is_v3 && value_end - j >= 4) {
			j += print_le32_dechex("Flags (?)", prefix, indent + 1,
				value, &value[j]);
		}
		else if(!is_v3 && value_end - j >= 8) {
			j += print_le64_dechex("Flags (?)", prefix, indent + 1,
				value, &value[j]);
		}
		else {
			break;
		}

		if(!is_v3);
		else if(value_end - j >= 8) {
			/* XXX: Misaligned? */
			first_logical_block = read_le64(&value[j]);
			j += print_le64_dechex("Extent start logical block",
				prefix, indent + 1, value, &value[j]);
		}
		else {
			break;
		}

		if(!is_v3);
		else if(value_end - j >= 4) {
			block_count = read_le32(&value[j]);
			j += print_le32_dechex("Extent block count (?)", prefix,
				indent + 1, value, &value[j]);
		}
		else {
			break;
		}

		if(first_physical_block && block_count && visitor &&
			visitor->node_file_extent)
		{
			err = visitor->node_file_extent(
				/* void *context */
				visitor->context,
				/* u64 first_logical_block */
				first_logical_block,
				/* u64 first_physical_block */
				first_physical_block,
				/* u64 block_count */
				block_count,
				/* u32 block_index_unit */
				block_index_unit);
			if(err) {
				goto out;
			}
		}
	}

	if(number_of_extents) {
		if(value_end - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_end - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_end - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_end - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_end - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_end - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
	}

	*jp = j;
out:
	return err;
}

static int parse_attribute_resident_data_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const attribute,
		const u16 value_size,
		u16 *const jp)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 j_start = *jp;
	const u16 value_end = j_start + value_size;

	int err = 0;
	size_t j = *jp;
	u64 logical_size = 0;

	(void) crawl_context;

	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent,
			attribute,
			&attribute[j]); /* 0x20 */
	}
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent,
			attribute,
			&attribute[j]); /* 0x24 */
	}
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent,
			attribute,
			&attribute[j]); /* 0x28 */
	}
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent,
			attribute,
			&attribute[j]); /* 0x2C */
	}
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent,
			attribute,
			&attribute[j]); /* 0x30 */
	}
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent,
			attribute,
			&attribute[j]); /* 0x34 */
	}
	if(value_end - j >= 8) {
		j += print_le64_dechex("Allocated size 1",
			prefix, indent,
			attribute,
			&attribute[j]); /* 0x38 */
	}
	if(value_end - j >= 8) {
		logical_size = read_le64(&attribute[j]);
		j += print_le64_dechex("Logical size 1",
			prefix, indent,
			attribute,
			&attribute[j]); /* 0x40 */
	}
	if(value_end - j >= 8) {
		j += print_le64_dechex("Logical size 2",
			prefix, indent,
			attribute,
			&attribute[j]); /* 0x48 */
	}
	if(value_end - j >= 8) {
		j += print_le64_dechex("Allocated size 2",
			prefix, indent,
			attribute,
			&attribute[j]); /* 0x50 */
	}
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent,
			attribute,
			&attribute[j]); /* 0x58 */
	}

	emit(prefix, indent, "Resident data @ %" PRIu16 " / 0x%" PRIX16 ":",
		PRAu16(j), PRAX16(j));
	if(value_end > j) {
		const size_t resident_bytes =
			sys_min(logical_size, (u16) (value_end - j));

		print_data_with_base(prefix, indent + 1, 0,
			resident_bytes, &attribute[j],
			resident_bytes);

		if(visitor && visitor->node_file_data) {
			err = visitor->node_file_data(
				/* void *context */
				visitor->context,
				/* const void *data */
				&attribute[j],
				/* size_t size */
				resident_bytes);
			if(err) {
				goto out;
			}
		}

		j += resident_bytes;
	}

	*jp = j;
out:
	return err;
}

static int parse_attribute_ea_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const data,
		const u16 value_size,
		u16 *const jp)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 j_start = *jp;
	const u16 value_end = j_start + value_size;

	int err = 0;
	u16 j = j_start;

	(void) crawl_context;

	/* 0x20 */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x24 */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x28 */
	if(value_end - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}

	/* After this, the EA list starts. */
	/* 0x2C */
	while(value_end - j >= 8) {
		u32 offset_to_next_ea = 0;
		u32 ea_end_offset = 0;
		u8 name_length = 0;
		u16 ea_data_length = 0;
		const char *name = NULL;
		const void *ea_data = NULL;

		if(value_end - j >= 4) {
			offset_to_next_ea = read_le32(&data[j]);
			ea_end_offset = j + offset_to_next_ea;
			j += print_le32_dechex("Offset to next EA", prefix,
				indent, data, &data[j]);
			if(ea_end_offset > value_end) {
				sys_log_warning("Offset to next EA is outside "
					"the bounds of the attribute: "
					"%" PRIu32 " > %" PRIu32,
					PRAu32(ea_end_offset),
					PRAu32(value_end));
				ea_end_offset = value_end;
			}
			else if(ea_end_offset <= j) {
				break;
			}
		}
		if(ea_end_offset - j >= 1) {
			j += print_u8_dechex("Flags", prefix, indent, data,
				&data[j]);
		}
		if(ea_end_offset - j >= 1) {
			name_length = ((u8*) data)[j];
			j += print_u8_dechex("Name length", prefix, indent,
				data, &data[j]);
		}
		if(ea_end_offset - j >= 2) {
			ea_data_length = read_le16(&data[j]);
			j += print_le16_dechex("Data length", prefix, indent,
				data, &data[j]);
		}

		if(name_length > ea_end_offset - j) {
			sys_log_warning("Name length exceeds EA bounds: "
				"%" PRIu8 " > %" PRIu32,
				PRAu8(name_length), PRAu32(ea_end_offset - j));
			name_length = ea_end_offset - j;
		}

		name = (const char*) &data[j];
		emit(prefix, indent, "Name @ %" PRIuz " / 0x%" PRIXz ": "
			"%" PRIbs,
			PRAuz(j), PRAXz(j), PRAbs(name_length, &data[j]));
		if(ea_end_offset - j < name_length) {
			break;
		}
		if(ea_end_offset - j < 1) {
			break;
		}
		j += name_length;

		print_u8_hex("Null terminator", prefix, indent, data,
			&data[j]);
		++j;

		if(ea_data_length > ea_end_offset - j) {
			sys_log_warning("data length exceeds EA bounds: "
				"%" PRIu8 " > %" PRIu32,
				PRAu8(ea_data_length),
				PRAu32(ea_end_offset - j));
			ea_data_length = ea_end_offset - j;
		}

		ea_data = &data[j];
		emit(prefix, indent, "Data @ %" PRIuz " / 0x%" PRIXz ":",
			PRAuz(j), PRAXz(j));
		print_data_with_base(prefix, indent + 1, 0, ea_data_length,
			&data[j], ea_data_length);

		if(visitor && visitor->node_ea) {
			err = visitor->node_ea(
				/* void *context */
				visitor->context,
				/* const char *name */
				name,
				/* size_t name_length */
				name_length,
				/* const void *data */
				ea_data,
				/* size_t data_size */
				ea_data_length);
			if(err) {
				goto out;
			}
		}

		j += ea_data_length;

		if(j < ea_end_offset) {
			print_data_with_base(prefix, indent,
				j, ea_end_offset,
				&data[j],
				ea_end_offset - j);
			j = ea_end_offset;
		}
	}

	*jp = j;
out:
	return err;
}

static int parse_attribute_named_stream_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const char *const cstr,
		const size_t cstr_length,
		const u8 *const attribute,
		const u16 value_size,
		u16 *const jp)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 j_start = *jp;
	const u8 *const attr_value = &attribute[j_start];

	int err = 0;
	u16 k = 0;
	sys_bool non_resident = SYS_FALSE;
	u32 data_size = 0;

	(void) crawl_context;

	if(value_size - k >= 4) {
		u32 flags;

		flags = read_le32(&attr_value[k]);
		k += print_le32_dechex("Flags", prefix, indent, attr_value,
			&attr_value[k]);

		if(flags & 0x10000000UL) {
			flags &= ~0x10000000UL;
			emit(prefix, indent + 1, "NON_RESIDENT%s",
				flags ? " |" : "");
			non_resident = SYS_TRUE;
		}
		if(flags) {
			emit(prefix, indent + 1, "<unknown: 0x%" PRIu32 ">",
				PRAu32(flags));
		}
	}
	if(value_size - k >= 4) {
		k += print_unknown32(prefix, indent, attr_value,
			&attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_unknown32(prefix, indent, attr_value,
			&attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_unknown32(prefix, indent, attr_value,
			&attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_unknown32(prefix, indent, attr_value,
			&attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_unknown32(prefix, indent, attr_value,
			&attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_le32_dechex("Allocated size (1)", prefix, indent,
			attr_value, &attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_unknown32(prefix, indent, attr_value,
			&attr_value[k]);
	}
	if(value_size - k >= 4) {
		data_size = read_le32(&attr_value[k]);
		k += print_le32_dechex("Attribute size (1)", prefix, indent,
			attr_value, &attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_unknown32(prefix, indent, attr_value,
			&attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_le32_dechex("Attribute size (2)", prefix, indent,
			attr_value, &attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_unknown32(prefix, indent, attr_value,
			&attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_le32_dechex("Allocated size (2)", prefix, indent,
			attr_value, &attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_unknown32(prefix, indent, attr_value,
			&attr_value[k]);
	}
	if(value_size - k >= 4) {
		k += print_unknown32(prefix, indent, attr_value,
			&attr_value[k]);
	}
	if(value_size - k > 0 && !non_resident) {
		const u32 data_limit =
			sys_min(data_size, (u16) (value_size - k));
		refs_node_stream_data data;

		memset(&data, 0, sizeof(data));

		emit(prefix, indent, "Resident data @ %" PRIuz " / "
			"0x%" PRIXz " (length: %" PRIuz "):",
			PRAuz(k), PRAXz(k), PRAuz(data_size));

		data.resident = SYS_TRUE;
		data.data.resident = &attr_value[k];

		if(visitor && visitor->node_stream) {
			err = visitor->node_stream(
				/* void *context */
				visitor->context,
				/* const char *name */
				cstr,
				/* size_t name_length */
				cstr_length,
				/* u64 data_size */
				data_size,
				/* const refs_node_stream_data
				 * *data_reference */
				&data);
			if(err) {
				goto out;
			}
		}

		print_data_with_base(prefix, indent + 1, k, k + data_limit,
			&attr_value[k], data_limit);
		k += data_limit;
	}
	else if(non_resident) {
		u64 stream_id = 0;

		emit(prefix, indent, "Non-resident data @ %" PRIuz " / "
			"0x%" PRIXz " (length: %" PRIuz "):",
			PRAuz(k), PRAXz(k), PRAuz(data_size));
		if(value_size - k >= 4) {
			stream_id = read_le64(&attr_value[k]);
			k += print_le64_dechex("Stream ID", prefix, indent + 1,
				attr_value, &attr_value[k]);
		}

		if(visitor && visitor->node_stream && stream_id) {
			refs_node_stream_data data;

			memset(&data, 0, sizeof(data));

			data.resident = SYS_FALSE;
			data.data.non_resident.stream_id = stream_id;

			err = visitor->node_stream(
				/* void *context */
				visitor->context,
				/* const char *name */
				cstr,
				/* size_t name_length */
				cstr_length,
				/* u64 data_size */
				data_size,
				/* const refs_node_stream_data
				 * *data_reference */
				&data);
			if(err) {
				goto out;
			}
		}

		if(value_size - k >= 4) {
			k += print_unknown32(prefix, indent + 1, attr_value,
				&attr_value[k]);
		}
	}

	if(k < value_size) {
		print_data_with_base(prefix, indent, k, value_size,
			&attr_value[k], value_size - k);
		k = value_size;
	}

	*jp += k;
out:
	return err;
}

static int parse_attribute_named_stream_extent_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 stream_id,
		const u8 *const data,
		const u16 value_size,
		u16 *const jp)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	const u32 block_index_unit = crawl_context->block_index_unit;
	const u16 j_start = *jp;

	int err = 0;
	u16 j = j_start;
	u16 k = 0;
	u32 num_extents = 0;

	/* 0x60 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x64 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x68 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x6C */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x70 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x74 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x78 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x7C */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x80 */
	if(value_size - j >= 4) {
		j += print_le32_dechex("Number of extents", prefix, indent,
			data, &data[j]);
	}
	/* 0x84 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x88 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x8C */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x90 */
	if(value_size - j >= 8) {
		j += print_le64_dechex("Allocated size (1)", prefix, indent,
			data, &data[j]);
	}
	/* 0x98 */
	if(value_size - j >= 8) {
		j += print_le64_dechex("Logical size (1)", prefix, indent,
			data, &data[j]);
	}
	/* 0xA0 */
	if(value_size - j >= 8) {
		j += print_le64_dechex("Logical size (2)", prefix, indent,
			data, &data[j]);
	}
	/* 0xA8 */
	if(value_size - j >= 8) {
		j += print_le64_dechex("Allocated size (2)", prefix, indent,
			data, &data[j]);
	}
	/* 0xB0 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xB4 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xB8 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xBC */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xC0 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xC4 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xC8 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xCC */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xD0 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xD4 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xD8 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xDC */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xE0 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xE4 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xE8 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xEC */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xF0 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xF4 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xF8 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0xFC */
	if(value_size - j >= 4) {
		num_extents = read_le32(&data[j]);
		j += print_le32_dechex("Number of extents (2)", prefix, indent,
			data, &data[j]);
	}
	/* 0x100 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x104 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x108 */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}
	/* 0x10C */
	if(value_size - j >= 4) {
		j += print_unknown32(prefix, indent, data, &data[j]);
	}

	/* Iterate over extents in stream. */
	for(k = 0; k < num_extents && (value_size - j) >= 24; ++k) {
		const u64 first_physical_block =
			logical_to_physical_block_number(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* u64 logical_block_number */
				read_le64(&data[j]));
		const u32 first_logical_block =
			read_le64(&data[j + 12]);
		const u32 cluster_count =
			read_le32(&data[j + 20]);

		if(visitor && visitor->node_stream_extent) {
			err = visitor->node_stream_extent(
				/* void *context */
				visitor->context,
				/* u64 stream_id */
				stream_id,
				/* u64 first_logical_block */
				first_logical_block,
				/* u64 first_physical_block */
				first_physical_block,
				/* u32 block_index_unit */
				block_index_unit,
				/* u32 cluster_count */
				cluster_count);
			if(err) {
				goto out;
			}
		}

		emit(prefix, indent, "Extent %" PRIu32 "/%" PRIu32 ":",
			PRAu32(k + 1), PRAu32(num_extents));

		if(!is_v3) {
			/* v1: 0x110 */
			j += print_le64_dechex("Block count", prefix,
				indent + 1,
				data, &data[j]);
		}

		/* v3: 0x110 */
		j += print_le64_dechex("First block", prefix, indent + 1, data,
			&data[j]);
		emit(prefix, indent + 2,
			"-> Physical block: %" PRIu64 " / 0x%" PRIX64 " (byte "
			"offset: %" PRIu64 ")",
			PRAu64(first_physical_block),
			PRAX64(first_physical_block),
			PRAu64(first_physical_block * block_index_unit));

		/* v3: 0x118 */
		j += print_le32_dechex("Flags", prefix, indent + 1, data,
			&data[j]);

		/* v3: 0x11C */
		j += print_le64_dechex("Logical block", prefix, indent + 1,
			data, &data[j]);

		/* v3: 0x124 */
		j += print_le32_dechex("Number of clusters in "
			"extent (?)", prefix, indent + 1, data, &data[j]);
	}

	*jp = j;
out:
	return err;
}

static int parse_non_resident_attribute_list_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const data,
		const u16 value_size,
		void *const context,
		u16 *const jp)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	const u32 block_index_unit = crawl_context->block_index_unit;
	const u16 j_start = *jp;
	const u16 value_end = j_start + value_size;

	int err = 0;
	u16 j = j_start;
	u64 logical_blocks[4] = { 0, 0, 0, 0 };
	u64 physical_blocks[4] = { 0, 0, 0, 0 };
	u8 *block = NULL;

	/* 0x10 */
	if(value_end - j >= 8) {
		logical_blocks[0] = read_le64(&data[j]);
		physical_blocks[0] =
			logical_to_physical_block_number(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* u64 logical_block_number */
				logical_blocks[0]);

		j += print_le64_dechex("Block number 1", prefix, indent, data,
			&data[j]);
		emit(prefix, indent + 1, "-> Physical block: %" PRIu64 " / "
			"0x%" PRIX64 " (byte offset: %" PRIu64 ")",
			PRAu64(physical_blocks[0]),
			PRAX64(physical_blocks[0]),
			PRAu64(physical_blocks[0] * block_index_unit));
	}
	/* v3: 0x18 */
	if(is_v3 && value_end - j >= 8) {
		logical_blocks[1] = read_le64(&data[j]);
		physical_blocks[1] =
			logical_to_physical_block_number(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* u64 logical_block_number */
				logical_blocks[1]);

		j += print_le64_dechex("Block number 2", prefix, indent,
			data, &data[j]);
		emit(prefix, indent + 1, "-> Physical block: %" PRIu64 " / "
			"0x%" PRIX64 " (byte offset: %" PRIu64 ")",
			PRAu64(physical_blocks[1]),
			PRAX64(physical_blocks[1]),
			PRAu64(physical_blocks[1] * block_index_unit));
	}
	/* v3: 0x20 */
	if(is_v3 && value_end - j >= 8) {
		logical_blocks[2] = read_le64(&data[j]);
		physical_blocks[2] =
			logical_to_physical_block_number(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* u64 logical_block_number */
				logical_blocks[2]);

		j += print_le64_dechex("Block number 3", prefix, indent,
			data, &data[j]);
		emit(prefix, indent + 1,
			"-> Physical block: %" PRIu64 " / "
			"0x%" PRIX64 " (byte offset: "
			"%" PRIu64 ")",
			PRAu64(physical_blocks[2]),
			PRAX64(physical_blocks[2]),
			PRAu64(physical_blocks[2] * block_index_unit));
	}
	/* v3: 0x28 */
	if(is_v3 && value_end - j >= 8) {
		logical_blocks[3] = read_le64(&data[j]);
		physical_blocks[3] =
			logical_to_physical_block_number(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* u64 logical_block_number */
				logical_blocks[3]);

		j += print_le64_dechex("Block number 4", prefix, indent,
			data, &data[j]);
		emit(prefix, indent + 1,
			"-> Physical block: %" PRIu64 " / "
			"0x%" PRIX64 " (byte offset: "
			"%" PRIu64 ")",
			PRAu64(physical_blocks[3]),
			PRAX64(physical_blocks[3]),
			PRAu64(physical_blocks[3] * block_index_unit));
	}
	/* v1: 0x18 v3: 0x30 */
	if(value_end - j >= 8) {
		j += print_le64_hex("Flags", prefix, indent, data,
			&data[j]);
	}
	/* v1: 0x20 v3: 0x38 */
	if(value_end - j >= 8) {
		j += print_le64_hex("Checksum", prefix, indent, data,
			&data[j]);
	}

	/* v1: 0x28 v3: 0x40 */
	if(!logical_blocks[0]) {
		sys_log_warning("Logical block 0 is invalid as a first block.");
	}
	else if(!physical_blocks[0]) {
		sys_log_warning("Unable to map logical block %" PRIu64 " / "
			"0x%" PRIX64 " to physical block.",
			PRAu64(logical_blocks[0]),
			PRAX64(logical_blocks[0]));
	}
	else {
		const size_t bytes_per_read =
			sys_min(crawl_context->cluster_size,
			crawl_context->block_size);

		size_t bytes_read = 0;
		u8 k = 0;

		err = sys_malloc(crawl_context->block_size, &block);
		if(err) {
			sys_log_perror(err, "Error while allocating "
				"%" PRIu32 " byte block",
				PRAu32(crawl_context->block_size));
			goto out;
		}

		while(bytes_read < crawl_context->block_size) {
			sys_log_debug("Reading logical block %" PRIu64 " / "
				"physical block %" PRIu64 " into "
				"%" PRIuz "-byte buffer %p at buffer offset "
				"%" PRIuz,
				PRAu64(logical_blocks[k]),
				PRAu64(physical_blocks[k]),
				PRAuz(crawl_context->block_size),
				block,
				PRAuz(bytes_read));
			err = sys_device_pread(
				/* sys_device *dev */
				crawl_context->dev,
				/* u64 pos */
				physical_blocks[k] * block_index_unit,
				/* size_t count */
				bytes_per_read,
				/* void *b */
				&block[bytes_read]);
			if(err) {
				break;
			}

			bytes_read += bytes_per_read;
			++k;
		}

		if(err) {
			sys_log_perror(err, "Error while reading %" PRIuz " "
				"bytes from attribute block %" PRIu64 " "
				"(offset %" PRIu64 ")",
				PRAuz(crawl_context->block_size),
				PRAu64(physical_blocks[k]),
				PRAu64(physical_blocks[k] * block_index_unit));
			goto out;
		}

		emit(prefix, indent, "Attribute node @ block %" PRIu64 " / "
			"0x%" PRIX64 ":",
			PRAu64(logical_blocks[0]), PRAX64(logical_blocks[0]));

		err = parse_generic_block(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* size_t indent */
			indent + 1,
			/* u64 cluster_number */
			physical_blocks[0],
			/* u64 block_number */
			logical_blocks[0],
			/* u64 block_queue_index */
			0 /* Different block queue... */,
			/* u8 level */
			4,
			/* const u8 *block */
			block,
			/* u32 block_size */
			crawl_context->block_size,
			/* block_queue *block_queue */
			NULL,
			/* sys_bool add_subnodes_in_offsets_order */
			SYS_TRUE,
			/* void *context */
			context,
			/* int (*parse_key)(
			 *      refs_node_crawl_context *crawl_context,
			 *      refs_node_walk_visitor *visitor,
			 *      const char *prefix,
			 *      size_t indent,
			 *      u64 object_id,
			 *      sys_bool is_index,
			 *      sys_bool is_v3,
			 *      const u8 *key,
			 *      u16 key_offset,
			 *      u16 key_size,
			 *      u32 entry_size,
			 *      void *context) */
			parse_attribute_key,
			/* int (*parse_leaf_value)(
			 *      refs_node_crawl_context *crawl_context,
			 *      refs_node_walk_visitor *visitor,
			 *      const char *prefix,
			 *      size_t indent,
			 *      u64 object_id,
			 *      const u8 *key,
			 *      u16 key_size,
			 *      const u8 *value,
			 *      u16 value_offset,
			 *      u16 value_size,
			 *      u16 entry_offset,
			 *      u32 entry_size,
			 *      void *context) */
			parse_attribute_leaf_value,
			/* int (*leaf_entry_handler)(
			 *      void *context,
			 *      const u8 *data,
			 *      u32 data_size,
			 *      u32 node_type) */
			NULL);
		if(err) {
			sys_log_perror(err, "Error while parsing non-resident "
				"attribute list");
			goto out;
		}
	}

	*jp = j;
out:
	if(block) {
		sys_free(&block);
	}

	return err;
}

static int parse_attribute_leaf_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u16 entry_offset,
		const u32 entry_size,
		void *const context)
{
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 attribute_type_offset = is_v3 ? 0x0C : 0x08;
	const u16 attribute_type =
		(key_size >= attribute_type_offset + 2) ?
		read_le16(&key[attribute_type_offset]) : 0;

	int err = 0;
	u16 j = 0;
	char *cstr = NULL;
	size_t cstr_length = 0;

	(void) object_id;
	(void) value_offset;
	(void) entry_offset;
	(void) entry_size;
	(void) context;

	emit(prefix, indent - 1, "Value (attribute) @ %" PRIu16 " / "
		"0x%" PRIX16 ":",
		PRAu16(value_offset), PRAX16(value_offset));

#if 0
	if(attribute_index - 1 == 1 &&
		key_size >= j + 0x08)
	{
#if 1
		/* This has the same layout as the allocation entry in a
		 * node. */
		err = parse_block_allocation_entry(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* size_t indent */
			indent,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *entry */
			&key[j],
			/* u32 entry_size */
			key_size,
			/* u32 entry_offset */
			offset_in_value,
			/* u32 *out_flags */
			NULL,
			/* u32 *out_value_offsets_start */
			NULL,
			/* u32 *out_value_offsets_end */
			NULL,
			/* u32 *out_value_count */
			&number_of_attributes);
		if(err) {
			goto out;
		}

		j += key_size;
#else
		j += print_unknown32(prefix, indent, key,
			&key[j]);
		number_of_attributes = read_le16(&key[j]);
		j += print_le16_dechex("Number of attributes", prefix,
			indent, key, &key[j]);
		j += print_unknown16(prefix, indent, key,
			&key[j]);
		j += print_unknown64(prefix, indent, key,
			&key[j]);
		if(key_size - j >= 0x8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]);
		}
		if(key_size - j >= 0x8) {
			j += print_unknown64(prefix, indent,
				key, &key[j]);
		}
#endif
	}
	else
#endif
	if(attribute_type == 0x0080) {
		/* Data stream. */
#if 1
		u16 data_stream_type;
#else
		u32 number_of_extents = 0;
		u32 k;
#endif

		sys_log_debug("Parsing data stream value.");

#if 0
		j += print_unknown64(prefix, indent, key,
			&key[j]); /* 0x10 */
		j += print_unknown16(prefix, indent, key,
			&key[j]); /* 0x18 */
		j += print_unknown16(prefix, indent, key,
			&key[j]); /* 0x1A */
		j += print_le16_hex("Attribute type (unnamed $DATA)", prefix,
			indent, key,
			&key[j]); /* 0x1C */
		j += print_unknown16(prefix, indent, key,
			&key[j]); /* 0x1E */
		j += print_unknown64(prefix, indent, key,
			&key[j]); /* 0x20 */
		j += print_unknown64(prefix, indent, key,
			&key[j]); /* 0x28 */
		j += print_unknown64(prefix, indent, key,
			&key[j]); /* 0x30 */
		/* Key ends here. */
#endif
#if 1
		data_stream_type = read_le16(&key[0x08]);
		sys_log_debug("Data stream type: 0x%" PRIX16,
			PRAX16(data_stream_type));

		if(is_v3 && data_stream_type == 0x1) {
			err = parse_attribute_resident_data_value(
				/* refs_node_crawl_context
				 * *crawl_context */
				crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* const u8 *value */
				value,
				/* u16 value_size */
				value_size,
				/* u16 *jp */
				&j);
			if(err) {
				goto out;
			}
		}
		else {
			err = parse_attribute_non_resident_data_value(
				/* refs_node_crawl_context
				 * *crawl_context */
				crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* const u8 *value */
				value,
				/* u16 value_size */
				value_size,
				/* u16 *jp */
				&j);
			if(err) {
				goto out;
			}
		}
#else
		j += print_unknown32(prefix, indent, value,
			&value[j]); /* 0x38 */
		j += print_unknown32(prefix, indent, value,
			&value[j]); /* 0x3C */
		j += print_unknown32(prefix, indent, value,
			&value[j]); /* 0x40 */
		j += print_unknown32(prefix, indent, value,
			&value[j]); /* 0x44 */
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x48 */
		}
		if(value_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				value, &value[j]); /* 0x4C */
		}
		if(value_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				value, &value[j]); /* 0x4E */
		}
		if(value_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				value, &value[j]); /* 0x50 */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Number of clusters",
				prefix, indent,
				value, &value[j]); /* 0x58 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x60 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x64 */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Allocated size (1)",
				prefix, indent,
				value, &value[j]); /* 0x68 */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Allocated size (2)",
				prefix, indent,
				value, &value[j]); /* 0x70 */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Allocated size (3)",
				prefix, indent,
				value, &value[j]); /* 0x78 */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Allocated size (4)",
				prefix, indent,
				value, &value[j]); /* 0x80 */
		}
		if(value_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				value, &value[j]); /* 0x88 */
		}
		if(value_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				value, &value[j]); /* 0x90 */
		}
		if(value_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				value, &value[j]); /* 0x98 */
		}
		if(value_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				value, &value[j]); /* 0xA0 */
		}
		if(value_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				value, &value[j]); /* 0xA8 */
		}
		if(value_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				value, &value[j]); /* 0xB0 */
		}
		if(value_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				value, &value[j]); /* 0xB8 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xC0 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xC4 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xC8 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xCC */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xD0 */
		}
		if(value_size - j >= 4) {
			number_of_extents = read_le32(&value[j]);
			j += print_le32_dechex("Number of extents",
				prefix, indent,
				value, &value[j]); /* 0xD4 */
		}
		if(value_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				value, &value[j]); /* 0xD8 */
		}
		if(value_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				value, &value[j]); /* 0xE0 */
		}

		for(k = 0; k < number_of_extents; ++k) {
			u64 first_block = 0;
			u32 block_count = 0;

			emit(prefix, indent, "Extent %" PRIu32 "/"
				"%" PRIu32 ":",
				PRAu32(k + 1),
				PRAu32(number_of_extents));
			if(value_size - j >= 8) {
				first_block =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					read_le64(&value[j]));
				j += print_le64_dechex("Extent start physical "
					"block value",
					prefix, indent + 1, value, &value[j]);
				emit(prefix, indent + 3, "Actual physical "
					"block: %" PRIu64 " / 0x%" PRIX64 " "
					"(byte offset: %" PRIu64 ")",
					PRAu64(first_block),
					PRAX64(first_block),
					PRAu64(first_block * block_index_unit));
			}
			else {
				break;
			}

			if(value_size - j >= 4) {
				j += print_le32_dechex("Flags (?)",
					prefix, indent + 1, value,
					&value[j]);
			}
			else {
				break;
			}

			if(value_size - j >= 8) {
				/* XXX: Misaligned? */
				j += print_le64_dechex("Extent start "
					"logical block", prefix,
					indent + 1, value,
					&value[j]);
			}
			else {
				break;
			}

			if(value_size - j >= 4) {
				block_count = read_le32(&value[j]);
				j += print_le32_dechex("Extent block "
					"count (?)", prefix, indent + 1,
					value, &value[j]);
			}
			else {
				break;
			}

			if(first_block && block_count && visitor &&
				visitor->node_file_extent)
			{
				err = visitor->node_file_extent(
					/* void *context */
					visitor->context,
					/* u64 first_block */
					first_block,
					/* u64 block_count */
					block_count,
					/* u32 block_index_unit */
					block_index_unit);
				if(err) {
					goto out;
				}
			}
		}

		if(number_of_extents) {
			if(value_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					value, &value[j]);
			}
			if(value_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					value, &value[j]);
			}
			if(value_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					value, &value[j]);
			}
			if(value_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					value, &value[j]);
			}
			if(value_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					value, &value[j]);
			}
			if(value_size - j >= 4) {
				j += print_unknown32(prefix, indent,
					value, &value[j]);
			}
		}
#endif
	}
#if 0
	else if(key_offset == 0x0010 && key_size == 0x000E) {
		/* This attribute type seems to hold extent info. */
		u64 first_block = 0;
		u64 block_count = 0;

		j += parse_level3_extent_value(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u32 block_index_unit */
			block_index_unit,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *value */
			value,
			/* size_t value_size */
			value_size,
			/* u64 *out_first_block */
			&first_block,
			/* u64 *out_block_count */
			&block_count);
		if(first_block && block_count && visitor &&
			visitor->node_file_extent)
		{
			err = visitor->node_file_extent(
				/* void *context */
				visitor->context,
				/* u64 first_block */
				first_block,
				/* u64 block_count */
				block_count,
				/* u32 block_index_unit */
				block_index_unit);
			if(err) {
				goto out;
			}
		}
	}
	else if(key_offset == 0x0010 && key_size == 0x0010 &&
		stream_type == 0x0080)
	{
		/* This attribute type appears to be inline data for the
		 * data stream. */
		u64 file_size = 0;

#if 0
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x10 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x14 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x18 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x1A */
		}
		if(key_size - j >= 4) {
			j += print_le32_dechex("Attribute type ($DATA)",
				prefix, indent,
				key, &key[j]); /* 0x1C */
		}
		/* Key ends here (?). */
#endif
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x20 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x24 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x28 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x2C */
		}
		if(value_size - j >= 8) {
			j += print_unknown64(prefix, indent,
				value, &value[j]); /* 0x30 */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Allocated size (1)",
				prefix, indent,
				value, &value[j]); /* 0x38 */
		}
		if(value_size - j >= 8) {
			file_size = read_le64(&value[j]);
			j += print_le64_dechex("Logical size (1)",
				prefix, indent,
				value, &value[j]); /* 0x40 */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Logical size (2)",
				prefix, indent,
				value, &value[j]); /* 0x48 */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Allocated size (2)",
				prefix, indent,
				value, &value[j]); /* 0x50 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x58 */
		}

		emit(prefix, indent + 1, "Resident data @ %" PRIu16 " / "
			"0x%" PRIX16, PRAu16(j), PRAX16(j));
		if(value_size > j) {
			const size_t resident_bytes =
				sys_min(file_size, (u16) (value_size - j));

			print_data_with_base(prefix, indent + 2, 0,
				resident_bytes, &value[j], resident_bytes);

			if(visitor && visitor->node_file_data) {
				err = visitor->node_file_data(
					/* void *context */
					visitor->context,
					/* const void *data */
					&value[j],
					/* size_t size */
					resident_bytes);
				if(err) {
					goto out;
				}
			}

			j += resident_bytes;
		}
	}
#endif
	else if(attribute_type == 0x00E0) {
		/* This attribute type appears to be inline data for the
		 * EA stream. Likely same format as the above. */
		sys_log_debug("Parsing $EA attribute value.");

#if 0
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x10 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x14 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x16 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x18 */
		}
		if(key_size - j >= 4) {
			j += print_le32_dechex("Stream type ($EA)",
				prefix, indent,
				key, &key[j]); /* 0x1C */
		}
		/* Key ends here. */
#endif
#if 0
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x20 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x24 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x28 */
		}

		/* After this, the EA list starts. */
		while(value_size - j >= 8) {
			u32 offset_to_next_ea = 0;
			u32 ea_end_offset = 0;
			u8 name_length = 0;
			u16 data_length = 0;
			const char *name = NULL;
			const void *data = NULL;

			if(value_size - j >= 4) {
				offset_to_next_ea =
					read_le32(&value[j]);
				ea_end_offset = j + offset_to_next_ea;
				j += print_le32_dechex("Offset to next "
					"EA", prefix, indent,
					value, &value[j]);
				if(ea_end_offset > value_size) {
					sys_log_warning("Offset to "
						"next EA is outside "
						"the bounds of the "
						"attribute: "
						"%" PRIu32 " > "
						"%" PRIu32,
						PRAu32(ea_end_offset),
						PRAu32(value_size));
					ea_end_offset = value_size;
				}
				else if(ea_end_offset <= j) {
					break;
				}
			}
			if(ea_end_offset - j >= 1) {
				j += print_u8_dechex("Flags", prefix,
					indent,
					value, &value[j]);
			}
			if(ea_end_offset - j >= 1) {
				name_length = value[j];
				j += print_u8_dechex("Name length",
					prefix, indent,
					value, &value[j]);
			}
			if(name_length > ea_end_offset - j) {
				sys_log_warning("Name length exceeds "
					"EA bounds: %" PRIu8 " > "
					"%" PRIu32,
					PRAu8(name_length),
					PRAu32(ea_end_offset - j));
			}
			if(ea_end_offset - j >= 2) {
				data_length = read_le16(&value[j]);
				j += print_le16_dechex("Data length",
					prefix, indent,
					value, &value[j]);
			}
			name = (const char*) &value[j];
			emit(prefix, indent, "Name @ %" PRIuz " / "
				"0x%" PRIXz ": %" PRIbs,
				PRAuz(j), PRAXz(j),
				PRAbs(sys_min(ea_end_offset - j,
				name_length), &value[j]));
			if(ea_end_offset - j < name_length) {
				break;
			}
			if(ea_end_offset - j < 1) {
				break;
			}
			j += name_length;
			print_u8_hex("Null terminator", prefix,
				indent, value, &value[j]);
			++j;
			if(data_length > ea_end_offset - j) {
				sys_log_warning("data length exceeds "
					"EA bounds: %" PRIu8 " > "
					"%" PRIu32,
					PRAu8(data_length),
					PRAu32(ea_end_offset - j));
			}
			data = &value[j];
			emit(prefix, indent, "Data @ %" PRIuz " / "
				"0x%" PRIXz ":",
				PRAuz(j), PRAXz(j));
			print_data_with_base(prefix, indent + 1, 0,
				data_length, &value[j],
				sys_min(ea_end_offset - j,
				data_length));
			if(visitor && visitor->node_ea) {
				err = visitor->node_ea(
					/* void *context */
					visitor->context,
					/* const char *name */
					name,
					/* size_t name_length */
					name_length,
					/* const void *data */
					data,
					/* size_t data_size */
					data_length);
				if(err) {
					goto out;
				}
			}
			if(ea_end_offset - j < data_length) {
				break;
			}
			j += data_length;

			if(j < ea_end_offset) {
				print_data_with_base(prefix, indent,
					j, ea_end_offset,
					&value[j],
					ea_end_offset - j);
				j = ea_end_offset;
			}
		}
#endif
		err = parse_attribute_ea_value(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *data */
			value,
			/* u16 value_size */
			value_size,
			/* u16 *jp */
			&j);
		if(err) {
			goto out;
		}
	}
	else if(attribute_type == 0x00B0) {
		const u16 name_start = is_v3 ? 0x10 : 0xC;
		const u16 name_end = key_size;

#if 0
		u32 data_size = 0;
		sys_bool non_resident = SYS_FALSE;
#endif

		sys_log_debug("Parsing named stream value.");

		/* This attribute type contains data about alternate data
		 * streams. */
#if 0
		j += parse_level3_attribute_header(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* size_t remaining_in_value */
			remaining_in_value,
			/* const u8 *attribute */
			key,
			/* u16 attribute_size */
			entry_size,
			/* u16 attribute_index */
			attribute_index);
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x08 */
		}
		if(key_size - j >= 2) {
			value_offset = read_le16(&key[j]);
			j += print_le16_dechex("Value offset", prefix,
				indent, key,
				&key[j]); /* 0x0A */
		}
		if(key_size - j >= 4) {
			value_size = read_le32(&key[j]);
			j += print_le32_dechex("Value size (1)", prefix,
				indent, key,
				&key[j]); /* 0x0C */
		}
#endif
#if 0
		if(key_size - j >= 4) {
			j += print_le32_dechex("Value size (2)", prefix,
				indent, key,
				&key[j]); /* 0x10 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x14 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x16 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x18 */
		}
		if(key_size - j >= 4) {
			j += print_le16_dechex("Stream type (named "
				"$DATA)",
				prefix, indent,
				key, &key[j]); /* 0x1C */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent, key,
				&key[j]); /* 0x1E */
		}

#if 1 /* Not possible. Disable when confident. */
		if(j < name_start) {
			const u32 print_end =
				sys_min(name_start,
				key_size);
			print_data_with_base(prefix, indent, j,
				print_end, &key[j],
				print_end - j);
			j = print_end;
		}
#endif
#endif
		if(visitor && visitor->node_stream) {
			const u16 name_length =
				(name_end - name_start) / sizeof(refschar);
			err = sys_unistr_decode(
				/* const refschar *ins */
				(const refschar*) &key[name_start],
				/* size_t ins_len */
				name_length,
				/* char **outs */
				&cstr,
				/* size_t *outs_len */
				&cstr_length);
			if(err) {
				sys_log_perror(err, "Error while decoding name "
					"in attribute key");
				goto out;
			}

#if 0
			emit(prefix, indent, "Name @ %" PRIuz " / 0x%" PRIXz " "
				"(length: %" PRIuz "):",
				PRAuz(j), PRAXz(j), PRAuz(cstr_length));
			emit(prefix, indent + 1, "%" PRIbs,
				PRAbs(cstr_length, cstr));
			j += name_length * sizeof(refschar);
#endif
		}

#if 0
		if(j < key_size) {
			const u32 print_end = sys_min(key_size, key_size);
			print_data_with_base(prefix, indent, j, print_end,
				&key[j], print_end - j);
			j = print_end;
		}
#endif

#if 0
		emit(prefix, indent, "Value @ %" PRIuz " / "
			"0x%" PRIXz " (size: %" PRIuz " / "
			"0x%" PRIXz "):",
			PRAuz(j), PRAXz(j), PRAuz(value_size),
			PRAXz(value_size));
#endif

#if 1
		if(value_size - j >= 4) {
			err = parse_attribute_named_stream_value(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* const char *cstr */
				cstr,
				/* size_t cstr_length */
				cstr_length,
				/* const u8 *attribute */
				value,
				/* u16 value_size */
				value_size,
				/* u16 *jp */
				&j);
			if(err) {
				goto out;
			}
		}
#else
		if(value_size - j >= 4) {
			u32 flags;

			flags = read_le32(&value[j]);
			j += print_le32_dechex("Flags", prefix, indent,
				value, &value[j]);

			if(flags & 0x10000000UL) {
				flags &= ~0x10000000UL;
				emit(prefix, indent + 1, "NON_RESIDENT%s",
					flags ? " |" : "");
				non_resident = SYS_TRUE;
			}
			if(flags) {
				emit(prefix, indent + 1,
					"<unknown: 0x%" PRIu32 ">",
					PRAu32(flags));
			}
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_le32_dechex("Allocated size (1)", prefix,
				indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			data_size = read_le32(&value[j]);
			j += print_le32_dechex("Attribute size (1)", prefix,
				indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_le32_dechex("Attribute size (2)", prefix,
				indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_le32_dechex("Allocated size (2)", prefix,
				indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent, value, &value[j]);
		}
		if(value_size > j && !non_resident) {
			const u32 data_limit =
				sys_min(data_size, (u16) (value_size - j));
			refs_node_stream_data data;

			memset(&data, 0, sizeof(data));

			emit(prefix, indent, "Resident data @ %" PRIuz " / "
				"0x%" PRIXz " (length: %" PRIuz "):",
				PRAuz(j), PRAXz(j), PRAuz(data_size));

			data.resident = SYS_TRUE;
			data.data.resident = &value[j];

			if(visitor && visitor->node_stream) {
				err = visitor->node_stream(
					/* void *context */
					visitor->context,
					/* const char *name */
					cstr,
					/* size_t name_length */
					cstr_length,
					/* u64 data_size */
					data_size,
					/* const refs_node_stream_data
					 * *data_reference */
					&data);
				if(err) {
					goto out;
				}
			}

			print_data_with_base(prefix, indent + 1, j,
				j + data_limit, &value[j], data_limit);
			j += data_limit;
		}
		else if(non_resident) {
			u64 stream_id = 0;

			emit(prefix, indent, "Non-resident data @ %" PRIuz " / "
				"0x%" PRIXz " (length: %" PRIuz "):",
				PRAuz(j), PRAXz(j), PRAuz(data_size));
			if(value_size - j >= 4) {
				stream_id = read_le64(&value[j]);
				j += print_le64_dechex("Stream ID", prefix,
					indent + 1, value, &value[j]);
			}

			if(visitor && visitor->node_stream && stream_id) {
				refs_node_stream_data data;

				memset(&data, 0, sizeof(data));

				data.resident = SYS_FALSE;
				data.data.non_resident.stream_id = stream_id;

				err = visitor->node_stream(
					/* void *context */
					visitor->context,
					/* const char *name */
					cstr,
					/* size_t name_length */
					cstr_length,
					/* u64 data_size */
					data_size,
					/* const refs_node_stream_data
					 * *data_reference */
					&data);
				if(err) {
					goto out;
				}
			}
			if(value_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1, value,
					&value[j]);
			}
		}

		if(j < value_size) {
			print_data_with_base(prefix, indent, j, value_size,
				&value[j], value_size - j);
			j = value_size;
		}
#endif
	}
	else if(key_offset == 0x0010 && key_size == 0x50) {
#if 1
		const u64 stream_id = read_le64(&key[0x30]);
#else
		u64 stream_id = 0;
		u32 num_extents = 0;
		u32 k;
#endif

		sys_log_debug("Parsing named stream extent value.");

#if 0
		j += parse_level3_attribute_header(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* size_t remaining_in_value */
			remaining_in_value,
			/* const u8 *attribute */
			key,
			/* u16 attribute_size */
			entry_size,
			/* u16 attribute_index */
			attribute_index);
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x08 */
		}
		if(key_size - j >= 2) {
			j += print_le16_dechex("Value offset", prefix,
				indent, key,
				&key[j]); /* 0x0A */
		}
		if(key_size - j >= 4) {
			j += print_le32_dechex("Value size (1)", prefix,
				indent, key,
				&key[j]); /* 0x0C */
		}
#endif
#if 0
		if(key_size - j >= 4) {
			j += print_le32_dechex("Value size (2)", prefix,
				indent, key,
				&key[j]); /* 0x10 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x14 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x16 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x18 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x1C */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x20 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x24 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x28 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x2C */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x30 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x34 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x38 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x3C */
		}
		if(key_size - j >= 4) {
			stream_id = read_le64(&key[j]);
			j += print_le32_dechex("Stream ID",
				prefix, indent,
				key, &key[j]); /* 0x40 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x44 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x48 */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x4C */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x50 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x54 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x58 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x5C */
		}
#endif
#if 1
		if(value_size - j >= 4) {
			err = parse_attribute_named_stream_extent_value(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* u64 stream_id */
				stream_id,
				/* const u8 *attribute */
				value,
				/* u16 value_size */
				value_size,
				/* u16 *jp */
				&j);
			if(err) {
				goto out;
			}
		}
#else
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x60 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x64 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x68 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x6C */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x70 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x74 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x78 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x7C */
		}
		if(value_size - j >= 4) {
			j += print_le32_dechex("Number of extents",
				prefix, indent,
				value, &value[j]); /* 0x80 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x84 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x88 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x8C */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Allocated size (1)",
				prefix, indent,
				value, &value[j]); /* 0x90 */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Logical size (1)",
				prefix, indent,
				value, &value[j]); /* 0x98 */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Logical size (2)",
				prefix, indent,
				value, &value[j]); /* 0xA0 */
		}
		if(value_size - j >= 8) {
			j += print_le64_dechex("Allocated size (2)",
				prefix, indent,
				value, &value[j]); /* 0xA8 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xB0 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xB4 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xB8 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xBC */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xC0 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xC4 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xC8 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xCC */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xD0 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xD4 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xD8 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xDC */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xE0 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xE4 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xE8 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xEC */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xF0 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xF4 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0xF8 */
		}
		if(value_size - j >= 4) {
			num_extents = read_le32(&value[j]);
			j += print_le32_dechex("Number of extents (2)",
				prefix, indent,
				value, &value[j]); /* 0xFC */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x100 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x104 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x108 */
		}
		if(value_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				value, &value[j]); /* 0x10C */
		}

		/* Iterate over extents in stream. */
		for(k = 0; k < num_extents &&
			(value_size - j) >= 24; ++k)
		{
			const u64 first_physical_block =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					read_le64(&value[j]));
			/* TODO: Guessing that this is the number of
			 * clusters in the extent. Not sure about it. */
			const u32 cluster_count =
				read_le32(&value[j + 20]);

			emit(prefix, indent, "Extent %" PRIu32 "/"
				"%" PRIu32 ":",
				PRAu32(k + 1), PRAu32(num_extents));

			j += print_le64_dechex("First block", prefix,
				indent + 1,
				value, &value[j]); /* 0x110 */
			emit(prefix, indent + 2,
				"-> Physical block: %" PRIu64 " / "
				"0x%" PRIX64 " (byte offset: "
				"%" PRIu64 ")",
				PRAu64(first_physical_block),
				PRAX64(first_physical_block),
				PRAu64(first_physical_block *
				block_index_unit));
			if(visitor && visitor->node_stream_extent) {
				err = visitor->node_stream_extent(
					/* void *context */
					visitor->context,
					/* u64 stream_id */
					stream_id,
					/* u64 first_block */
					first_physical_block,
					/* u32 block_index_unit */
					block_index_unit,
					/* u32 cluster_count */
					cluster_count);
				if(err) {
					goto out;
				}
			}

			j += print_unknown32(prefix, indent + 1,
				value, &value[j]); /* 0x118 */

			j += print_unknown32(prefix, indent + 1,
				value, &value[j]); /* 0x11C */

			j += print_unknown32(prefix, indent + 1,
				value, &value[j]); /* 0x120 */

			j += print_le32_dechex("Number of clusters in "
				"extent (?)", prefix, indent + 1,
				value, &value[j]); /* 0x124 */
		}
#endif
	}
#if 0
	else if(key_offset == 0x10 && key_size == 0x00) {
		/* This appears to contain an independently allocated
		 * (non-resident) attribute list. */
		u64 logical_blocks[4] = { 0, 0, 0, 0 };
		u64 physical_blocks[4] = { 0, 0, 0, 0 };

#if 0
		j += parse_level3_attribute_header(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* size_t remaining_in_value */
			remaining_in_value,
			/* const u8 *attribute */
			key,
			/* u16 attribute_size */
			entry_size,
			/* u16 attribute_index */
			attribute_index);
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x08 */
		}
		if(key_size - j >= 2) {
			j += print_unknown16(prefix, indent,
				key, &key[j]); /* 0x0A */
		}
		if(key_size - j >= 4) {
			j += print_unknown32(prefix, indent,
				key, &key[j]); /* 0x0C */
		}
#endif
		if(value_size - j >= 8) {
			logical_blocks[0] = read_le64(&value[j]);
			physical_blocks[0] =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					logical_blocks[0]);

			j += print_le64_dechex("Block number 1", prefix,
				indent,
				value, &value[j]); /* 0x10 */
			emit(prefix, indent + 1,
				"-> Physical block: %" PRIu64 " / "
				"0x%" PRIX64 " (byte offset: "
				"%" PRIu64 ")",
				PRAu64(physical_blocks[0]),
				PRAX64(physical_blocks[0]),
				PRAu64(physical_blocks[0] *
				block_index_unit));
		}
		if(value_size - j >= 8) {
			logical_blocks[1] = read_le64(&value[j]);
			physical_blocks[1] =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					logical_blocks[1]);

			j += print_le64_dechex("Block number 2", prefix,
				indent,
				value, &value[j]); /* 0x18 */
			emit(prefix, indent + 1,
				"-> Physical block: %" PRIu64 " / "
				"0x%" PRIX64 " (byte offset: "
				"%" PRIu64 ")",
				PRAu64(physical_blocks[1]),
				PRAX64(physical_blocks[1]),
				PRAu64(physical_blocks[1] *
				block_index_unit));
		}
		if(value_size - j >= 8) {
			logical_blocks[2] = read_le64(&value[j]);
			physical_blocks[2] =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					logical_blocks[2]);

			j += print_le64_dechex("Block number 3", prefix,
				indent,
				value, &value[j]); /* 0x20 */
			emit(prefix, indent + 1,
				"-> Physical block: %" PRIu64 " / "
				"0x%" PRIX64 " (byte offset: "
				"%" PRIu64 ")",
				PRAu64(physical_blocks[2]),
				PRAX64(physical_blocks[2]),
				PRAu64(physical_blocks[2] *
				block_index_unit));
		}
		if(value_size - j >= 8) {
			logical_blocks[3] = read_le64(&value[j]);
			physical_blocks[3] =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* u64 logical_block_number */
					logical_blocks[3]);

			j += print_le64_dechex("Block number 4", prefix,
				indent,
				value, &value[j]); /* 0x28 */
			emit(prefix, indent + 1,
				"-> Physical block: %" PRIu64 " / "
				"0x%" PRIX64 " (byte offset: "
				"%" PRIu64 ")",
				PRAu64(physical_blocks[3]),
				PRAX64(physical_blocks[3]),
				PRAu64(physical_blocks[3] *
				block_index_unit));
		}
		if(value_size - j >= 8) {
			j += print_le64_hex("Flags", prefix,
				indent,
				value, &value[j]); /* 0x30 */
		}
		if(value_size - j >= 8) {
			j += print_le64_hex("Checksum", prefix,
				indent,
				value, &value[j]); /* 0x38 */
		}

/* Disable recursively finding more attribute blocks because of false
 * positives. Maybe we shouldn't do this in the first place, it doesn't make
 * much sense. */
#if 0
		if(logical_blocks[0]) {
			const size_t bytes_per_read =
				sys_min(crawl_context->cluster_size,
				crawl_context->block_size);

			u8 *block = NULL;
			size_t bytes_read = 0;
			u8 i = 0;

			err = sys_malloc(crawl_context->block_size,
				&block);
			if(err) {
				sys_log_perror(err, "Error while "
					"allocating %" PRIu32 " byte "
					"block",
					PRAu32(crawl_context->
					block_size));
				goto out;
			}

			while(bytes_read < crawl_context->block_size) {
				sys_log_debug("Reading logical block "
					"%" PRIu64 " / physical block "
					"%" PRIu64 " into "
					"%" PRIuz "-byte buffer %p at "
					"buffer offset %" PRIuz,
					PRAu64(logical_blocks[i]),
					PRAu64(physical_blocks[i]),
					PRAuz(crawl_context->
					block_size),
					block,
					PRAuz(bytes_read));
				err = sys_device_pread(
					/* sys_device *dev */
					crawl_context->dev,
					/* u64 pos */
					physical_blocks[i] *
					block_index_unit,
					/* size_t count */
					bytes_per_read,
					/* void *b */
					&block[bytes_read]);
				if(err) {
					break;
				}

				bytes_read += bytes_per_read;
				++i;
			}
			if(err) {
				sys_free(&block);
				sys_log_pwarning(err, "Error while "
					"reading %" PRIuz " bytes from "
					"attribute block %" PRIu64 " "
					"(offset %" PRIu64 ")",
					PRAuz(crawl_context->
					block_size),
					PRAu64(physical_blocks[i]),
					PRAu64(physical_blocks[i] *
					block_index_unit));
				goto out;
			}

			err = parse_generic_block(
				/* refs_node_crawl_context
				 *     *crawl_context */
				crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* size_t indent */
				indent + 1,
				/* u64 cluster_number */
				physical_blocks[0],
				/* u64 block_number */
				logical_blocks[0],
				/* u64 block_queue_index */
				0 /* Different block queue... */,
				/* u8 level */
				4,
				/* const u8 *block */
				block,
				/* u32 block_size */
				crawl_context->block_size,
				/* block_queue *block_queue */
				NULL,
				/* sys_bool
				 *     add_subnodes_in_offsets_order */
				SYS_TRUE,
				/* void *context */
				context,
				/* int (*parse_key)(
				 *      refs_node_crawl_context *crawl_context,
				 *      refs_node_walk_visitor *visitor,
				 *      const char *prefix,
				 *      size_t indent,
				 *      u64 object_id,
				 *      sys_bool is_index,
				 *      sys_bool is_v3,
				 *      const u8 *key,
				 *      u16 key_offset,
				 *      u16 key_size,
				 *      u32 entry_size,
				 *      void *context) */
				parse_attribute_key,
				/* int (*parse_leaf_value)(
				 *      refs_node_crawl_context
				 *          *crawl_context,
				 *      refs_node_walk_visitor *visitor,
				 *      const char *prefix,
				 *      size_t indent,
				 *      u64 object_id,
				 *      const u8 *key,
				 *      u16 key_offset,
				 *      u16 key_size,
				 *      const u8 *value,
				 *      u16 value_offset,
				 *      u16 value_size,
				 *      u16 entry_offset,
				 *      u32 entry_size,
				 *      void *context) */
				parse_attribute_leaf_value,
				/* int (*leaf_entry_handler)(
				 *      void *context,
				 *      const u8 *data,
				 *      u32 data_size,
				 *      u32 node_type) */
				NULL);
			sys_free(&block);
			if(err) {
				sys_log_pwarning(err, "Error while "
					"parsing non-resident "
					"attribute list");
				goto out;
			}
		}
#endif
	}
#endif
out:
	if(j < value_size) {
		print_data_with_base(prefix, indent, j, value_size, &value[j],
			value_size - j);
	}

	if(cstr) {
		sys_free(&cstr);
	}

	return err;
}

static u16 parse_level3_attribute_header(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const size_t remaining_in_value,
		const u8 *const attribute,
		const u16 attribute_size,
		const u16 attribute_index)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 remaining_in_attribute =
		sys_min(remaining_in_value, attribute_size);

	u16 j = 0;

	(void) attribute_index;

	if(remaining_in_attribute - j < 4) {
		goto out;
	}
	j += print_le32_dechex("Size", prefix, indent + 1, attribute,
		&attribute[j]); /* 0x00 */

	if(remaining_in_attribute - j < 2) {
		goto out;
	}
	j += print_le16_dechex("Key offset", prefix, indent + 1, attribute,
		&attribute[j]); /* 0x04 */

	if(remaining_in_attribute - j < 2) {
		goto out;
	}
	j += print_le16_dechex("Key size", prefix, indent + 1, attribute,
		&attribute[j]); /* 0x06 */

	if(remaining_in_attribute - j < 2) {
		goto out;
	}
	j += print_le16_dechex("Flags?", prefix, indent + 1, attribute,
		&attribute[j]); /* 0x08 */

	if(remaining_in_attribute - j < 2) {
		goto out;
	}
	j += print_le16_dechex("Value offset", prefix, indent + 1, attribute,
		&attribute[j]); /* 0x0A */

	if(remaining_in_attribute - j < 2) {
		goto out;
	}
	j += print_le16_dechex("Value size", prefix, indent + 1, attribute,
		&attribute[j]); /* 0x0C */

	if(remaining_in_attribute - j < 2) {
		goto out;
	}
	j += print_unknown16(prefix, indent + 1, attribute,
		&attribute[j]); /* 0x0E */
out:
	return j;
}

/**
 * Parse a reparse point attribute in a long entry.
 */
static int parse_reparse_point_attribute(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const size_t remaining_in_value,
		const u16 remaining_in_attribute,
		const u8 *const attribute,
		const u16 attribute_size,
		const u16 attribute_index,
		u16 *const jp)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 reparse_tag = 0;
	u16 reparse_data_size = 0;
	u16 j = *jp;

	j += parse_level3_attribute_header(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const char *prefix */
		prefix,
		/* size_t indent */
		indent,
		/* size_t remaining_in_value */
		remaining_in_value,
		/* const u8 *attribute */
		attribute,
		/* u16 attribute_size */
		attribute_size,
		/* u16 attribute_index */
		attribute_index);
	if(remaining_in_attribute - j >= 4) {
		j += print_le32_dechex("Value size (2)", prefix, indent + 1,
			attribute, &attribute[j]); /* 0x10 */
	}
	if(remaining_in_attribute - j >= 2) {
		j += print_unknown16(prefix, indent + 1, attribute,
			&attribute[j]); /* 0x14 */
	}
	if(remaining_in_attribute - j >= 2) {
		j += print_unknown16(prefix, indent + 1, attribute,
			&attribute[j]); /* 0x16 */
	}
	if(remaining_in_attribute - j >= 4) {
		j += print_unknown32(prefix, indent + 1, attribute,
			&attribute[j]); /* 0x18 */
	}
	if(remaining_in_attribute - j >= 4) {
		j += print_le32_dechex("Attribute type (reparse point data)",
			prefix, indent + 1, attribute,
			&attribute[j]); /* 0x1C */
	}
	if(remaining_in_attribute - j >= 4) {
		j += print_unknown32(prefix, indent + 1, attribute,
			&attribute[j]); /* 0x20 */
	}
	if(remaining_in_attribute - j >= 4) {
		j += print_unknown32(prefix, indent + 1, attribute,
			&attribute[j]); /* 0x24 */
	}
	if(remaining_in_attribute - j >= 4) {
		j += print_unknown32(prefix, indent + 1, attribute,
			&attribute[j]); /* 0x28 */
	}
	if(remaining_in_attribute - j >= 4) {
		const char *reparse_tag_string = NULL;

		reparse_tag = read_le32(&attribute[j]);

		j += print_le32_hex("Reparse tag", prefix, indent + 1,
			attribute, &attribute[j]); /* 0x2C */
		switch(reparse_tag) {
		case 0xA0000003UL:
			reparse_tag_string = "IO_REPARSE_TAG_MOUNT_POINT";
			break;
		case 0xA000000CUL:
			reparse_tag_string = "IO_REPARSE_TAG_SYMLINK";
			break;
		case 0xA000001DUL:
			reparse_tag_string = "IO_REPARSE_TAG_LX_SYMLINK";
			break;
		case 0x80000023UL:
			reparse_tag_string = "IO_REPARSE_TAG_AF_UNIX";
			break;
		case 0x80000024UL:
			reparse_tag_string = "IO_REPARSE_TAG_LX_FIFO";
			break;
		case 0x80000025UL:
			reparse_tag_string = "IO_REPARSE_TAG_LX_CHR";
			break;
		case 0x80000026UL:
			reparse_tag_string = "IO_REPARSE_TAG_LX_BLK";
			break;
		default:
			reparse_tag_string = "<unknown reparse tag>";
			break;
		}

		emit(prefix, indent + 2, "%s", reparse_tag_string);
	}
	if(remaining_in_attribute - j >= 2) {
		reparse_data_size = read_le16(&attribute[j]);
		j += print_le16_dechex("Reparse data size", prefix, indent + 1,
			attribute, &attribute[j]); /* 0x30 */
	}
	if(remaining_in_attribute - j >= 2) {
		j += print_le16_dechex("Reserved", prefix, indent + 1,
			attribute, &attribute[j]); /* 0x32 */
	}

	if(reparse_data_size > remaining_in_attribute - j) {
		sys_log_warning("Reparse data size extends beyond the bounds "
			"of the attribute. Reparse data size: %" PRIu16 " "
			"Remaining in attribute: %" PRIu16,
			PRAu16(reparse_data_size),
			PRAu16(remaining_in_attribute - j));
	}
	else if((reparse_tag == 0xA0000003UL || reparse_tag == 0xA000000CUL) &&
		(remaining_in_attribute - j) >=
		((reparse_tag == 0xA0000003UL) ? 8 : 12))
	{
		/* Mount point / symlink. */
		u16 substitute_name_offset = 0;
		u16 substitute_name_size = 0;
		u16 print_name_offset = 0;
		u16 print_name_size = 0;
		u32 flags = 0;
		u16 k = 0;
		u16 k_start = 0;

		substitute_name_offset = read_le16(&attribute[j + k]);
		k += print_le16_dechex("Substitute name offset", prefix,
			indent + 1, attribute, &attribute[j + k]); /* 0x34 */
		substitute_name_size = read_le16(&attribute[j + k]);
		k += print_le16_dechex("Substitute name size", prefix,
			indent + 1, attribute, &attribute[j + k]); /* 0x36 */
		print_name_offset = read_le16(&attribute[j + k]);
		k += print_le16_dechex("Print name offset", prefix, indent + 1,
			attribute, &attribute[j + k]); /* 0x38 */
		print_name_size = read_le16(&attribute[j + k]);
		k += print_le16_dechex("Print name size", prefix, indent + 1,
			attribute, &attribute[j + k]); /* 0x3A */
		if(reparse_tag == 0xA000000CUL) {
			/* Symlinks have an additional flags field. */
			flags = read_le32(&attribute[j + k]);
			k += print_le32_hex("Flags", prefix, indent + 1,
				attribute, &attribute[j + k]); /* 0x3C */
			if(flags & 0x00000001UL) {
				emit(prefix, indent + 2, "%s",
					"SYMLINK_FLAG_RELATIVE");
			}
		}

		k_start = k;
		while(k < reparse_data_size) {
			const u16 offset = k - k_start;
			const char *name_label = NULL;
			u16 name_size;
			char *cname = NULL;
			size_t cname_length = 0;

			if(offset == substitute_name_offset) {
				name_label = "Substitute name";
				name_size = substitute_name_size;
			}
			else if(offset == print_name_offset) {
				name_label = "Print name";
				name_size = print_name_size;
			}

			if(name_label) {
				err = sys_unistr_decode(
					/* const refschar *ins */
					(const refschar*) &attribute[j + k],
					/* size_t ins_len */
					name_size / sizeof(refschar),
					/* char **outs */
					&cname,
					/* size_t *outs_len */
					&cname_length);
				if(err) {
					sys_log_pwarning(err, "Error while "
						"decoding '%s'", name_label);
					err = 0;
					name_label = NULL;
				}
			}

			if(!name_label) {
				const u16 min_offset =
					sys_min(substitute_name_offset,
					print_name_offset);
				const u16 max_offset =
					sys_max(substitute_name_offset,
					print_name_offset);
				const u16 next_offset =
					(offset < min_offset) ? min_offset :
					((offset < max_offset) ? max_offset :
					(reparse_data_size - k_start));

				if(k - k_start >= max_offset) {
					break;
				}

				print_data_with_base(prefix, indent + 1, j + k,
					remaining_in_attribute,
					&attribute[j + k],
					k_start + next_offset - k);

				k = k_start + next_offset;
				continue;
			}

			if(visitor && visitor->node_symlink &&
				offset == print_name_offset)
			{
				err = visitor->node_symlink(
					/* void *context */
					visitor->context,
					/* refs_symlink_type type */
					(reparse_tag != 0xA000000CUL) ?
					REFS_SYMLINK_TYPE_JUNCTION :
					((flags & 0x00000001UL) ?
					REFS_SYMLINK_TYPE_SYMLINK_RELATIVE :
					REFS_SYMLINK_TYPE_SYMLINK_ABSOLUTE),
					/* const char *target */
					cname,
					/* size_t target_length */
					cname_length);
				if(err) {
					goto out;
				}
			}

			emit(prefix, indent + 1, "%s @ %" PRIu16 " / "
				"0x%" PRIX16 ": %" PRIbs,
				name_label, PRAu16(j + k), PRAX16(j + k),
				PRAbs(cname_length, cname));
			sys_free(&cname);
			k += name_size;
		}

		j += k;
	}
	else if(reparse_tag == 0xA000001D && (remaining_in_attribute - j) >= 4)
	{
		/* WSL symlink. */
		const u16 wsl_string_size = reparse_data_size - 4;

		j += print_le32_dechex("Type", prefix, indent + 1, attribute,
			&attribute[j]); /* 0x34 */

		if(visitor && visitor->node_symlink) {
			err = visitor->node_symlink(
				/* void *context */
				visitor->context,
				/* refs_symlink_type type */
				REFS_SYMLINK_TYPE_WSL,
				/* const char *target */
				(const char*) &attribute[j],
				/* size_t target_length */
				wsl_string_size);
			if(err) {
				goto out;
			}
		}

		emit(prefix, indent + 1, "Symlink data: %" PRIbs,
			PRAbs(wsl_string_size, &attribute[j]));
		j += wsl_string_size;
	}

	*jp = j;
out:
	return err;
}

/**
 * Parse a long level 3 tree entry value.
 *
 * Long values (type 1) are in all known instances files or links/reparse
 * points.
 */
int parse_level3_long_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 parent_node_object_id,
		const u16 entry_offset,
		const u8 *const key,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		void *const context)
{
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	const u16 key_type = (key_size < 2) ? 0 : read_le16(&key[0]);
	const u64 creation_time =
		(value_size < 40 + 8) ? 0 : read_le64(&value[40]);
	const u64 last_access_time =
		(value_size < 48 + 8) ? 0 : read_le64(&value[48]);
	const u64 last_data_modification_time =
		(value_size < 56 + 8) ? 0 : read_le64(&value[56]);
	const u64 last_mft_modification_time =
		(value_size < 64 + 8) ? 0 : read_le64(&value[64]);
	const u32 file_flags =
		(value_size < 72 + 4) ? 0 : read_le32(&value[72]);
	const u64 file_size =
		(value_size < (is_v3 ? 88 : 104) + 8) ? 0 :
		read_le64(&value[is_v3 ? 88 : 104]);
	const u64 allocated_size =
		(value_size < (is_v3 ? 96 : 112) + 8) ? 0 :
		read_le64(&value[is_v3 ? 96 : 112]);

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 i = 0;
	size_t cur_attribute_end = 0;
	u16 attribute_size = 0;
	u16 attribute_index = 0;
	u32 attributes_offset = 0;
	u32 number_of_attributes = 0;
	u16 offsets_start = 0;
	u16 j = 0;
	char *cstr = NULL;

	(void) context;

	sys_log_debug("Long value for key type 0x%" PRIX16 ".",
		PRAX16(key_type));

	if(visitor && key_type == 0x0030U && visitor->node_long_entry) {
		err = visitor->node_long_entry(
			/* void *context */
			visitor->context,
			/* const refschar *file_name */
			(const refschar*) &key[4],
			/* u16 file_name_length */
			(key_size - 4) / sizeof(refschar),
			/* u16 child_entry_offset */
			entry_offset,
			/* u32 file_flags */
			file_flags,
			/* u64 parent_node_object_id */
			parent_node_object_id,
			/* u64 create_time */
			creation_time,
			/* u64 last_access_time */
			last_access_time,
			/* u64 last_write_time */
			last_data_modification_time,
			/* u64 last_mft_change_time */
			last_mft_modification_time,
			/* u64 file_size */
			file_size,
			/* u64 allocated_size */
			allocated_size,
			/* const u8 *key */
			key,
			/* size_t key_size */
			key_size,
			/* const u8 *record */
			value,
			/* size_t record_size */
			value_size);
		if(err) {
			goto out;
		}
	}
	else if(visitor && key_type == 0x0040U && key_size >= 24 &&
		visitor->node_hardlink_entry)
	{
		const u64 hard_link_id = read_le64(&key[8]);
		const u64 parent_id = read_le64(&key[16]);

		err = visitor->node_hardlink_entry(
			/* void *context */
			visitor->context,
			/* u64 hard_link_id */
			hard_link_id,
			/* u64 parent_id */
			parent_id,
			/* u16 child_entry_offset */
			entry_offset,
			/* u32 file_flags */
			file_flags,
			/* u64 create_time */
			creation_time,
			/* u64 last_access_time */
			last_access_time,
			/* u64 last_write_time */
			last_data_modification_time,
			/* u64 last_mft_change_time */
			last_mft_modification_time,
			/* u64 file_size */
			file_size,
			/* u64 allocated_size */
			allocated_size,
			/* const u8 *key */
			key,
			/* size_t key_size */
			key_size,
			/* const u8 *record */
			value,
			/* size_t record_size */
			value_size);
		if(err) {
			goto out;
		}
	}

	emit(prefix, indent - 1, "Value (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		entry_type_to_string(0x1), PRAu16(value_offset),
		PRAX16(value_offset));

	emit(prefix, indent, "Basic information @ 0 / 0x0:");
	++attribute_index;

	/* This field has the observed values 0 and 168 / 0xA8 with the latter
	 * occurring the most (about 20 times more often than the value 0). */
	attribute_size = read_le16(&value[0]);
	emit(prefix, indent + 1, "Attribute size: %" PRIu16 " / 0x%" PRIX16,
		PRAu16(attribute_size), PRAX16(attribute_size));

	cur_attribute_end =
		(attribute_size && attribute_size < value_size) ?
		attribute_size : value_size;

	if(attribute_size >= 120) {
		print_unknown16(prefix, indent + 1, value, &value[2]);

		/* This field has the value 65576 / 0x10028 in all observed
		 * instances.
		 * It's possible that these are 2 16-bit fields with values 0x28
		 * followed by 0x1. */
		print_unknown32(prefix, indent + 1, value, &value[4]);

		/* This field has the value 1 / 0x1 in in all observed
		 * instances. */
		print_unknown32(prefix, indent + 1, value, &value[8]);

		/* This field has the value 448 / 0x1C0 in all but 3 observed
		 * instances. The remaining 3 instances have the value 0. */
		print_unknown32(prefix, indent + 1, value, &value[12]);

		/* This field has the value 448 / 0x1C0 in all observed
		 * instances. */
		print_unknown32(prefix, indent + 1, value, &value[16]);

		/* This field has the value 2/ 0x2 in all observed instances. */
		print_unknown32(prefix, indent + 1, value, &value[20]);

		/* This field has the observed values 0 and 1 with 0 occurring
		 * about 4 times as often as 1. */
		print_unknown64(prefix, indent + 1, value, &value[24]);

		/* This field has the observed values 0, 2 and 4 with 0 being
		 * the most common, then 2, then 4.
		 * The value of this field appears to correlate with the change
		 * of meaning for some of the other fields, down around 256
		 * bytes into the struct. */
		print_unknown64(prefix, indent + 1, value, &value[32]);

		print_filetime(prefix, indent + 1,
			"Creation time",
			read_le64(&value[40]));
		print_filetime(prefix, indent + 1,
			"Last data modification time",
			read_le64(&value[48]));
		print_filetime(prefix, indent + 1,
			"Last MFT entry change time",
			read_le64(&value[56]));
		print_filetime(prefix, indent + 1,
			"Last access time",
			read_le64(&value[64]));
		print_file_flags(visitor, prefix, indent + 1, value,
			&value[72]);
		print_unknown32(prefix, indent + 1, value, &value[76]);

		/* Note: The object ID of a file is verified to partially match
		 * the output of fsutil file queryFileID in the low 64 bits of
		 * the 128 bit hex string.
		 * For example, an Object ID of 0x9B8 was printed by fsutil as:
		 *   0x0000000000000fed00000000000009b8
		 *
		 * I'm unsure what the high 64 bits displayed by fsutil (0xFED)
		 * represent, but the value is found in the header of some
		 * metadata blocks, at offset 72 (unknown field). It's not
		 * present in all metadata blocks but adjacent values are
		 * frequently found so it may be a metadata update version which
		 * is incremented on each full flush or something similar.
		 * Needs further investigation.
		 *
		 * Or could it be that this is the id / index in the node and
		 * that the file ID is composed of the parent directory's object
		 * ID and the index/ID in the parent directory?
		 */
		if(is_v3) {
			print_unknown32(prefix, indent + 1, value, &value[80]);
			print_unknown32(prefix, indent + 1, value, &value[84]);
			print_le64_dechex("File size", prefix, indent + 1, value,
				&value[88]);
			print_le64_dechex("Allocated size", prefix, indent + 1,
				value, &value[96]);
			print_unknown64(prefix, indent + 1, value,
				&value[104]);
			print_unknown64(prefix, indent + 1, value,
				&value[112]);
		}
		else {
			emit(prefix, indent + 1, "Parent object ID: "
				"%" PRIu64 " / 0x%" PRIX64,
				PRAu64(read_le64(&value[80])),
				PRAX64(read_le64(&value[80])));
			print_unknown64(prefix, indent + 1, value, &value[88]);
			print_unknown64(prefix, indent + 1, value, &value[96]);
			print_le64_dechex("File size", prefix, indent + 1,
				value, &value[104]);
			emit(prefix, indent + 1, "Allocated size: %" PRIu64,
				PRAu64(read_le64(&value[112])));
		}

		i += 120;
		/* Note: These three fields are connected but the meaning is
		 * unknown.
		 * When one is 0 all are 0 (most common value).
		 *
		 * In observations 120 and 124 always have the same value (even
		 * though they are different precision fields). When 120 is
		 * 0x79, then 124 is 0x79 (second most common value).
		 *
		 * Observed values for 126 (except 0) are (in order of
		 * occurrences):
		 *   0x5 0x7 0x4 0x6 */
		if(cur_attribute_end >= 0x7C) {
			i += print_unknown32(prefix, indent + 1, value,
				&value[0x78]);
		}
		if(cur_attribute_end >= 0x7E) {
			i += print_unknown16(prefix, indent + 1, value,
				&value[0x7C]);
		}
		if(cur_attribute_end >= 0x80) {
			i += print_unknown16(prefix, indent + 1, value,
				&value[0x7E]);
		}
		if(cur_attribute_end >= 0x88) {
			i += print_unknown64(prefix, indent + 1, value,
				&value[0x80]);
		}
		if(cur_attribute_end >= 0x90) {
			i += print_unknown64(prefix, indent + 1, value,
				&value[0x88]);
		}
		if(cur_attribute_end >= 0x98) {
			i += print_unknown64(prefix, indent + 1, value,
				&value[0x90]);
		}
		if(cur_attribute_end >= 0xA0) {
			i += print_unknown64(prefix, indent + 1, value,
				&value[0x98]);
		}
		if(cur_attribute_end >= 0xA8) {
			i += print_unknown64(prefix, indent + 1, value,
				&value[0xA0]);
		}
	}

	sys_log_debug("cur_attribute_end: %" PRIuz, PRAuz(cur_attribute_end));
	sys_log_debug("i: %" PRIuz, PRAuz(i));
	sys_log_debug("attribute_size: %" PRIu16, PRAu16(attribute_size));

	if(attribute_size < value_size &&
		i < attribute_size)
	{
		print_data_with_base(prefix, indent + 1, i, attribute_size,
			&value[i], attribute_size - i);
		i += attribute_size - i;
	}

	attributes_offset = i;

	while(i + 2 <= value_size && (attribute_index < 2 ||
		(u16) (attribute_index - 2) < number_of_attributes))
	{
		const size_t offset_in_value = i;
		const size_t remaining_in_value = value_size - offset_in_value;
		const u8 *const attribute = &value[offset_in_value];

		u16 remaining_in_attribute = 0;
		u16 attr_key_offset = 0;
		u16 attr_key_size = 0;
		u16 attr_value_offset = 0;
		u16 attr_value_size = 0;
		u16 attribute_type = 0;

		attribute_size = 0;
		if(remaining_in_value >= 2) {
			attribute_size = read_le16(&attribute[0]);
		}
		if(!attribute_size) {
			break;
		}

		remaining_in_attribute =
			(u16) sys_min(attribute_size, remaining_in_value);

		if(attribute_index >= 2) {
			attr_key_offset =
				(remaining_in_attribute >= 0x4 + 2) ?
				read_le16(&attribute[0x4]) : 0;
			attr_key_size =
				(remaining_in_attribute >= 0x6 + 2) ?
				read_le16(&attribute[0x6]) : 0;
			attr_value_offset =
				(remaining_in_attribute >= 0xA + 2) ?
				read_le16(&attribute[0xA]) : 0;
			attr_value_size =
				(remaining_in_attribute >= 0xC + 2) ?
				read_le16(&attribute[0xC]) : 0;
		}

		if(attribute_index == 1) {
			emit(prefix, indent, "Attribute header @ %" PRIuz " / "
				"0x%" PRIXz ":",
				PRAuz(offset_in_value),
				PRAXz(offset_in_value));
		}
		else {
			const u16 attribute_type_offset = is_v3 ? 0x1C : 0x18;

			if(remaining_in_attribute >= attribute_type_offset + 2)
			{
				attribute_type = read_le16(
					&attribute[attribute_type_offset]);
			}

			emit(prefix, indent, "Attribute %" PRIu16 " / "
				"%" PRIu32 " @ %" PRIuz " / 0x%" PRIXz ":",
				PRAu16((attribute_index - 2) + 1),
				PRAu32(number_of_attributes),
				PRAuz(offset_in_value),
				PRAXz(offset_in_value));
		}

		++attribute_index;

		j = 0;

		if(remaining_in_value < 8) {
			break;
		}

		if(attribute_index - 1 == 1 &&
			remaining_in_attribute >= j + 0x18)
		{
			/* This has the same layout as the allocation entry in a
			 * node. */
			err = parse_block_allocation_entry(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent + 1,
				/* sys_bool is_v3 */
				is_v3,
				/* const u8 *entry */
				&attribute[j],
				/* u32 entry_size */
				remaining_in_attribute,
				/* u32 entry_offset */
				offset_in_value,
				/* u32 *out_flags */
				NULL,
				/* u32 *out_value_offsets_start */
				NULL,
				/* u32 *out_value_offsets_end */
				NULL,
				/* u32 *out_value_count */
				&number_of_attributes);
			if(err) {
				goto out;
			}

			if(number_of_attributes > value_size) {
				sys_log_warning("Inconsistent number of "
					"attributes: %" PRIu32 " > %" PRIu16 " "
					"(size of value)",
					PRAu32(number_of_attributes),
					PRAu16(value_size));
				number_of_attributes = 0;
			}

			j += remaining_in_attribute;
		}
		else if(attribute_type == 0x0080) {
			u16 data_stream_type;

			sys_log_debug("Parsing data stream attribute.");

			j += parse_level3_attribute_header(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* size_t remaining_in_value */
				remaining_in_value,
				/* const u8 *attribute */
				attribute,
				/* u16 attribute_size */
				attribute_size,
				/* u16 attribute_index */
				attribute_index);

#if 1
			emit(prefix, indent + 1, "Key @ %" PRIuz " / "
				"0x%" PRIXz " (size: %" PRIuz " / "
				"0x%" PRIXz "):",
				PRAuz(j), PRAXz(j), PRAuz(attr_key_size),
				PRAXz(attr_key_size));
			err = parse_attribute_data_key(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent + 2,
				/* const u8 *key */
				attribute,
				/* u16 key_size */
				sys_min(remaining_in_attribute - j,
				attr_key_size),
				/* u16 *jp */
				&j);
			if(err) {
				goto out;
			}

			if(j < attr_value_offset) {
				const u32 print_end =
					sys_min(attr_value_offset,
					remaining_in_attribute);
				print_data_with_base(prefix, indent + 1, j,
					print_end, &attribute[j],
					print_end - j);
				j = print_end;
			}

			emit(prefix, indent + 1, "Value @ %" PRIuz " / "
				"0x%" PRIXz " (size: %" PRIuz " / "
				"0x%" PRIXz "):",
				PRAuz(j), PRAXz(j), PRAuz(attr_value_size),
				PRAXz(attr_value_size));
			data_stream_type =
				read_le16(&attribute[attr_key_offset + 0x08]);
			sys_log_debug("Data stream type: 0x%" PRIX16,
				PRAX16(data_stream_type));
			if(is_v3 && data_stream_type == 0x1) {
				err = parse_attribute_resident_data_value(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* refs_node_walk_visitor *visitor */
					visitor,
					/* const char *prefix */
					prefix,
					/* size_t indent */
					indent + 2,
					/* const u8 *value */
					attribute,
					/* u16 value_size */
					sys_min(remaining_in_attribute - j,
					attr_value_size),
					/* u16 *jp */
					&j);
				if(err) {
					goto out;
				}
			}
			else {
				err = parse_attribute_non_resident_data_value(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* refs_node_walk_visitor *visitor */
					visitor,
					/* const char *prefix */
					prefix,
					/* size_t indent */
					indent + 2,
					/* const u8 *value */
					attribute,
					/* u16 value_size */
					sys_min(remaining_in_attribute - j,
					attr_value_size),
					/* u16 *jp */
					&j);
				if(err) {
					goto out;
				}
			}
#else
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x08 */
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x0A */
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x0C */
			j += print_unknown64(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x10 */
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x18 */
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x1A */
			j += print_le16_hex("Attribute type (unnamed $DATA)",
				prefix, indent + 1, attribute,
				&attribute[j]); /* 0x1C */
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x1E */
			j += print_unknown64(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x20 */
			j += print_unknown64(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x28 */
			j += print_unknown64(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x30 */
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x38 */
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x3C */
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x40 */
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]); /* 0x44 */
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x48 */
			}
			if(attribute_size - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x4C */
			}
			if(attribute_size - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x4E */
			}
			if(attribute_size - j >= 8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x50 */
			}
			if(attribute_size - j >= 8) {
				j += print_le64_dechex("Number of clusters",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x58 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x60 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x64 */
			}
			if(attribute_size - j >= 8) {
				j += print_le64_dechex("Allocated size (1)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x68 */
			}
			if(attribute_size - j >= 8) {
				j += print_le64_dechex("Logical size (1)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x70 */
			}
			if(attribute_size - j >= 8) {
				j += print_le64_dechex("Logical size (2)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x78 */
			}
			if(attribute_size - j >= 8) {
				j += print_le64_dechex("Allocated size (2)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x80 */
			}
			if(attribute_size - j >= 8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x88 */
			}
			if(attribute_size - j >= 8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x90 */
			}
			if(attribute_size - j >= 8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x98 */
			}
			if(attribute_size - j >= 8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xA0 */
			}
			if(attribute_size - j >= 8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xA8 */
			}
			if(attribute_size - j >= 8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xB0 */
			}
			if(attribute_size - j >= 8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xB8 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xC0 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xC4 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xC8 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xCC */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xD0 */
			}
			if(attribute_size - j >= 4) {
				number_of_extents = read_le32(&attribute[j]);
				j += print_le32_dechex("Number of extents",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0xD4 */
			}
			if(attribute_size - j >= 8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xD8 */
			}
			if(attribute_size - j >= 8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xE0 */
			}

			for(k = 0; k < number_of_extents; ++k) {
				u64 first_block = 0;
				u32 block_count = 0;

				emit(prefix, indent + 1, "Extent %" PRIu32 "/"
					"%" PRIu32 ":",
					PRAu32(k + 1),
					PRAu32(number_of_extents));
				if(attribute_size - j >= 8) {
					first_block =
					logical_to_physical_block_number(
						/* refs_node_crawl_context
						 * *crawl_context */
						crawl_context,
						/* u64 logical_block_number */
						read_le64(&attribute[j]));
					j += print_le64_dechex("Extent start "
						"physical block value", prefix,
						indent + 2, attribute,
						&attribute[j]);
					emit(prefix, indent + 3, "Actual "
						"physical block: %" PRIu64 " / "
						"0x%" PRIX64 " (byte offset: "
						"%" PRIu64 ")",
						PRAu64(first_block),
						PRAX64(first_block),
						PRAu64(first_block *
						block_index_unit));
				}
				else {
					break;
				}

				if(attribute_size - j >= 4) {
					j += print_le32_dechex("Flags (?)",
						prefix, indent + 2, attribute,
						&attribute[j]);
				}
				else {
					break;
				}

				if(attribute_size - j >= 8) {
					/* XXX: Misaligned? */
					j += print_le64_dechex("Extent start "
						"logical block", prefix,
						indent + 2, attribute,
						&attribute[j]);
				}
				else {
					break;
				}

				if(attribute_size - j >= 4) {
					block_count = read_le32(&attribute[j]);
					j += print_le32_dechex("Extent block "
						"count (?)", prefix, indent + 2,
						attribute, &attribute[j]);
				}
				else {
					break;
				}

				if(first_block && block_count && visitor &&
					visitor->node_file_extent)
				{
					err = visitor->node_file_extent(
						/* void *context */
						visitor->context,
						/* u64 first_block */
						first_block,
						/* u64 block_count */
						block_count,
						/* u32 block_index_unit */
						block_index_unit);
					if(err) {
						goto out;
					}
				}
			}

			if(number_of_extents) {
				if(attribute_size - j >= 4) {
					j += print_unknown32(prefix, indent + 1,
						attribute, &attribute[j]);
				}
				if(attribute_size - j >= 4) {
					j += print_unknown32(prefix, indent + 1,
						attribute, &attribute[j]);
				}
				if(attribute_size - j >= 4) {
					j += print_unknown32(prefix, indent + 1,
						attribute, &attribute[j]);
				}
				if(attribute_size - j >= 4) {
					j += print_unknown32(prefix, indent + 1,
						attribute, &attribute[j]);
				}
				if(attribute_size - j >= 4) {
					j += print_unknown32(prefix, indent + 1,
						attribute, &attribute[j]);
				}
				if(attribute_size - j >= 4) {
					j += print_unknown32(prefix, indent + 1,
						attribute, &attribute[j]);
				}
			}
#endif
		}
#if 0
		else if(attr_key_offset == 0x0010 && attr_key_size == 0x000E) {
			/* This attribute type seems to hold extent info. */
			u64 first_block = 0;
			u64 block_count = 0;

			j += parse_level3_attribute_header(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* size_t remaining_in_value */
				remaining_in_value,
				/* const u8 *attribute */
				attribute,
				/* u16 attribute_size */
				attribute_size,
				/* u16 attribute_index */
				attribute_index);
			j += print_unknown32(prefix, indent, attribute,
				&attribute[0x8]);
			j += print_unknown32(prefix, indent, attribute,
				&attribute[0xC]);
			j += parse_level3_extent_attribute(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent + 1,
				/* u32 block_index_unit */
				block_index_unit,
				/* sys_bool is_v3 */
				is_v3,
				/* const u8 *attribute */
				attribute,
				/* size_t attribute_size */
				remaining_in_attribute,
				/* u64 *out_first_block */
				&first_block,
				/* u64 *out_block_count */
				&block_count);
			if(first_block && block_count && visitor &&
				visitor->node_file_extent)
			{
				err = visitor->node_file_extent(
					/* void *context */
					visitor->context,
					/* u64 first_block */
					first_block,
					/* u64 block_count */
					block_count,
					/* u32 block_index_unit */
					block_index_unit);
				if(err) {
					goto out;
				}
			}
		}
		else if(attr_key_offset == 0x0010 && attr_key_size == 0x0010 &&
			attribute_type == 0x0080)
		{
			/* This attribute type appears to be inline data for the
			 * data stream. */
			j += parse_level3_attribute_header(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* size_t remaining_in_value */
				remaining_in_value,
				/* const u8 *attribute */
				attribute,
				/* u16 attribute_size */
				attribute_size,
				/* u16 attribute_index */
				attribute_index);
			if(attribute_size - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x08 */
			}
			if(attribute_size - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x0A */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x0C */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x10 */
			}
			if(attribute_size - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x14 */
			}
			if(attribute_size - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x18 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x1A */
			}
			if(attribute_size - j >= 4) {
				j += print_le32_dechex("Attribute type "
					"(unnamed $DATA)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x1C */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x20 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x24 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x28 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x2C */
			}
			if(attribute_size - j >= 8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x30 */
			}
			if(attribute_size - j >= 8) {
				j += print_le64_dechex("Allocated size 1",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x38 */
			}
			if(attribute_size - j >= 8) {
				j += print_le64_dechex("Logical size 1",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x40 */
			}
			if(attribute_size - j >= 8) {
				j += print_le64_dechex("Logical size 2",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x48 */
			}
			if(attribute_size - j >= 8) {
				j += print_le64_dechex("Allocated size 2",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x50 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x58 */
			}

			emit(prefix, indent + 1, "Resident data @ %" PRIu16 " "
				"/ 0x%" PRIX16, PRAu16(j), PRAX16(j));
			if(attribute_size > j) {
				const size_t resident_bytes =
					sys_min(file_size,
					(u16) (attribute_size - j));

				print_data_with_base(prefix, indent + 2, 0,
					resident_bytes, &attribute[j],
					resident_bytes);

				if(visitor && visitor->node_file_data) {
					err = visitor->node_file_data(
						/* void *context */
						visitor->context,
						/* const void *data */
						&attribute[j],
						/* size_t size */
						resident_bytes);
					if(err) {
						goto out;
					}
				}

				j += resident_bytes;
			}
		}
#endif
		else if(attribute_type == 0x00E0) {
			/* This attribute type appears to be inline data for the
			 * EA stream. Likely same format as the above. */

			sys_log_debug("Parsing $EA attribute.");

			j += parse_level3_attribute_header(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* size_t remaining_in_value */
				remaining_in_value,
				/* const u8 *attribute */
				attribute,
				/* u16 attribute_size */
				attribute_size,
				/* u16 attribute_index */
				attribute_index);

#if 0
			if(attribute_size - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x08 */
			}
			if(attribute_size - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x0A */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x0C */
			}
#endif

			emit(prefix, indent + 1, "Key @ %" PRIuz " / "
				"0x%" PRIXz " (size: %" PRIuz " / "
				"0x%" PRIXz "):",
				PRAuz(j), PRAXz(j), PRAuz(attr_key_size),
				PRAXz(attr_key_size));
#if 1
			if(remaining_in_attribute - j >= 4) {
				err = parse_attribute_ea_key(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* refs_node_walk_visitor *visitor */
					visitor,
					/* const char *prefix */
					prefix,
					/* size_t indent */
					indent + 2,
					/* const u8 *data */
					attribute,
					/* u16 key_size */
					sys_min(remaining_in_attribute - j,
					attr_key_size),
					/* u16 *jp */
					&j);
				if(err) {
					goto out;
				}
			}
#else
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x10 */
			}
			if(attribute_size - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x14 */
			}
			if(attribute_size - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x16 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x18 */
			}
			if(attribute_size - j >= 4) {
				j += print_le32_dechex("Stream type ($EA)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x1C */
			}
#endif

			if(j < attr_value_offset) {
				const u32 print_end =
					sys_min(attr_value_offset,
					remaining_in_attribute);
				print_data_with_base(prefix, indent + 1, j,
					print_end, &attribute[j],
					print_end - j);
				j = print_end;
			}

			emit(prefix, indent + 1, "Value @ %" PRIuz " / "
				"0x%" PRIXz " (size: %" PRIuz " / "
				"0x%" PRIXz "):",
				PRAuz(j), PRAXz(j), PRAuz(attr_value_size),
				PRAXz(attr_value_size));

#if 1
			if(remaining_in_attribute - j >= 4) {
				err = parse_attribute_ea_value(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* refs_node_walk_visitor *visitor */
					visitor,
					/* const char *prefix */
					prefix,
					/* size_t indent */
					indent + 2,
					/* const u8 *data */
					attribute,
					/* u16 key_size */
					sys_min(remaining_in_attribute - j,
					attr_value_size),
					/* u16 *jp */
					&j);
				if(err) {
					goto out;
				}
			}
#else
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x20 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x24 */
			}
			if(attribute_size - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x28 */
			}

			/* After this, the EA list starts. */
			while(attribute_size - j >= 8) {
				u32 offset_to_next_ea = 0;
				u32 ea_end_offset = 0;
				u8 name_length = 0;
				u16 data_length = 0;
				const char *name = NULL;
				const void *data = NULL;

				if(attribute_size - j >= 4) {
					offset_to_next_ea =
						read_le32(&attribute[j]);
					ea_end_offset = j + offset_to_next_ea;
					j += print_le32_dechex("Offset to next "
						"EA", prefix, indent + 1,
						attribute, &attribute[j]);
					if(ea_end_offset > attribute_size) {
						sys_log_warning("Offset to "
							"next EA is outside "
							"the bounds of the "
							"attribute: "
							"%" PRIu32 " > "
							"%" PRIu32,
							PRAu32(ea_end_offset),
							PRAu32(attribute_size));
						ea_end_offset = attribute_size;
					}
					else if(ea_end_offset <= j) {
						break;
					}
				}
				if(ea_end_offset - j >= 1) {
					j += print_u8_dechex("Flags", prefix,
						indent + 1,
						attribute, &attribute[j]);
				}
				if(ea_end_offset - j >= 1) {
					name_length = attribute[j];
					j += print_u8_dechex("Name length",
						prefix, indent + 1,
						attribute, &attribute[j]);
				}
				if(name_length > ea_end_offset - j) {
					sys_log_warning("Name length exceeds "
						"EA bounds: %" PRIu8 " > "
						"%" PRIu32,
						PRAu8(name_length),
						PRAu32(ea_end_offset - j));
				}
				if(ea_end_offset - j >= 2) {
					data_length = read_le16(&attribute[j]);
					j += print_le16_dechex("Data length",
						prefix, indent + 1,
						attribute, &attribute[j]);
				}
				name = (const char*) &attribute[j];
				emit(prefix, indent + 1, "Name @ %" PRIuz " / "
					"0x%" PRIXz ": %" PRIbs,
					PRAuz(j), PRAXz(j),
					PRAbs(sys_min(ea_end_offset - j,
					name_length), &attribute[j]));
				if(ea_end_offset - j < name_length) {
					break;
				}
				j += name_length;
				if(ea_end_offset - j < 1) {
					break;
				}
				print_u8_hex("Null terminator", prefix,
					indent + 1, attribute, &attribute[j]);
				++j;
				if(data_length > ea_end_offset - j) {
					sys_log_warning("data length exceeds "
						"EA bounds: %" PRIu8 " > "
						"%" PRIu32,
						PRAu8(data_length),
						PRAu32(ea_end_offset - j));
				}
				data = &attribute[j];
				emit(prefix, indent + 1, "Data @ %" PRIuz " / "
					"0x%" PRIXz ":",
					PRAuz(j), PRAXz(j));
				print_data_with_base(prefix, indent + 2, 0,
					data_length, &attribute[j],
					sys_min(ea_end_offset - j,
					data_length));
				if(visitor && visitor->node_ea) {
					err = visitor->node_ea(
						/* void *context */
						visitor->context,
						/* const char *name */
						name,
						/* size_t name_length */
						name_length,
						/* const void *data */
						data,
						/* size_t data_size */
						data_length);
					if(err) {
						goto out;
					}
				}
				if(ea_end_offset - j < data_length) {
					break;
				}
				j += data_length;

				if(j < ea_end_offset) {
					print_data_with_base(prefix, indent + 1,
						j, ea_end_offset,
						&attribute[j],
						ea_end_offset - j);
					j = ea_end_offset;
				}
			}
#endif
		}
		else if(attribute_type == 0x00B0) {
#if 0
			const u16 name_start = attr_key_offset;
			const u16 name_end = attr_key_size;
#endif

#if 0
			u16 attr_value_offset = 0;
			u32 attr_value_size = 0;
			u32 real_name_offset = 0;
#endif
			size_t cstr_length = 0;
#if 0
			u32 data_size = 0;
			sys_bool non_resident = SYS_FALSE;
#endif

			sys_log_debug("Parsing named stream attribute.");

			/* This attribute type contains data relating to
			 * alternate data streams. */
			j += parse_level3_attribute_header(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* size_t remaining_in_value */
				remaining_in_value,
				/* const u8 *attribute */
				attribute,
				/* u16 attribute_size */
				attribute_size,
				/* u16 attribute_index */
				attribute_index);

#if 1
			emit(prefix, indent + 1, "Key @ %" PRIuz " / "
				"0x%" PRIXz " (size: %" PRIuz " / "
				"0x%" PRIXz "):",
				PRAuz(j), PRAXz(j), PRAuz(attr_key_size),
				PRAXz(attr_key_size));

			err = parse_attribute_named_stream_key(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent + 2,
				/* const u8 *attribute */
				attribute,
				/* u16 key_size */
				sys_min(remaining_in_attribute - j,
				attr_key_size),
				/* u16 *jp */
				&j,
				/* char **out_cstr */
				&cstr,
				/* size_t *out_cstr_length */
				&cstr_length);
			if(err) {
				goto out;
			}
#else
			if(remaining_in_attribute - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x08 */
			}
			if(remaining_in_attribute - j >= 2) {
				attr_value_offset = read_le16(&attribute[j]);
				j += print_le16_dechex("Value offset", prefix,
					indent + 1, attribute,
					&attribute[j]); /* 0x0A */
			}
			if(remaining_in_attribute - j >= 4) {
				attr_value_size = read_le32(&attribute[j]);
				j += print_le32_dechex("Value size (1)", prefix,
					indent + 1, attribute,
					&attribute[j]); /* 0x0C */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_le32_dechex("Value size (2)", prefix,
					indent + 1, attribute,
					&attribute[j]); /* 0x10 */
			}
			if(remaining_in_attribute - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x14 */
			}
			if(remaining_in_attribute - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x16 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x18 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_le32_dechex("Stream type (named "
					"$DATA)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x1C */
			}

			real_name_offset = 0x10 + name_start;
			if(j < real_name_offset) {
				const u32 print_end =
					sys_min(real_name_offset,
					remaining_in_attribute);
				print_data_with_base(prefix, indent + 1, j,
					print_end, &attribute[j],
					print_end - j);
				j = print_end;
			}

			if(remaining_in_attribute - j >= name_end - name_start)
			{
				err = sys_unistr_decode(
					/* const refschar *ins */
					(const refschar*) &attribute[0x10 +
					name_start],
					/* size_t ins_len */
					(name_end - name_start) /
					sizeof(refschar),
					/* char **outs */
					&cstr,
					/* size_t *outs_len */
					&cstr_length);
				if(err) {
					goto out;
				}
				else {
					emit(prefix, indent + 1, "Name @ "
						"%" PRIuz " / 0x%" PRIXz " "
						"(length: %" PRIuz "):",
						PRAuz(j), PRAXz(j),
						PRAuz(cstr_length));
					emit(prefix, indent + 2, "%" PRIbs,
						PRAbs(cstr_length, cstr));
					j += cstr_length * sizeof(refschar);
				}
			}
#endif

			if(j < attr_value_offset) {
				const u32 print_end =
					sys_min(attr_value_offset,
					remaining_in_attribute);
				print_data_with_base(prefix, indent + 1, j,
					print_end, &attribute[j],
					print_end - j);
				j = print_end;
			}

			emit(prefix, indent + 1, "Value @ %" PRIuz " / "
				"0x%" PRIXz " (size: %" PRIuz " / "
				"0x%" PRIXz "):",
				PRAuz(j), PRAXz(j), PRAuz(attr_value_size),
				PRAXz(attr_value_size));

#if 1
			if(remaining_in_attribute > j) {
				err = parse_attribute_named_stream_value(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* refs_node_walk_visitor *visitor */
					visitor,
					/* const char *prefix */
					prefix,
					/* size_t indent */
					indent + 2,
					/* const char *cstr */
					cstr,
					/* size_t cstr_length */
					cstr_length,
					/* const u8 *attribute */
					attribute,
					/* u16 value_size */
					sys_min(remaining_in_attribute - j,
					attr_value_size),
					/* u16 *jp */
					&j);
				if(err) {
					goto out;
				}
			}
#else
			if(remaining_in_attribute > j) {
				const u8 *const attr_value = &attribute[j];
				const u32 true_value_size =
					sys_min(attr_value_size,
					(u16) (remaining_in_attribute - j));
				u16 k = 0;

				if(true_value_size - k >= 4) {
					u32 flags;

					flags = read_le32(&attr_value[k]);
					k += print_le32_dechex("Flags", prefix,
						indent + 2, attr_value,
						&attr_value[k]);

					if(flags & 0x10000000UL) {
						flags &= ~0x10000000UL;
						emit(prefix, indent + 3,
							"NON_RESIDENT%s",
							flags ? " |" : "");
						non_resident = SYS_TRUE;
					}
					if(flags) {
						emit(prefix, indent + 3,
							"<unknown: "
							"0x%" PRIu32 ">",
							PRAu32(flags));
					}
				}
				if(true_value_size - k >= 4) {
					k += print_unknown32(prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_unknown32(prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_unknown32(prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_unknown32(prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_unknown32(prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_le32_dechex("Allocated size "
						"(1)", prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_unknown32(prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					data_size = read_le32(&attr_value[k]);
					k += print_le32_dechex("Attribute size "
						"(1)", prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_unknown32(prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_le32_dechex("Attribute size "
						"(2)", prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_unknown32(prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_le32_dechex("Allocated size "
						"(2)", prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_unknown32(prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k >= 4) {
					k += print_unknown32(prefix, indent + 2,
						attr_value, &attr_value[k]);
				}
				if(true_value_size - k > 0 && !non_resident) {
					const u32 data_limit =
						sys_min(data_size,
						attr_value_size - k);
					refs_node_stream_data data;

					memset(&data, 0, sizeof(data));

					emit(prefix, indent + 2, "Resident "
						"data @ %" PRIuz " / "
						"0x%" PRIXz " (length: "
						"%" PRIuz "):",
						PRAuz(k), PRAXz(k),
						PRAuz(data_size));

					data.resident = SYS_TRUE;
					data.data.resident = &attr_value[k];

					if(visitor && visitor->node_stream) {
						err = visitor->node_stream(
							/* void *context */
							visitor->context,
							/* const char *name */
							cstr,
							/* size_t name_length */
							cstr_length,
							/* u64 data_size */
							data_size,
							/* const
							 * refs_node_stream_data
							 * *data_reference */
							&data);
						if(err) {
							goto out;
						}
					}

					print_data_with_base(prefix, indent + 3,
						k, k + data_limit,
						&attr_value[k], data_limit);
					k += data_limit;
				}
				else if(non_resident) {
					u64 stream_id = 0;

					emit(prefix, indent + 2, "Non-resident "
						"data @ %" PRIuz " / "
						"0x%" PRIXz " (length: "
						"%" PRIuz "):",
						PRAuz(k), PRAXz(k),
						PRAuz(data_size));
					if(true_value_size - k >= 4) {
						stream_id =
							read_le64(
							&attr_value[k]);
						k += print_le64_dechex("Stream "
							"ID", prefix,
							indent + 3, attr_value,
							&attr_value[k]);
					}

					if(visitor && visitor->node_stream &&
						stream_id)
					{
						refs_node_stream_data data;

						memset(&data, 0, sizeof(data));

						data.resident = SYS_FALSE;
						data.data.non_resident.stream_id
							= stream_id;

						err = visitor->node_stream(
							/* void *context */
							visitor->context,
							/* const char *name */
							cstr,
							/* size_t name_length */
							cstr_length,
							/* u64 data_size */
							data_size,
							/* const
							 * refs_node_stream_data
							 * *data_reference */
							&data);
						if(err) {
							goto out;
						}
					}
					if(true_value_size - k >= 4) {
						k += print_unknown32(prefix,
							indent + 3, attr_value,
							&attr_value[k]);
					}
				}

				if(k < true_value_size) {
					print_data_with_base(prefix, indent + 2,
						k, true_value_size,
						&attr_value[k],
						true_value_size - k);
					k = true_value_size;
				}

				j += k;
			}
#endif
		}
		else if(attr_key_offset == 0x0010 && attr_key_size == 0x50) {
			u64 stream_id = 0;
#if 0
			u32 num_extents = 0;
			u32 k;
#endif

			sys_log_debug("Parsing named stream extent attribute.");

			j += parse_level3_attribute_header(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* size_t remaining_in_value */
				remaining_in_value,
				/* const u8 *attribute */
				attribute,
				/* u16 attribute_size */
				attribute_size,
				/* u16 attribute_index */
				attribute_index);

			emit(prefix, indent + 1, "Key @ %" PRIuz " / "
				"0x%" PRIXz " (size: %" PRIuz " / "
				"0x%" PRIXz "):",
				PRAuz(j), PRAXz(j), PRAuz(attr_key_size),
				PRAXz(attr_key_size));

#if 0
			if(remaining_in_attribute - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x08 */
			}
			if(remaining_in_attribute - j >= 2) {
				j += print_le16_dechex("Value offset", prefix,
					indent + 1, attribute,
					&attribute[j]); /* 0x0A */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_le32_dechex("Value size (1)", prefix,
					indent + 1, attribute,
					&attribute[j]); /* 0x0C */
			}
#endif

#if 1
			if(remaining_in_attribute - j >= 4) {
				err = parse_attribute_named_stream_extent_key(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* refs_node_walk_visitor *visitor */
					visitor,
					/* const char *prefix */
					prefix,
					/* size_t indent */
					indent + 2,
					/* const u8 *attribute */
					attribute,
					/* u16 value_size */
					sys_min(remaining_in_attribute - j,
					attr_key_size),
					/* u16 *jp */
					&j,
					/* u64 *out_stream_id */
					&stream_id);
				if(err) {
					goto out;
				}
			}
#else
			if(remaining_in_attribute - j >= 4) {
				j += print_le32_dechex("Value size (2)", prefix,
					indent + 1, attribute,
					&attribute[j]); /* 0x10 */
			}
			if(remaining_in_attribute - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x14 */
			}
			if(remaining_in_attribute - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x16 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x18 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x1C */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x20 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x24 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x28 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x2C */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x30 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x34 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x38 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x3C */
			}
			if(remaining_in_attribute - j >= 4) {
				stream_id = read_le64(&attribute[j]);
				j += print_le32_dechex("Stream ID",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x40 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x44 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x48 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x4C */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x50 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x54 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x58 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x5C */
			}
#endif
#if 1
			if(j < attr_value_offset) {
				const u32 print_end =
					sys_min(attr_value_offset,
					remaining_in_attribute);
				print_data_with_base(prefix, indent + 1, j,
					print_end, &attribute[j],
					print_end - j);
				j = print_end;
			}

			emit(prefix, indent + 1, "Value @ %" PRIuz " / "
				"0x%" PRIXz " (size: %" PRIuz " / "
				"0x%" PRIXz "):",
				PRAuz(j), PRAXz(j), PRAuz(attr_value_size),
				PRAXz(attr_value_size));

			if(remaining_in_attribute - j >= 4) {
				err = parse_attribute_named_stream_extent_value(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* refs_node_walk_visitor *visitor */
					visitor,
					/* const char *prefix */
					prefix,
					/* size_t indent */
					indent + 2,
					/* u64 stream_id */
					stream_id,
					/* const u8 *attribute */
					attribute,
					/* u16 value_size */
					sys_min(remaining_in_attribute - j,
					attr_value_size),
					/* u16 *jp */
					&j);
				if(err) {
					goto out;
				}
			}
#else
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x60 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x64 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x68 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x6C */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x70 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x74 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x78 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x7C */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_le32_dechex("Number of extents",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x80 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x84 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x88 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x8C */
			}
			if(remaining_in_attribute - j >= 8) {
				j += print_le64_dechex("Allocated size (1)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x90 */
			}
			if(remaining_in_attribute - j >= 8) {
				j += print_le64_dechex("Logical size (1)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0x98 */
			}
			if(remaining_in_attribute - j >= 8) {
				j += print_le64_dechex("Logical size (2)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0xA0 */
			}
			if(remaining_in_attribute - j >= 8) {
				j += print_le64_dechex("Allocated size (2)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0xA8 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xB0 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xB4 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xB8 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xBC */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xC0 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xC4 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xC8 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xCC */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xD0 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xD4 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xD8 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xDC */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xE0 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xE4 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xE8 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xEC */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xF0 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xF4 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0xF8 */
			}
			if(remaining_in_attribute - j >= 4) {
				num_extents = read_le32(&attribute[j]);
				j += print_le32_dechex("Number of extents (2)",
					prefix, indent + 1,
					attribute, &attribute[j]); /* 0xFC */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x100 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x104 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x108 */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x10C */
			}

			/* Iterate over extents in stream. */
			for(k = 0; k < num_extents &&
				(remaining_in_attribute - j) >= 24; ++k)
			{
				const u64 first_physical_block =
					logical_to_physical_block_number(
						/* refs_node_crawl_context
						 * *crawl_context */
						crawl_context,
						/* u64 logical_block_number */
						read_le64(&attribute[j]));
				/* TODO: Guessing that this is the number of
				 * clusters in the extent. Not sure about it. */
				const u32 cluster_count =
					read_le32(&attribute[j + 20]);

				emit(prefix, indent + 1, "Extent %" PRIu32 "/"
					"%" PRIu32 ":",
					PRAu32(k + 1), PRAu32(num_extents));

				j += print_le64_dechex("First block", prefix,
					indent + 2,
					attribute, &attribute[j]); /* 0x110 */
				emit(prefix, indent + 3,
					"-> Physical block: %" PRIu64 " / "
					"0x%" PRIX64 " (byte offset: "
					"%" PRIu64 ")",
					PRAu64(first_physical_block),
					PRAX64(first_physical_block),
					PRAu64(first_physical_block *
					block_index_unit));
				if(visitor && visitor->node_stream_extent) {
					err = visitor->node_stream_extent(
						/* void *context */
						visitor->context,
						/* u64 stream_id */
						stream_id,
						/* u64 first_block */
						first_physical_block,
						/* u32 block_index_unit */
						block_index_unit,
						/* u32 cluster_count */
						cluster_count);
					if(err) {
						goto out;
					}
				}

				j += print_unknown32(prefix, indent + 2,
					attribute, &attribute[j]); /* 0x118 */

				j += print_unknown32(prefix, indent + 2,
					attribute, &attribute[j]); /* 0x11C */

				j += print_unknown32(prefix, indent + 2,
					attribute, &attribute[j]); /* 0x120 */

				j += print_le32_dechex("Number of clusters in "
					"extent (?)", prefix, indent + 2,
					attribute, &attribute[j]); /* 0x124 */
			}
#endif
		}
		else if(attr_key_offset == 0x0010 && attribute_type == 0x00C0) {
			err = parse_reparse_point_attribute(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* size_t remaining_in_value */
				remaining_in_value,
				/* u16 remaining_in_attribute */
				remaining_in_attribute,
				/* const u8 *attribute */
				attribute,
				/* u16 attribute_size */
				attribute_size,
				/* u16 attribute_index */
				attribute_index,
				/* u16 *jp */
				&j);
			if(err) {
				goto out;
			}
		}
		else if(attr_key_offset == 0x10 && attr_key_size == 0x00) {
			/* This appears to contain an independently allocated
			 * (non-resident) attribute list. */
#if 0
			u64 logical_blocks[4] = { 0, 0, 0, 0 };
			u64 physical_blocks[4] = { 0, 0, 0, 0 };
#endif

			sys_log_debug("Parsing non-resident attribute list "
				"entry.");

			j += parse_level3_attribute_header(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* size_t remaining_in_value */
				remaining_in_value,
				/* const u8 *attribute */
				attribute,
				/* u16 attribute_size */
				attribute_size,
				/* u16 attribute_index */
				attribute_index);
#if 0
			if(remaining_in_attribute - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x08 */
			}
			if(remaining_in_attribute - j >= 2) {
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x0A */
			}
			if(remaining_in_attribute - j >= 4) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]); /* 0x0C */
			}
#endif

#if 1
			emit(prefix, indent + 1, "Value @ %" PRIuz " / "
				"0x%" PRIXz " (size: %" PRIuz " / "
				"0x%" PRIXz "):",
				PRAuz(j), PRAXz(j), PRAuz(attr_value_size),
				PRAXz(attr_value_size));

			if(remaining_in_attribute - j >= 4) {
				err = parse_non_resident_attribute_list_value(
					/* refs_node_crawl_context
					 * *crawl_context */
					crawl_context,
					/* refs_node_walk_visitor *visitor */
					visitor,
					/* const char *prefix */
					prefix,
					/* size_t indent */
					indent + 2,
					/* const u8 *data */
					attribute,
					/* u16 value_size */
					sys_min(remaining_in_attribute - j,
					attr_value_size),
					/* void *context */
					context,
					/* u16 *jp */
					&j);
				if(err) {
					goto out;
				}
			}
#else
			if(remaining_in_attribute - j >= 8) {
				logical_blocks[0] = read_le64(&attribute[j]);
				physical_blocks[0] =
					logical_to_physical_block_number(
						/* refs_node_crawl_context
						 * *crawl_context */
						crawl_context,
						/* u64 logical_block_number */
						logical_blocks[0]);

				j += print_le64_dechex("Block number 1", prefix,
					indent + 1,
					attribute, &attribute[j]); /* 0x10 */
				emit(prefix, indent + 2,
					"-> Physical block: %" PRIu64 " / "
					"0x%" PRIX64 " (byte offset: "
					"%" PRIu64 ")",
					PRAu64(physical_blocks[0]),
					PRAX64(physical_blocks[0]),
					PRAu64(physical_blocks[0] *
					block_index_unit));
			}
			if(remaining_in_attribute - j >= 8) {
				logical_blocks[1] = read_le64(&attribute[j]);
				physical_blocks[1] =
					logical_to_physical_block_number(
						/* refs_node_crawl_context
						 * *crawl_context */
						crawl_context,
						/* u64 logical_block_number */
						logical_blocks[1]);

				j += print_le64_dechex("Block number 2", prefix,
					indent + 1,
					attribute, &attribute[j]); /* 0x18 */
				emit(prefix, indent + 2,
					"-> Physical block: %" PRIu64 " / "
					"0x%" PRIX64 " (byte offset: "
					"%" PRIu64 ")",
					PRAu64(physical_blocks[1]),
					PRAX64(physical_blocks[1]),
					PRAu64(physical_blocks[1] *
					block_index_unit));
			}
			if(remaining_in_attribute - j >= 8) {
				logical_blocks[2] = read_le64(&attribute[j]);
				physical_blocks[2] =
					logical_to_physical_block_number(
						/* refs_node_crawl_context
						 * *crawl_context */
						crawl_context,
						/* u64 logical_block_number */
						logical_blocks[2]);

				j += print_le64_dechex("Block number 3", prefix,
					indent + 1,
					attribute, &attribute[j]); /* 0x20 */
				emit(prefix, indent + 2,
					"-> Physical block: %" PRIu64 " / "
					"0x%" PRIX64 " (byte offset: "
					"%" PRIu64 ")",
					PRAu64(physical_blocks[2]),
					PRAX64(physical_blocks[2]),
					PRAu64(physical_blocks[2] *
					block_index_unit));
			}
			if(remaining_in_attribute - j >= 8) {
				logical_blocks[3] = read_le64(&attribute[j]);
				physical_blocks[3] =
					logical_to_physical_block_number(
						/* refs_node_crawl_context
						 * *crawl_context */
						crawl_context,
						/* u64 logical_block_number */
						logical_blocks[3]);

				j += print_le64_dechex("Block number 4", prefix,
					indent + 1,
					attribute, &attribute[j]); /* 0x28 */
				emit(prefix, indent + 2,
					"-> Physical block: %" PRIu64 " / "
					"0x%" PRIX64 " (byte offset: "
					"%" PRIu64 ")",
					PRAu64(physical_blocks[3]),
					PRAX64(physical_blocks[3]),
					PRAu64(physical_blocks[3] *
					block_index_unit));
			}
			if(remaining_in_attribute - j >= 8) {
				j += print_le64_hex("Flags", prefix,
					indent + 1,
					attribute, &attribute[j]); /* 0x30 */
			}
			if(remaining_in_attribute - j >= 8) {
				j += print_le64_hex("Checksum", prefix,
					indent + 1,
					attribute, &attribute[j]); /* 0x38 */
			}

			if(!logical_blocks[0]) {
				sys_log_warning("Logical block 0 is invalid as "
					"a first block.");
			}
			else if(!physical_blocks[0]) {
				sys_log_warning("Unable to map logical block "
					"%" PRIu64 " / 0x%" PRIX64 " to "
					"physical block.",
					PRAu64(logical_blocks[0]),
					PRAX64(logical_blocks[0]));
			}
			else {
				const size_t bytes_per_read =
					sys_min(crawl_context->cluster_size,
					crawl_context->block_size);

				u8 *block = NULL;
				size_t bytes_read = 0;
				u8 k = 0;

				err = sys_malloc(crawl_context->block_size,
					&block);
				if(err) {
					sys_log_perror(err, "Error while "
						"allocating %" PRIu32 " byte "
						"block",
						PRAu32(crawl_context->
						block_size));
					goto out;
				}

				while(bytes_read < crawl_context->block_size) {
					sys_log_debug("Reading logical block "
						"%" PRIu64 " / physical block "
						"%" PRIu64 " into "
						"%" PRIuz "-byte buffer %p at "
						"buffer offset %" PRIuz,
						PRAu64(logical_blocks[k]),
						PRAu64(physical_blocks[k]),
						PRAuz(crawl_context->
						block_size),
						block,
						PRAuz(bytes_read));
					err = sys_device_pread(
						/* sys_device *dev */
						crawl_context->dev,
						/* u64 pos */
						physical_blocks[k] *
						block_index_unit,
						/* size_t count */
						bytes_per_read,
						/* void *b */
						&block[bytes_read]);
					if(err) {
						break;
					}

					bytes_read += bytes_per_read;
					++k;
				}
				if(err) {
					sys_log_pwarning(err, "Error while "
						"reading %" PRIuz " bytes from "
						"attribute block %" PRIu64 " "
						"(offset %" PRIu64 ")",
						PRAuz(crawl_context->
						block_size),
						PRAu64(physical_blocks[k]),
						PRAu64(physical_blocks[k] *
						block_index_unit));
					sys_free(&block);
					continue;
				}

				err = parse_generic_block(
					/* refs_node_crawl_context
					 *     *crawl_context */
					crawl_context,
					/* refs_node_walk_visitor *visitor */
					visitor,
					/* size_t indent */
					indent + 2,
					/* u64 cluster_number */
					physical_blocks[0],
					/* u64 block_number */
					logical_blocks[0],
					/* u64 block_queue_index */
					0 /* Different block queue... */,
					/* u8 level */
					4,
					/* const u8 *block */
					block,
					/* u32 block_size */
					crawl_context->block_size,
					/* block_queue *block_queue */
					NULL,
					/* sys_bool
					 *     add_subnodes_in_offsets_order */
					SYS_TRUE,
					/* void *context */
					context,
					/* int (*parse_key)(
					 *      refs_node_crawl_context
					 *          *crawl_context,
					 *      refs_node_walk_visitor *visitor,
					 *      const char *prefix,
					 *      size_t indent,
					 *      u64 object_id,
					 *      sys_bool is_index,
					 *      sys_bool is_v3,
					 *      const u8 *key,
					 *      u16 key_offset,
					 *      u16 key_size,
					 *      u32 entry_size,
					 *      void *context) */
					parse_attribute_key,
					/* int (*parse_leaf_value)(
					 *      refs_node_crawl_context
					 *          *crawl_context,
					 *      refs_node_walk_visitor *visitor,
					 *      const char *prefix,
					 *      size_t indent,
					 *      u64 object_id,
					 *      const u8 *key,
					 *      u16 key_size,
					 *      const u8 *value,
					 *      u16 value_offset,
					 *      u16 value_size,
					 *      u16 entry_offset,
					 *      u32 entry_size,
					 *      void *context) */
					parse_attribute_leaf_value,
					/* int (*leaf_entry_handler)(
					 *      void *context,
					 *      const u8 *data,
					 *      u32 data_size,
					 *      u32 node_type) */
					NULL);
				sys_free(&block);
				if(err) {
					sys_log_pwarning(err, "Error while "
						"parsing non-resident "
						"attribute list");
					continue;
				}
			}
#endif
		}

		if(j < remaining_in_attribute) {
			print_data_with_base(prefix, indent + 1, j,
				remaining_in_attribute, &attribute[j],
				remaining_in_attribute - j);
			j = remaining_in_attribute;
		}

		i += remaining_in_attribute;

		if(cstr) {
			sys_free(&cstr);
		}
	}

	offsets_start = value_size - number_of_attributes * 4;
	if(i < offsets_start) {
		print_data_with_base(prefix, indent, i, value_size, &value[i],
			offsets_start - i);
		i = offsets_start;
	}

	for(j = 0; j < number_of_attributes; ++j) {
		emit(prefix, indent, "Index of attribute %" PRIu16 " @ "
			"%" PRIuz " / 0x%" PRIXz ": %" PRIu16 " (absolute: "
			"%" PRIu32 ", flags: 0x%" PRIX16 ")",
			PRAu16(j + 2), PRAuz(i), PRAXz(i),
			PRAu16(read_le16(&value[i])),
			PRAu32(attributes_offset + read_le16(&value[i])),
			PRAX16(read_le16(&value[i + 2])));
		i += 4;
	}
out:
	if(cstr) {
		sys_free(&cstr);
	}

	return err;
}

/**
 * Parse a short level 3 tree entry value.
 *
 * Short values (type 2) are usually directories, but occasionally we have found
 * files that are represented by short values. Whether or not it's a file
 * depends on the value of the file flags bit 0x10000000. If it's set then it's
 * a directory. If it's not set it's a file and the allocated size/file size
 * fields describe its allocation state.
 */
int parse_level3_short_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 parent_node_object_id,
		const u16 entry_offset,
		const u8 *const key,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		void *const context)
{
	const sys_bool is_v3 =
		(crawl_context->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	const u64 object_id =
		(value_size < (is_v3 ? 8 : 0) + 8) ? 0 :
		read_le64(&value[is_v3 ? 8 : 0]);
	const u64 hard_link_id =
		(!is_v3 || value_size < 0 + 8) ? 0 : read_le64(&value[0]);
	const u64 creation_time =
		(value_size < 16 + 8) ? 0 : read_le64(&value[16]);
	const u64 last_data_modification_time =
		(value_size < 24 + 8) ? 0 : read_le64(&value[24]);
	const u64 last_mft_modification_time =
		(value_size < 32 + 8) ? 0 : read_le64(&value[32]);
	const u64 last_access_time =
		(value_size < 40 + 8) ? 0 : read_le64(&value[40]);
	const u64 allocated_size =
		(value_size < 48 + 8) ? 0 : read_le64(&value[48]);
	const u64 file_size =
		(value_size < 56 + 8) ? 0 : read_le64(&value[56]);
	const u32 file_flags =
		(value_size < 64 + 4) ? 0 : read_le32(&value[64]);

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;

	(void) crawl_context;
	(void) context;

	if(visitor && visitor->node_short_entry) {
		err = visitor->node_short_entry(
			/* void *context */
			visitor->context,
			/* const refschar *file_name */
			(const refschar*) &key[4],
			/* u16 file_name_length */
			(key_size - 4) / sizeof(refschar),
			/* u16 child_entry_offset */
			entry_offset,
			/* u32 file_flags */
			file_flags,
			/* u64 parent_node_object_id */
			parent_node_object_id,
			/* u64 object_id */
			object_id,
			/* u64 hard_link_id */
			hard_link_id,
			/* u64 create_time */
			creation_time,
			/* u64 last_access_time */
			last_access_time,
			/* u64 last_write_time */
			last_data_modification_time,
			/* u64 last_mft_change_time */
			last_mft_modification_time,
			/* u64 file_size */
			file_size,
			/* u64 allocated_size */
			allocated_size,
			/* const u8 *key */
			key,
			/* size_t key_size */
			key_size,
			/* const u8 *record */
			value,
			/* size_t record_size */
			value_size);
		if(err) {
			goto out;
		}
	}

	emit(prefix, indent - 1, "Value (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		entry_type_to_string(0x2), PRAu16(value_offset),
		PRAX16(value_offset));

	/* Note: The object ID of a directory is verified to partially match the
	 * output of fsutil file queryFileID in the high 64 bits of the 128 bit
	 * hex string.
	 * For example, an Object ID of 0xAF8 was printed by fsutil as:
	 *   0x0000000000000af80000000000000000
	 *
	 * I'm unsure what if anything maps to the low 64 bits displayed by
	 * fsutil.
	 */
	if(is_v3) {
		/* Technically only from version 3.5 onwards. */
		print_le64_dechex("Hard link ID", prefix, indent, value,
			&value[0]);
	}

	emit(prefix, indent, "Object ID: %" PRIu64 " / 0x%" PRIX64,
		PRAu64(object_id), PRAX64(object_id));

	if(!is_v3) {
		print_unknown64(prefix, indent, value, &value[8]);
	}
	print_filetime(prefix, indent, "Creation time",
		creation_time);
	print_filetime(prefix, indent, "Last data modification time",
		last_data_modification_time);
	print_filetime(prefix, indent, "Last MFT entry change time",
		last_mft_modification_time);
	print_filetime(prefix, indent, "Last access time",
		last_access_time);
	print_le64_dechex("Allocated size", prefix, indent, value, &value[48]);
	print_le64_dechex("File size", prefix, indent, value, &value[56]);
	print_file_flags(visitor, prefix, indent, value, &value[64]);
	print_unknown32(prefix, indent, value, &value[68]);
	if(value_size > 72) {
		emit(prefix, indent, "Unknown @ 72:");
		print_data_with_base(prefix, indent + 1, 72, value_size,
			&value[72], value_size - 72);
	}
out:
	return err;
}

static int parse_level3_volume_label_value(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		void *const context)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	char *cname = NULL;
	size_t cname_length = 0;
	size_t i = 0;

	(void) context;

	sys_log_debug("Volume label value! visitor=%p "
		"visitor->volume_label_entry=%p visitor->context=%p",
		visitor,
		visitor ? visitor->node_volume_label_entry : NULL,
		visitor ? visitor->context : NULL);

	if(visitor && visitor->node_volume_label_entry) {
		err = visitor->node_volume_label_entry(
			/* void *context */
			visitor->context,
			/* refschar *volume_label */
			(const refschar*) value,
			/* u16 volume_label_length */
			value_size / 2);
		if(err) {
			goto out;
		}
	}

	emit(prefix, indent - 1, "Value (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"volume label", PRAu16(value_offset),
		PRAX16(value_offset));

	err = sys_unistr_decode(
		(const refschar*) value,
		value_size / 2,
		&cname,
		&cname_length);
	if(err) {
		sys_log_perror(err, "Error while decoding volume label");
		goto out;
	}

	emit(prefix, indent, "Volume label (length: %" PRIu16 "): %" PRIbs,
		PRAu16(value_size / 2),
		PRAbs(cname_length, cname));

	i += (value_size / 2) * 2;
	if(i < value_size) {
		print_data_with_base(prefix, indent, i, value_size, &value[i],
			value_size - i);
	}
out:
	if(cname) {
		sys_free(&cname);
	}

	return err;
}

static int parse_level3_leaf_value(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u8 *const key,
		const u16 key_offset,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u16 entry_offset,
		const u32 entry_size,
		void *const context)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 key_type = (key_size >= 2) ? read_le16(&key[0]) : 0;
	const u16 dirent_type = (key_size >= 4) ? read_le16(&key[2]) : 0;

	int err = 0;

	(void) key_offset;
	(void) entry_size;
	(void) context;

	if((key_type == 0x0030 && dirent_type == 0x0001) || /* Regular file. */
		key_type == 0x0040 || /* Hardlinked file. */
		(key_type == 0x0010U && dirent_type == 0x0000U)) /* Reparse. */
	{
		err = parse_level3_long_value(
			/* refs_node_crawl_context *context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 parent_node_object_id */
			object_id,
			/* u16 entry_offset */
			entry_offset,
			/* const u8 *key */
			key,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* void *context */
			NULL);
		if(err) {
			goto out;
		}
	}
	else if(key_type == 0x30 && dirent_type == 0x2) {
		/* Directory. */
		err = parse_level3_short_value(
			/* refs_node_crawl_context *context */
			crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* u64 parent_node_object_id */
			object_id,
			/* u16 entry_offset */
			entry_offset,
			/* const u8 *key */
			key,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* void *context */
			NULL);
		if(err) {
			goto out;
		}
	}
	else if(key_type == 0x510) {
		/* Volume label */
		err = parse_level3_volume_label_value(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *value */
			value,
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* void *context */
			NULL);
		if(err) {
			goto out;
		}
	}
	else {
		emit(prefix, indent - 1, "Value (unknown type):");
		print_data_with_base(prefix, indent, 0, 0, value, value_size);
	}
out:
	return err;
}

static int parse_level3_block(
		refs_node_crawl_context *const crawl_context,
		refs_node_walk_visitor *const visitor,
		const u64 cluster_number,
		const u64 block_number,
		const u64 block_queue_index,
		const u8 *const block,
		const u32 block_size,
		u64 **const level3_queue,
		size_t *const level3_queue_length)
{
	int err = 0;
	block_queue block_queue;

	memset(&block_queue, 0, sizeof(block_queue));
	block_queue.block_numbers = *level3_queue;
	block_queue.block_queue_length = *level3_queue_length;
	block_queue.elements_per_entry = 1;

	err = parse_generic_block(
		/* refs_node_crawl_context *crawl_context */
		crawl_context,
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* size_t indent */
		0,
		/* u64 cluster_number */
		cluster_number,
		/* u64 block_number */
		block_number,
		/* u64 block_queue_index */
		block_queue_index,
		/* u8 level */
		3,
		/* const u8 *block */
		block,
		/* u32 block_size */
		block_size,
		/* block_queue *block_queue */
		&block_queue,
		/* sys_bool add_subnodes_in_offsets_order */
		SYS_TRUE,
		/* void *context */
		&block_queue,
		/* int (*parse_key)(
		 *      refs_node_crawl_context *crawl_context,
		 *      refs_node_walk_visitor *visitor,
		 *      const char *prefix,
		 *      size_t indent,
		 *      u64 object_id,
		 *      sys_bool is_v3,
		 *      sys_bool is_index,
		 *      const u8 *key,
		 *      u16 key_offset,
		 *      u16 key_size,
		 *      u32 entry_size,
		 *      void *context) */
		parse_level3_key,
		/* int (*parse_leaf_value)(
		 *      refs_node_crawl_context *crawl_context,
		 *      refs_node_walk_visitor *visitor,
		 *      const char *prefix,
		 *      size_t indent,
		 *      u64 object_id,
		 *      const u8 *key,
		 *      u16 key_size,
		 *      const u8 *value,
		 *      u16 value_offset,
		 *      u16 value_size,
		 *      u16 entry_offset,
		 *      u32 entry_size,
		 *      void *context) */
		parse_level3_leaf_value,
		/* int (*leaf_entry_handler)(
		 *      void *context,
		 *      const u8 *data,
		 *      u32 data_size,
		 *      u32 node_type) */
		NULL);
	if(err) {
		goto out;
	}

	*level3_queue = block_queue.block_numbers;
	*level3_queue_length =
		block_queue.block_queue_length;
out:
	return err;
}

void refs_block_map_destroy(
		refs_block_map **const block_map)
{
	if((*block_map)->entries) {
		sys_free(&(*block_map)->entries);
	}

	sys_free(block_map);
}

static int crawl_volume_metadata(
		refs_node_walk_visitor *const visitor,
		sys_device *const dev,
		REFS_BOOT_SECTOR *const bs,
		REFS_SUPERBLOCK_HEADER **const sb,
		REFS_LEVEL1_NODE **const primary_level1_node,
		REFS_LEVEL1_NODE **const secondary_level1_node,
		refs_block_map **const block_map,
		const u64 *const start_node,
		const u64 *const object_id)
{
	const sys_bool is_v3 = (bs->version_major >= 3) ? SYS_TRUE : SYS_FALSE;

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u64 cluster_size_64 = 0;
	u32 cluster_size = 0;
	u32 block_size = 0;
	u32 block_index_unit = 0;
	u8 *padding = NULL;
	u8 *block = NULL;
	refs_block_map *mappings = NULL;
	u64 primary_level1_block = 0;
	u64 secondary_level1_block = 0;
	u64 *primary_level2_blocks = NULL;
	size_t primary_level2_blocks_count = 0;
	u64 *secondary_level2_blocks = NULL;
	size_t secondary_level2_blocks_count = 0;
	block_queue level2_queue;
	block_queue level3_queue;
	refs_node_crawl_context crawl_context;
	size_t i = 0;

	memset(&level2_queue, 0, sizeof(level2_queue));
	memset(&level3_queue, 0, sizeof(level3_queue));
	memset(&crawl_context, 0, sizeof(crawl_context));

	/* Superblock seems to be at cluster 30. Block is metadata-block
	 * sized. */
	cluster_size_64 =
		((u64) le32_to_cpu(bs->bytes_per_sector)) *
		le32_to_cpu(bs->sectors_per_cluster);
	if(cluster_size_64 > UINT32_MAX) {
		sys_log_error("Unreasonably large cluster size: %" PRIu64,
			PRAu64(cluster_size_64));
		err = EINVAL;
		goto out;
	}

	cluster_size = (u32) cluster_size_64;
	block_size =
		is_v3 ? sys_max(16U * 1024U, cluster_size) :
		((cluster_size == 4096) ? 12U * 1024U : 16U * 1024U);

	block_index_unit = is_v3 ? cluster_size : 16384;

	crawl_context = refs_node_crawl_context_init(
		/* sys_device *dev */
		dev,
		/* REFS_BOOT_SECTOR *bs */
		bs,
		/* refs_block_map *block_map */
		NULL,
		/* u32 cluster_size */
		cluster_size,
		/* u32 block_size */
		block_size,
		/* u32 block_index_unit */
		block_index_unit,
		/* u8 version_major */
		bs->version_major,
		/* u8 version_minor */
		bs->version_minor);

	if(visitor && visitor->print_visitor.print_message) {
		/* Print the data between the boot sector and the superblock. */
		err = sys_malloc(30 * block_index_unit - sizeof(bs),
			&padding);
		if(err) {
			sys_log_perror(err, "Error while allocating %" PRIuz " "
				"bytes for padding",
				PRAuz(30 * block_index_unit - sizeof(bs)));
			goto out;
		}

		err = sys_device_pread(
			/* sys_device *dev */
			dev,
			/* u64 pos */
			sizeof(*bs),
			/* size_t count */
			30 * block_index_unit - sizeof(*bs),
			/* void *b */
			padding);
		if(err) {
			sys_log_perror(err, "Error while reading %" PRIuz " "
				"bytes from sector 1 (offset %" PRIu64 ")",
				PRAuz(30 * block_index_unit - sizeof(*bs)),
				PRAu64(sizeof(*bs)));
			goto out;
		}

		print_data_with_base("", 0, sizeof(*bs),
			30 * block_index_unit, padding,
			30 * block_index_unit - sizeof(*bs));

		sys_free(&padding);
	}

	err = sys_malloc(block_size, &block);
	if(err) {
		sys_log_perror(err, "Error while allocating %" PRIuz " bytes "
			"for metadata block",
			PRAuz(block_size));
		goto out;
	}

	if(!(sb && *sb)) {
		err = sys_device_pread(
			/* sys_device *dev */
			dev,
			/* u64 pos */
			30 * block_index_unit,
			/* size_t count */
			block_size,
			/* void *b */
			block);
		if(err) {
			sys_log_perror(err, "Error while reading %" PRIuz " "
				"bytes from cluster 30 (offset %" PRIu64 ")",
				PRAuz(block_size),
				PRAu64(30 * block_index_unit));
			goto out;
		}
	}

	emit("", 0, "Superblock:");

	if(!is_v3) {
		parse_superblock_v1(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const u8 *block */
			(sb && *sb) ? (const u8*) *sb : block,
			/* size_t block_size */
			block_index_unit,
			/* u64 *out_primary_level1_block */
			&primary_level1_block,
			/* u64 *out_secondary_level1_block */
			&secondary_level1_block);
	}
	else {
		parse_superblock_v3(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const u8 *block */
			(sb && *sb) ? (const u8*) *sb : block,
			/* size_t block_size */
			block_index_unit,
			/* u64 *out_primary_level1_block */
			&primary_level1_block,
			/* u64 *out_secondary_level1_block */
			&secondary_level1_block);
	}

	if(!primary_level1_block || !secondary_level1_block) {
		sys_log_error("Level 1 block references are invalid.");
		err = EIO;
		goto out;
	}

	if(primary_level1_block) {
		if(!(primary_level1_node && *primary_level1_node)) {
			err = sys_device_pread(
				/* sys_device *dev */
				dev,
				/* u64 pos */
				primary_level1_block * block_index_unit,
				/* size_t count */
				block_size,
				/* void *b */
				block);
			if(err) {
				sys_log_perror(err, "Error while reading "
					"%" PRIuz " bytes from metadata block "
					"%" PRIu64 " (offset %" PRIu64 ")",
					PRAuz(block_size),
					PRAu64(primary_level1_block),
					PRAu64(primary_level1_block *
					block_index_unit));
				goto out;
			}
		}

		err = parse_level1_block(
			/* refs_node_crawl_context *context */
			&crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* u64 block_number */
			primary_level1_block,
			/* u64 cluster_number */
			primary_level1_block,
			/* u64 block_queue_index */
			0,
			/* const u8 *block */
			(primary_level1_node && *primary_level1_node) ?
			(const u8*) *primary_level1_node : block,
			/* size_t block_size */
			block_size,
			/* u64 **out_level2_extents */
			&primary_level2_blocks,
			/* size_t *out_level2_extents_count */
			&primary_level2_blocks_count);
		if(err) {
			goto out;
		}
	}

	if(secondary_level1_block) {
		if(!(secondary_level1_node && *secondary_level1_node)) {
			err = sys_device_pread(
				/* sys_device *dev */
				dev,
				/* u64 pos */
				secondary_level1_block * block_index_unit,
				/* size_t count */
				block_size,
				/* void *b */
				block);
			if(err) {
				sys_log_perror(err, "Error while reading "
					"%" PRIuz " bytes from metadata block "
					"%" PRIu64 " "
					"(offset %" PRIu64 ")",
					PRAuz(block_size),
					PRAu64(secondary_level1_block),
					PRAu64(secondary_level1_block *
					block_index_unit));
				goto out;
			}
		}

		err = parse_level1_block(
			/* refs_node_crawl_context *context */
			&crawl_context,
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* u64 cluster_number */
			primary_level1_block,
			/* u64 block_number */
			secondary_level1_block,
			/* u64 block_queue_index */
			1,
			/* const u8 *block */
			(secondary_level1_node && *secondary_level1_node) ?
			(const u8*) *secondary_level1_node : block,
			/* size_t block_size */
			block_size,
			/* u64 **out_level2_extents */
			&secondary_level2_blocks,
			/* size_t *out_level2_extents_count */
			&secondary_level2_blocks_count);
		if(err) {
			goto out;
		}
	}

	if(!primary_level2_blocks || !secondary_level2_blocks) {
		sys_log_critical("No %s%s%s level 2 blocks parsed!",
			!primary_level2_blocks ? "primary" : "",
			(!primary_level2_blocks && !secondary_level2_blocks) ?
				"/" : "",
			!secondary_level2_blocks ? "secondary" : "");
		err = EINVAL;
		goto out;
	}

	if(primary_level2_blocks_count != secondary_level2_blocks_count)
	{
		sys_log_warning("Mismatching level 2 block count in "
			"level 1 blocks: %" PRIu32 " != %" PRIu32 " "
			"Proceeding with primary...",
			PRAu32(primary_level2_blocks_count),
			PRAu32(secondary_level2_blocks_count));
	}
	else if(memcmp(primary_level2_blocks, secondary_level2_blocks,
		primary_level2_blocks_count * 24))
	{
		if(block_map && *block_map) {
			sys_log_debug("Mismatching level 2 block data in "
				"level 1 blocks. Proceeding with primary...");
		}
		else {
			sys_log_warning("Mismatching level 2 block data in "
				"level 1 blocks. Proceeding with primary...");
		}
	}

	level2_queue.block_numbers = primary_level2_blocks;
	level2_queue.block_queue_length = primary_level2_blocks_count;
	level2_queue.elements_per_entry = is_v3 ? 6 : 3;

	level3_queue.elements_per_entry = 1;

	primary_level2_blocks = NULL;
	primary_level2_blocks_count = 0;

	if(block_map && *block_map) {
		mappings = *block_map;
	}
	else {
		err = sys_calloc(sizeof(*mappings), &mappings);
		if(err) {
			sys_log_perror(err, "Error while allocating mappings "
				"base struct");
			goto out;
		}

		/* For v3 volumes we first iterate over the Level 2 blocks to
		 * find the block region mappings, located in the tree with
		 * object ID 0xB. */
		for(i = 0; is_v3 && i < level2_queue.block_queue_length; ++i) {
			const u64 logical_block_number =
				level2_queue.block_numbers[i * (is_v3 ? 6 : 3)];

			u64 physical_block_number;
			const REFS_V3_BLOCK_HEADER *header = NULL;
			size_t j = 0;
			u64 tree_object_id = 0;

			physical_block_number =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					&crawl_context,
					/* u64 logical_block_number */
					logical_block_number);
			if(!physical_block_number) {
				continue;
			}

			sys_log_debug("Reading block %" PRIuz " / %" PRIuz ": "
				"%" PRIu64 " -> %" PRIu64,
				PRAuz(i),
				PRAuz(level2_queue.block_queue_length),
				PRAu64(logical_block_number),
				PRAu64(physical_block_number));

			err = sys_device_pread(
				/* sys_device *dev */
				dev,
				/* u64 pos */
				physical_block_number * block_index_unit,
				/* size_t count */
				block_size,
				/* void *b */
				block);
			if(err) {
				sys_log_pwarning(err, "Error while reading "
					"%" PRIuz " bytes from metadata block "
					"%" PRIu64 " (offset %" PRIu64 ")",
					PRAuz(block_size),
					PRAu64(physical_block_number),
					PRAu64(physical_block_number *
					block_index_unit));
				continue;
			}

			header = (const REFS_V3_BLOCK_HEADER*) block;

			if(memcmp(header->signature, "MSB+", 4) ||
				le64_to_cpu(header->block_number) !=
				logical_block_number)
			{
				sys_log_warning("Invalid data while reading "
					"block with identity mapping: %" PRIu64,
					PRAu64(logical_block_number));
				continue;
			}

			tree_object_id = le64_to_cpu(header->object_id);
			if(tree_object_id != 0xB && tree_object_id != 0xC) {
				/* Not the tree that we are looking for... */
				continue;
			}

			/* We are now sure that this is the 0xB tree, which
			 * describes logical->physical block mappings. If this
			 * is an index node we iterate over the indices in the
			 * order described by the attribute list. */

			err = parse_generic_block(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* refs_node_walk_visitor *visitor */
				NULL,
				/* size_t indent */
				0,
				/* u64 cluster_number */
				physical_block_number,
				/* u64 block_number */
				logical_block_number,
				/* u64 block_queue_index */
				i,
				/* u8 level */
				2,
				/* const u8 *block */
				block,
				/* u32 block_size */
				block_size,
				/* block_queue *block_queue */
				&level2_queue,
				/* sys_bool add_subnodes_in_offsets_order */
				SYS_TRUE,
				/* void *context */
				(tree_object_id == 0xB) ? mappings : NULL,
				/* int (*parse_key)(
				 *      refs_node_crawl_context *crawl_context,
				 *      refs_node_walk_visitor *visitor,
				 *      const char *prefix,
				 *      size_t indent,
				 *      u64 object_id,
				 *      sys_bool is_v3,
				 *      sys_bool is_index,
				 *      const u8 *key,
				 *      u16 key_offset,
				 *      u16 key_size,
				 *      void *context) */
				NULL,
				/* int (*parse_leaf_value)(
				 *      refs_node_crawl_context *crawl_context,
				 *      refs_node_walk_visitor *visitor,
				 *      const char *prefix,
				 *      size_t indent,
				 *      u64 object_id,
				 *      const u8 *key,
				 *      u16 key_size,
				 *      const u8 *value,
				 *      u16 value_offset,
				 *      u16 value_size,
				 *      u16 entry_offset,
				 *      u32 entry_size,
				 *      void *context) */
				(tree_object_id == 0xB) ?
				parse_level2_0xB_leaf_value_add_mapping :
				parse_level2_block_0xB_0xC_leaf_value,
				/* int (*leaf_entry_handler)(
				 *      void *context,
				 *      const u8 *data,
				 *      u32 data_size,
				 *      u32 node_type) */
				NULL);
			if(err) {
				goto out;
			}

			sys_log_debug("Mapping table after processing 0xB "
				"block (%" PRIuz " entries):",
				PRAuz(mappings->length));
			for(j = 0; j < mappings->length; ++j) {
				sys_log_debug("\t[%" PRIuz "]:",
					PRAuz(j));
				sys_log_debug("\t\tStart: %" PRIu64,
					PRAu64(mappings->entries[j].
					start));
				sys_log_debug("\t\tLength: %" PRIu64,
					PRAu64(mappings->entries[j].
					length));
			}
		}

		if(block_map) {
			*block_map = mappings;
		}
	}

	crawl_context.block_map = mappings;

	/* At this point the mappings are set up and we can look up a node by
	 * node number. */
	if(start_node) {
		const u64 logical_block_number = *start_node;
		u64 physical_block_number;
		u64 start_object_id = 0;
		sys_bool is_valid = SYS_FALSE;

		/* Discard primary level 2 blocks as we want a crawl targeted at
		 * the requested node number. The crawl may still add level 2
		 * blocks to the queue if we encounter a level 2 index node. */
		sys_free(&level2_queue.block_numbers);
		level2_queue.block_queue_length = 0;

		physical_block_number =
			logical_to_physical_block_number(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* u64 logical_block_number */
				*start_node);

		sys_log_debug("Reading block %" PRIuz " / %" PRIuz ": "
			"%" PRIu64 " -> %" PRIu64,
			PRAuz(i),
			PRAuz(level2_queue.block_queue_length),
			PRAu64(logical_block_number),
			PRAu64(physical_block_number));

		err = sys_device_pread(
			/* sys_device *dev */
			dev,
			/* u64 pos */
			physical_block_number * block_index_unit,
			/* size_t count */
			block_size,
			/* void *b */
			block);
		if(err) {
			sys_log_perror(err, "Error while reading "
				"%" PRIuz " bytes from metadata block "
				"%" PRIu64 " (offset %" PRIu64 ")",
				PRAuz(block_size),
				PRAu64(physical_block_number),
				PRAu64(physical_block_number *
				block_index_unit));
			goto out;
		}

		err = parse_block_header(
			/* refs_node_walk_visitor *visitor */
			NULL,
			/* const char *prefix */
			"",
			/* size_t indent */
			0,
			/* u8 level */
			2 /* Levels 2 and 3 share the same signature, MSB+. */,
			/* const u8 *block */
			block,
			/* u32 block_size */
			block_size,
			/* u64 cluster_number */
			physical_block_number,
			/* u64 block_number */
			logical_block_number,
			/* u64 block_queue_index */
			0,
			/* sys_bool *out_is_valid */
			&is_valid,
			/* sys_bool *out_is_v3 */
			NULL,
			/* u32 *out_header_size */
			NULL,
			/* u64 *out_object_id */
			&start_object_id);
		if(err) {
			goto out;
		}

		if(start_object_id < 0x500) {
			err = block_queue_add(
				/* block_queue *block_queue */
				&level2_queue,
				/* u64 block_number */
				logical_block_number);
			if(err) {
				goto out;
			}
		}
		else {
			err = block_queue_add(
				/* block_queue *block_queue */
				&level3_queue,
				/* u64 block_number */
				logical_block_number);
			if(err) {
				goto out;
			}
		}
	}

	if(level2_queue.block_queue_length) {
		for(i = 0; i < level2_queue.block_queue_length; ++i) {
			const u64 logical_block_number =
				level2_queue.block_numbers[i * (is_v3 ? 6 : 3)];
			u64 physical_block_number;
			u64 object_id_mapping = 0;
			sys_bool object_id_mapping_found = SYS_FALSE;

			physical_block_number =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					&crawl_context,
					/* u64 logical_block_number */
					logical_block_number);

			sys_log_debug("Reading block %" PRIuz " / %" PRIuz ": "
				"%" PRIu64 " -> %" PRIu64,
				PRAuz(i),
				PRAuz(level2_queue.block_queue_length),
				PRAu64(logical_block_number),
				PRAu64(physical_block_number));

			err = sys_device_pread(
				/* sys_device *dev */
				dev,
				/* u64 pos */
				physical_block_number * block_index_unit,
				/* size_t count */
				block_size,
				/* void *b */
				block);
			if(err) {
				sys_log_pwarning(err, "Error while reading "
					"%" PRIuz " bytes from metadata block "
					"%" PRIu64 " (offset %" PRIu64 ")",
					PRAuz(block_size),
					PRAu64(physical_block_number),
					PRAu64(physical_block_number *
					block_index_unit));
				continue;
			}

			if(object_id) {
				object_id_mapping = *object_id;
			}

			err = parse_level2_block(
				/* refs_node_crawl_context *context */
				&crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* u64 cluster_number */
				physical_block_number,
				/* u64 block_number */
				logical_block_number,
				/* u64 block_queue_index */
				i,
				/* const u8 *block */
				block,
				/* u32 block_size */
				block_size,
				/* u64 *object_id_mapping */
				object_id ? &object_id_mapping : NULL,
				/* sys_bool *object_id_mapping_found */
				object_id ? &object_id_mapping_found : NULL,
				/* u64 **level2_queue */
				&level2_queue.block_numbers,
				/* size_t *level2_queue_length */
				&level2_queue.block_queue_length,
				/* u64 **level3_queue */
				object_id ? NULL : &level3_queue.block_numbers,
				/* size_t *level3_queue_length */
				object_id ? NULL :
				&level3_queue.block_queue_length);
			if(err) {
				goto out;
			}

			if(object_id && object_id_mapping_found) {
				err = block_queue_add(
					/* block_queue *block_queue */
					&level3_queue,
					/* u64 block_number */
					object_id_mapping);
				if(err) {
					sys_log_perror(err, "Error while "
						"adding mapped block to queue");
					goto out;
				}

				/* We have found what we are looking for, so
				 * ignore the rest of the level 2 queue and
				 * proceed to the requested level 3 block. */
				break;
			}
		}
	}
	if(level3_queue.block_queue_length) {
		for(i = 0; i < level3_queue.block_queue_length; ++i) {
			const u64 logical_block_number =
				level3_queue.block_numbers[i];
			u64 physical_block_number;

			physical_block_number =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					&crawl_context,
					/* u64 logical_block_number */
					logical_block_number);

			err = sys_device_pread(
				/* sys_device *dev */
				dev,
				/* u64 pos */
				physical_block_number * block_index_unit,
				/* size_t count */
				block_size,
				/* void *b */
				block);
			if(err) {
				sys_log_perror(err, "Error while reading "
					"%" PRIuz " bytes from metadata block "
					"%" PRIu64 " (offset %" PRIu64 ")",
					PRAuz(block_size),
					PRAu64(logical_block_number),
					PRAu64(physical_block_number *
					block_index_unit));
				goto out;
			}

			err = parse_level3_block(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* u64 cluster_number */
				physical_block_number,
				/* u64 block_number */
				logical_block_number,
				/* u64 block_queue_index */
				i,
				/* const u8 *block */
				block,
				/* u32 block_size */
				block_size,
				/* u64 **level3_queue */
				&level3_queue.block_numbers,
				/* size_t *level3_queue_length */
				&level3_queue.block_queue_length);
			if(err) {
				goto out;
			}
		}
	}
out:
	if(level3_queue.block_numbers) {
		sys_free(&level3_queue.block_numbers);
	}

	if(level2_queue.block_numbers) {
		sys_free(&level2_queue.block_numbers);
	}

	if(secondary_level2_blocks) {
		sys_free(&secondary_level2_blocks);
	}

	if(primary_level2_blocks) {
		sys_free(&primary_level2_blocks);
	}

	if(block) {
		sys_free(&block);
	}

	if(mappings && !(block_map && *block_map == mappings)) {
		refs_block_map_destroy(
			/* refs_block_map **block_map */
			&mappings);
	}

	if(padding) {
		sys_free(&padding);
	}

	return err;
}

int refs_node_walk(
		sys_device *const dev,
		REFS_BOOT_SECTOR *const bs,
		REFS_SUPERBLOCK_HEADER **const sb,
		REFS_LEVEL1_NODE **const primary_level1_node,
		REFS_LEVEL1_NODE **const secondary_level1_node,
		refs_block_map **const block_map,
		const u64 *const start_node,
		const u64 *const object_id,
		refs_node_walk_visitor *const visitor)
{
	/* Iterate over a node based on its node data. */
	return crawl_volume_metadata(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* sys_device *dev */
		dev,
		/* REFS_BOOT_SECTOR *bs */
		bs,
		/* REFS_SUPERBLOCK_HEADER **sb */
		sb,
		/* REFS_LEVEL1_NODE **primary_level1_node */
		primary_level1_node,
		/* REFS_LEVEL1_NODE **secondary_level1_node */
		secondary_level1_node,
		/* refs_block_map **block_map */
		block_map,
		/* const u64 *start_node */
		start_node,
		/* const u64 *object_id */
		object_id);
}

int refs_node_scan(
		sys_device *const dev,
		REFS_BOOT_SECTOR *const bs,
		refs_node_scan_visitor *const visitor)
{
	/* Scan the whole volume length for metadata nodes. Until our tree
	 * traversal code is complete we do it the brute-force way. */

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 sector_size = 0;
	u64 cluster_size = 0;
	u32 block_size = 0;
	u32 clusters_per_block = 0;
	u64 device_size = 0;
	u32 block_index_unit = 0;
	u8 *padding = NULL;
	u32 buffer_size = 0;
	ssize_t buffer_valid_size = 0;
	u64 buffer_valid_end = 0;
	u8 *buffer = NULL;
	u8 *block = NULL;
	u64 i = 0;

	/* Superblock seems to be at cluster 30. Block is metadata-block
	 * sized. */
	sector_size = le32_to_cpu(bs->bytes_per_sector);
	cluster_size =
		((u64) sector_size) * le32_to_cpu(bs->sectors_per_cluster);
	block_size =
		(bs->version_major == 1) ?
		((cluster_size == 4096) ? 12U * 1024U : 16U * 1024U) :
		sys_max(16U * 1024U, cluster_size);
	clusters_per_block =
		(block_size > cluster_size) ? block_size / cluster_size : 1;
	device_size = le64_to_cpu(bs->num_sectors) * sector_size;

	block_index_unit = (bs->version_major == 1) ? 16384 : cluster_size;

	err = sys_malloc(30 * block_index_unit - sizeof(bs), &padding);
	if(err) {
		sys_log_perror(err, "Error while allocating %" PRIuz " bytes "
			"for padding",
			PRAuz(30 * block_index_unit - sizeof(bs)));
		goto out;
	}

	err = sys_device_pread(
		/* sys_device *dev */
		dev,
		/* u64 pos */
		sizeof(*bs),
		/* size_t count */
		30 * block_index_unit - sizeof(*bs),
		/* void *b */
		padding);
	if(err) {
		sys_log_perror(err, "Error while reading %" PRIuz " bytes from "
			"sector 1 (offset %" PRIu64 ")",
			PRAuz(30 * block_index_unit - sizeof(*bs)),
			PRAu64(sizeof(*bs)));
		goto out;
	}

	print_data_with_base("", 0, sizeof(*bs), 30 * block_index_unit,
		padding, 30 * block_index_unit - sizeof(*bs));

	sys_free(&padding);

	buffer_size = (u32) sys_max(block_size, 32U * 1024UL * 1024UL);
	err = sys_malloc(buffer_size, &buffer);
	if(err) {
		sys_log_perror(err, "Error while allocating %" PRIu32 " bytes "
			"for metadata block buffer",
			PRAu32(buffer_size));
		goto out;
	}

	for(i = 30 * block_index_unit; i < device_size;
		i += sys_min(cluster_size, block_size))
	{
		const REFS_V3_BLOCK_HEADER *header = NULL;
		const size_t offset_in_buffer = i % buffer_size;

		if(i >= buffer_valid_end) {
			/* Fill buffer. */
			const u64 buffer_read_offset =
				(i / buffer_size) * buffer_size;

			sys_log_debug("Filling %" PRIu32 "-byte buffer from "
				"offset %" PRIu64 "...",
				PRAu32(buffer_size),
				PRAu64(buffer_read_offset));

			err = sys_device_pread(
				/* sys_device *dev */
				dev,
				/* u64 pos */
				buffer_read_offset,
				/* size_t count */
				buffer_size,
				/* void *b */
				buffer);
			if(err) {
				sys_log_perror(err, "Error while reading "
					"%" PRIu32 " bytes from block "
					"%" PRIu64 " (offset %" PRIu64 ")",
					PRAu32(buffer_size),
					PRAu64(i / block_index_unit),
					PRAu64(i));
				goto out;
			}

			buffer_valid_end =
				buffer_read_offset + (u64) buffer_valid_size;
		}

		if(i + sector_size > buffer_valid_end) {
			break;
		}

		block = &buffer[offset_in_buffer];

		if(!(!memcmp(block, "SUPB", 4) || !memcmp(block, "CHKP", 4) ||
			!memcmp(block, "MSB+", 4)))
		{
			continue;
		}

		header = (const REFS_V3_BLOCK_HEADER*) block;

		emit("", 0, "%" PRIu64 "/0x%" PRIX64 ": %" PRIbs " / logical "
			"block %" PRIu64 "/0x%" PRIX64 " / object ID "
			"%" PRIu64 "/0x%" PRIX64,
			PRAu64(i / block_index_unit),
			PRAX64(i / block_index_unit),
			PRAbs(4, header->signature),
			PRAu64(le64_to_cpu(header->block_number)),
			PRAX64(le64_to_cpu(header->block_number)),
			PRAu64(le64_to_cpu(header->object_id)),
			PRAX64(le64_to_cpu(header->object_id)));
		if(visitor && visitor->visit_node) {
			const u64 block_end =
				i + clusters_per_block * cluster_size;
			const u32 cluster_count =
				block_end <= device_size ? clusters_per_block :
				((device_size - i) / cluster_size);

			err = visitor->visit_node(
				/* void *context */
				visitor->context,
				/* u64 cluster_number */
				i / cluster_size,
				/* u32 cluster_count */
				cluster_count,
				/* const REFS_V3_BLOCK_HEADER *header */
				header);
			if(err) {
				goto out;
			}
		}
	}
out:
	if(block) {
		sys_free(&block);
	}

	if(padding) {
		sys_free(&padding);
	}

	return err;
}
