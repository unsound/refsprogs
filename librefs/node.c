/*-
 * node.c - ReFS node handling definitions.
 *
 * Copyright (c) 2022-2023 Erik Larsson
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
		REFS_BOOT_SECTOR *const bs,
		refs_block_map *const mapping_table,
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
			PRAuz(((u64) header - (u64) block) + 0x18),
			PRAXz(((u64) header - (u64) block) + 0x18),
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
			PRAuz(((u64) header - (u64) block) + 0x28),
			PRAXz(((u64) header - (u64) block) + 0x28),
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

	if(REFS_VERSION_MIN(visitor->version_major, visitor->version_minor, 3,
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
	print_unknown64(prefix, indent, block, &header[0x50]);
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
	u32 i;

	emit(prefix, 0, "Entry %" PRIu32 " (%s) @ %" PRIu32 " / 0x%" PRIX32 ":",
		PRAu32(entry_index),
		"table header",
		PRAu32(entry_offset),
		PRAX32(entry_offset));
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
		const sys_bool is_v3,
		const u8 *const entry,
		const u32 entry_size,
		const u32 entry_offset,
		const u32 entry_index,
		u32 *const out_flags,
		u32 *const out_value_offsets_start,
		u32 *const out_value_offsets_end,
		u32 *const out_value_count)
{
	static const char *const prefix = "\t";
	static const size_t indent = 1;

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 i = 0;

	emit(prefix, 0, "Entry %" PRIu32 " (%s) @ %" PRIu32 " / 0x%" PRIX32 ":",
		PRAu32(entry_index),
		"allocation entry",
		PRAu32(entry_offset),
		PRAX32(entry_offset));
	emit(prefix, indent, "Size: %" PRIu64,
		PRAu64(entry_size));
	emit(prefix, indent, "Free space offset: %" PRIu64,
		PRAu64(read_le32(&entry[0x4])));
	emit(prefix, indent, "Free space size: %" PRIu64,
		PRAu64(read_le32(&entry[0x8])));

	emit(prefix, indent, "Flags?: %" PRIu64 " / 0x%" PRIX64,
		PRAu64(read_le32(&entry[0xC])),
		PRAX64(read_le32(&entry[0xC])));
	if(out_flags) {
		*out_flags = read_le32(&entry[0xC]);
	}

	print_le32_dechex("Value offsets array start offset", prefix, indent,
		entry, &entry[0x10]);
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
	(void) is_index;
	(void) context;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"unknown", PRAu16(key_offset), PRAX16(key_offset));

	print_data_with_base(prefix, indent, 0, entry_size, key, key_size);

	return 0;
}

static int parse_unknown_leaf_value(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u32 block_index_unit,
		const sys_bool is_v3,
		const u8 *const key,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u32 entry_size,
		void *const context)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	(void) object_id;
	(void) block_index_unit;
	(void) is_v3;
	(void) key;
	(void) key_size;
	(void) context;

	emit(prefix, indent - 1, "Value (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"unknown", PRAu16(value_offset), PRAX16(value_offset));

	print_data_with_base(prefix, indent, 0, entry_size, value, value_size);

	return 0;
}

static int parse_generic_entry(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const u64 object_id,
		const u32 block_index_unit,
		const sys_bool is_v3,
		const sys_bool is_index,
		const u8 *const entry,
		const u32 entry_size,
		const u32 entry_offset,
		const u32 entry_index,
		void *const context,
		int (*const parse_key)(
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
			refs_node_walk_visitor *visitor,
			const char *prefix,
			size_t indent,
			u64 object_id,
			u32 block_index_unit,
			sys_bool is_v3,
			const u8 *key,
			u16 key_size,
			const u8 *value,
			u16 value_offset,
			u16 value_size,
			u32 entry_size,
			void *context),
		u64 *const out_next_level_block_number)
{
	static const size_t indent = 1;

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 i = 0;
	u16 key_offset = 0;
	u16 key_size = 0;
	const u8 *key = NULL;
	u16 value_offset = 0;
	u16 value_size = 0;

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

	emit(prefix, indent - 1, "Entry %" PRIu32 " (%s) @ %" PRIu32 " / "
		"0x%" PRIX32 ":",
		PRAu32(entry_index),
		"regular entry",
		PRAu32(entry_offset),
		PRAX32(entry_offset));
	emit(prefix, indent, "Size: %" PRIu64 " / 0x%" PRIX64,
		PRAu64(entry_size),
		PRAX64(entry_size));

	print_le16_dechex("Key offset", prefix, indent, entry, &entry[0x4]);
	key_offset = read_le16(&entry[0x4]);
	print_le16_dechex("Key size", prefix, indent, entry, &entry[0x6]);
	key_size = read_le16(&entry[0x6]);
	print_le16_dechex("Flags?", prefix, indent, entry, &entry[0x8]);
	value_offset = read_le16(&entry[0xA]);
	print_le16_dechex("Value offset", prefix, indent, entry, &entry[0xA]);
	value_size = read_le16(&entry[0xC]);
	print_le16_dechex("Value size", prefix, indent, entry, &entry[0xC]);
	print_unknown16(prefix, indent, entry, &entry[0xE]);

	i = 0x10;

	if(key_size && key_offset >= 0x10 && key_offset < entry_size &&
		(entry_size - key_offset) >= key_size &&
		(key_offset + key_size) <= value_offset)
	{
		if(i < key_offset) {
			print_data_with_base(prefix, indent, i, entry_size,
				&entry[i], key_offset - i);
			i = key_offset;
		}

		key = &entry[i];

		err = (parse_key ? parse_key : parse_unknown_key)(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
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
		print_data_with_base(prefix, indent, i, entry_size,
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
			indent + 1,
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
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* u64 object_id */
			object_id,
			/* u32 block_index_unit */
			block_index_unit,
			/* sys_bool is_v3 */
			is_v3,
			/* const u8 *key */
			key,
			/* u16 key_size */
			key ? key_size : 0,
			/* const u8 *value */
			&entry[value_offset],
			/* u16 value_offset */
			value_offset,
			/* u16 value_size */
			value_size,
			/* u32 entry_size */
			entry_size,
			/* void *context */
			context);
	}
out:
	return err;
}

static int parse_generic_block(
		refs_node_walk_visitor *const visitor,
		const u64 cluster_number,
		const u64 block_number,
		const u64 block_queue_index,
		const u8 level,
		const u8 *const block,
		const u32 block_size,
		const u32 block_index_unit,
		block_queue *const block_queue,
		const sys_bool add_subnodes_in_offsets_order,
		void *const context,
		int (*const parse_key)(
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
			refs_node_walk_visitor *visitor,
			const char *prefix,
			size_t indent,
			u64 object_id,
			u32 block_index_unit,
			sys_bool is_v3,
			const u8 *key,
			u16 key_size,
			const u8 *value,
			u16 value_offset,
			u16 value_size,
			u32 entry_size,
			void *context),
		int (*const leaf_entry_handler)(
			void *context,
			const u8 *data,
			u32 data_size,
			u32 node_type))
{
	static const char *const prefix = "\t";

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
		0,
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
	err = parse_block_header_entry(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const u8 *entry */
		entry,
		/* u32 entry_size */
		entry_size,
		/* u32 entry_offset */
		i,
		/* u32 entry_index */
		0);
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
	err = parse_block_allocation_entry(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* sys_bool is_v3 */
		is_v3,
		/* const u8 *entry */
		entry,
		/* u32 entry_size */
		entry_size,
		/* size_t entry_offset */
		i,
		/* u32 entry_index */
		1,
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

		if(cur_offset + 4 > value_offsets_start_real) {
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
			/* refs_node_walk_visitor *visitor */
			!((print_visitor && print_visitor->print_message) ||
			!add_subnodes_in_offsets_order) ? visitor : NULL,
			/* const char *prefix */
			prefix,
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
			/* size_t entry_offset */
			cur_offset,
			/* u32 entry_index */
			cur_index,
			/* void *context */
			context,
			/* int (*parse_key)(
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
			 *      refs_node_walk_visitor *visitor,
			 *      const char *prefix,
			 *      size_t indent,
			 *      u64 object_id,
			 *      u32 block_index_unit,
			 *      sys_bool is_v3,
			 *      const u8 *key,
			 *      u16 key_size,
			 *      const u8 *value,
			 *      u16 value_offset,
			 *      u16 value_size,
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
				print_data_with_base(prefix, 0, i, block_size,
					&block[i],
					smallest_matching_offset - i);
			}

			i = smallest_matching_offset;
			entry = &block[i];
			entry_size = read_le32(entry);

			err = parse_generic_entry(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
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
				/* size_t entry_offset */
				i,
				/* u32 entry_index */
				2 + smallest_matching_entryno,
				/* void *context */
				context,
				/* int (*parse_key)(
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
				 *      u32 block_index_unit,
				 *      sys_bool is_v3,
				 *      const u8 *key,
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
			print_data_with_base(prefix, 0, i, block_size,
				&block[i],
				value_offsets_start_real - i);
		}

		emit(prefix, 0, "Value offsets:");
		i = value_offsets_start_real;
		for(; i < value_offsets_end_real; i += 4) {
			emit(prefix, 1, "[%" PRIuz "]: %" PRIu16 " / "
				"0x%" PRIX16 " (absolute: %" PRIu32 " / "
				"0x%" PRIX32 ") flags / unknown: "
				"0x%" PRIX16,
				PRAuz((i - value_offsets_start_real) /
				4),
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
		print_data_with_base(prefix, 0, i, block_size, &block[i],
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
	u64 block_number = 0;

	(void) object_id;
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
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u32 block_index_unit,
		const sys_bool is_v3,
		const u8 *const key,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u32 entry_size,
		void *const context)
{
	block_range *const range = (block_range*) context;

	int err = 0;

	(void) object_id;
	(void) block_index_unit;
	(void) is_v3;
	(void) key;
	(void) key_size;

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
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u32 block_index_unit,
		const sys_bool is_v3,
		const u8 *const key,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u32 entry_size,
		void *const context)
{
	refs_block_map *const mappings = (refs_block_map*) context;

	int err = 0;
	block_range leaf_range;

	(void) object_id;
	(void) block_index_unit;
	(void) is_v3;
	(void) key;
	(void) key_size;

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
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u32 block_index_unit,
		const sys_bool is_v3,
		const u8 *const key,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u32 entry_size,
		void *const context)
{
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
	else if(object_id == 0xC) {
		err = parse_level2_block_0xB_0xC_leaf_value(
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

	return err;
}

static int parse_level2_block(
		refs_node_walk_visitor *const visitor,
		const u64 cluster_number,
		const u64 block_number,
		const u64 block_queue_index,
		const u8 *const block,
		const u32 block_size,
		const u32 block_index_unit,
		u64 *const object_id_mapping,
		sys_bool *const object_id_mapping_found,
		u64 **const level2_queue,
		size_t *const level2_queue_length,
		u64 **const level3_queue,
		size_t *const level3_queue_length)
{
	static const char *const prefix = "\t";

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
		/* refs_node_walk_visitor *visitor */
		visitor,
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
		/* u32 block_index_unit */
		block_index_unit,
		/* block_queue *block_queue */
		(object_id != 0xB && object_id != 0xC) ? &level2_block_queue :
		NULL,
		/* sys_bool add_subnodes_in_offsets_order */
		SYS_TRUE,
		/* void *context */
		(object_id == 0x2) ? &context : NULL,
		/* int (*parse_key)(
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
		 *      refs_node_walk_visitor *visitor,
		 *      const char *prefix,
		 *      size_t indent,
		 *      u64 object_id,
		 *      u32 block_index_unit,
		 *      sys_bool is_v3,
		 *      const u8 *key,
		 *      u16 key_size,
		 *      const u8 *value,
		 *      u16 value_offset,
		 *      u16 value_size,
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
	const size_t block_count_offset = is_v3 ? 0xE4 : 0xE0;
	const size_t first_block_offset = is_v3 ? 0xD0 : 0xE8;

	u64 first_block = 0;
	u64 block_count = 0;

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	size_t i = 0x8;

	if(attribute_size < 0x56) {
		return 0;
	}

	print_unknown32(prefix, indent, attribute, &attribute[0x8]);
	print_unknown32(prefix, indent, attribute, &attribute[0xC]);
	print_unknown64(prefix, indent, attribute, &attribute[0x10]);
	print_unknown64(prefix, indent, attribute, &attribute[0x18]);
	print_unknown32(prefix, indent, attribute, &attribute[0x20]);
	print_unknown32(prefix, indent, attribute, &attribute[0x24]);
	print_unknown32(prefix, indent, attribute, &attribute[0x28]);
	print_unknown32(prefix, indent, attribute, &attribute[0x2C]);
	print_unknown32(prefix, indent, attribute, &attribute[0x30]);
	print_unknown32(prefix, indent, attribute, &attribute[0x34]);
	print_unknown64(prefix, indent, attribute, &attribute[0x38]);
	print_unknown64(prefix, indent, attribute, &attribute[0x40]);
	print_unknown64(prefix, indent, attribute, &attribute[0x48]);
	print_unknown32(prefix, indent, attribute, &attribute[0x50]);
	print_unknown16(prefix, indent, attribute, &attribute[0x54]);
	i = 0x56;

	if(i + 2 <= attribute_size) {
		i += print_le16_dechex("Number of clusters", prefix, indent,
			attribute, &attribute[i]);
	}
	if(i < attribute_size) {
		const size_t data_size =
			sys_min(attribute_size,
			sys_min(block_count_offset, first_block_offset)) - i;
		print_data_with_base(prefix, indent, i,
			attribute_size,
			&attribute[i], data_size);
		i += data_size;
	}
	if(block_count_offset < first_block_offset && i + 8 <= attribute_size) {
		block_count = read_le64(&attribute[block_count_offset]);
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
		print_data_with_base(prefix, indent, i, attribute_size,
			&attribute[i], first_block_offset - i);
		i = first_block_offset;
	}
	if(i + 8 <= attribute_size) {
		first_block = read_le64(&attribute[first_block_offset]);
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
		print_data_with_base(prefix, indent, i, attribute_size,
			&attribute[i], block_count_offset - i);
		i = block_count_offset;
	}
	if(block_count_offset > first_block_offset && i + 8 <= attribute_size) {
		block_count = read_le32(&attribute[block_count_offset]);
		emit(prefix, indent, "Block count @ %" PRIuz " / "
			"0x%" PRIXz ": %" PRIu32 " / 0x%" PRIX32 " (%" PRIu64 " "
			"bytes)",
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

	(void) context;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"object ID", PRAu16(key_offset), PRAX16(key_offset));

	print_le16_dechex("Key type", prefix, indent, key, &key[0]);
	print_unknown16(prefix, indent, key, &key[2]);
	print_unknown32(prefix, indent, key, &key[4]);
	print_le64_dechex("Object ID", prefix, indent, key, &key[8]);

	return err;
}

static int parse_level3_unknown_key(
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

	(void) context;

	emit(prefix, indent - 1, "Key (%s) @ %" PRIu16 " / 0x%" PRIX16 ":",
		"unknown", PRAu16(key_offset), PRAX16(key_offset));

	print_le16_dechex("Key type", prefix, indent, key, &key[0]);
	emit(prefix, indent, "Key data:");
	print_data_with_base(prefix, indent, 0, entry_size, key, key_size);

	return err;
}

static int parse_level3_key(
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
	else {
		err = parse_level3_unknown_key(
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

/**
 * Parse a long level 3 tree entry value.
 *
 * Long values (type 1) are in all known instances files or links/reparse
 * points.
 */
int parse_level3_long_value(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u32 block_index_unit,
		const sys_bool is_v3,
		const u8 *const key,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		void *const context)
{
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
		(value_size < (is_v3 ? 96 : 104) + 8) ? 0 :
		read_le64(&value[is_v3 ? 96 : 112]);

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 i = 0;
	size_t cur_attribute_end = 0;
	u16 attribute_size = 0;
	u16 attribute_index = 0;
	u32 attributes_offset = 0;
	u16 number_of_attributes = 0;
	u16 offsets_start = 0;
	u16 j = 0;

	(void) context;

	if(visitor && visitor->node_long_entry) {
		err = visitor->node_long_entry(
			/* void *context */
			visitor->context,
			/* const refschar *file_name */
			(const refschar*) &key[4],
			/* u16 file_name_length */
			(key_size - 4) / sizeof(refschar),
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

	emit(prefix, indent, "Attribute %" PRIu16 " @ 0 / 0x0:",
		PRAu16(attribute_index));
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
		print_le32_hex("File flags", prefix, indent + 1, value,
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
			print_le64_dec("File size", prefix, indent + 1, value,
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
			print_le64_dec("File size", prefix, indent + 1, value,
				&value[104]);
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
		if(cur_attribute_end > 0x7C) {
			i += print_unknown32(prefix, indent + 1, value,
				&value[0x78]);
		}
		if(cur_attribute_end > 0x7E) {
			i += print_unknown16(prefix, indent + 1, value,
				&value[0x7C]);
		}
		if(cur_attribute_end > 0x80) {
			i += print_unknown16(prefix, indent + 1, value,
				&value[0x7E]);
		}
		if(cur_attribute_end > 0x88) {
			i += print_unknown64(prefix, indent + 1, value,
				&value[0x80]);
		}
		if(cur_attribute_end > 0x90) {
			i += print_unknown64(prefix, indent + 1, value,
				&value[0x88]);
		}
		if(cur_attribute_end > 0x98) {
			i += print_unknown64(prefix, indent + 1, value,
				&value[0x90]);
		}
		if(cur_attribute_end > 0xA0) {
			i += print_unknown64(prefix, indent + 1, value,
				&value[0x98]);
		}
		if(cur_attribute_end > 0xA8) {
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
		(attribute_index - 2) < number_of_attributes))
	{
		const size_t offset_in_value = i;
		const size_t remaining_in_value =
			value_size - offset_in_value;
		const u8 *attribute = &value[offset_in_value];
		u16 remaining_in_attribute = 0;
		u16 attribute_type = 0;
		u16 attribute_type2 = 0;

		attribute_size = read_le16(&attribute[0]);
		if(!attribute_size) {
			break;
		}

		emit(prefix, indent, "Attribute %" PRIu16 " @ %" PRIuz " / "
			"0x%" PRIXz ":",
			PRAu16(attribute_index),
			PRAuz(offset_in_value),
			PRAXz(offset_in_value));
		++attribute_index;

		j = 0;

		emit(prefix, indent + 1, "Attribute size @ %" PRIuz " / "
			"0x%" PRIXz ": %" PRIu16 " / 0x%" PRIX16 "%s",
			PRAuz(j),
			PRAXz(j),
			PRAu16(attribute_size),
			PRAX16(attribute_size),
			(attribute_size > remaining_in_value) ?
			" (OVERFLOW)" : "");
		if(remaining_in_value < 8) {
			break;
		}

		j += 2;

		remaining_in_attribute =
			(u16) sys_min(attribute_size, remaining_in_value);

		print_unknown16(prefix, indent + 1, attribute,
			&attribute[0x02]);
		j += 2;

		attribute_type = read_le16(&attribute[j]);
		attribute_type2 = read_le16(&attribute[j + 2]);
		j += print_le16_hex("Attribute type 1", prefix, indent + 1,
			attribute, &attribute[j + 0]);
		j += print_le16_hex("Attribute type 2", prefix, indent + 1,
			attribute, &attribute[j + 2]);


		if(attribute_index - 1 == 1 &&
			remaining_in_attribute >= j + 0x18)
		{
			/* Attributes header, always seems to be 40 / 0x28 bytes
			 * on v3 and 32 / 0x20 on v1 and has the number of
			 * attributes plus some other unknown data. */
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]);
			number_of_attributes = read_le16(&attribute[j]);
			j += print_le16_dechex("Number of attributes", prefix,
				indent + 1, attribute, &attribute[j]);
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown64(prefix, indent + 1, attribute,
				&attribute[j]);
			if(remaining_in_attribute - j >= 0x8) {
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]);
			}
		}
		else if(attribute_type == 0x0010 && attribute_type2 == 0x0028 &&
			attribute_size >= 0x48)
		{
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown64(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown16(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown64(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown64(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown64(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]);
			j += print_unknown32(prefix, indent + 1, attribute,
				&attribute[j]);
			if(attribute_size >= 0xE8) {
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]);
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]);
				j += print_unknown16(prefix, indent + 1,
					attribute, &attribute[j]);
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]);
				j += print_unknown64(prefix, indent + 1,
					attribute, &attribute[j]);
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]);
				j += print_unknown32(prefix, indent + 1,
					attribute, &attribute[j]);
			}
		}
		else if(attribute_type == 0x0010 && attribute_type2 == 0x000E) {
			/* This attribute type seems to hold extent info. */
			u64 first_block = 0;
			u64 block_count = 0;

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
			}
		}

		if(j < remaining_in_attribute) {
			print_data_with_base(prefix, indent + 1, j,
				remaining_in_attribute, &attribute[j],
				remaining_in_attribute - j);
			j = remaining_in_attribute;
		}

		i += remaining_in_attribute;
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
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const sys_bool is_v3,
		const u8 *const key,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		void *const context)
{
	const u64 object_id =
		(value_size < (is_v3 ? 8 : 0) + 8) ? 0 :
		read_le64(&value[is_v3 ? 8 : 0]);
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

	(void) context;

	if(visitor && visitor->node_short_entry) {
		err = visitor->node_short_entry(
			/* void *context */
			visitor->context,
			/* const refschar *file_name */
			(const refschar*) &key[4],
			/* u16 file_name_length */
			(key_size - 4) / sizeof(refschar),
			/* u32 file_flags */
			file_flags,
			/* u64 object_id */
			object_id,
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
		print_unknown64(prefix, indent, value, &value[0]);
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
	emit(prefix, indent, "File flags: 0x%" PRIX32,
		PRAX32(file_flags));
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
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u64 object_id,
		const u32 block_index_unit,
		const sys_bool is_v3,
		const u8 *const key,
		const u16 key_size,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		const u32 entry_size,
		void *const context)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 key_type = (key_size >= 2) ? read_le16(&key[0]) : 0;
	const u16 dirent_type = (key_size >= 4) ? read_le16(&key[2]) : 0;

	int err = 0;

	(void) object_id;
	(void) entry_size;

	if(key_type == 0x30 && dirent_type == 0x1) {
		/* File. */
		err = parse_level3_long_value(
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
		refs_node_walk_visitor *const visitor,
		const u64 cluster_number,
		const u64 block_number,
		const u64 block_queue_index,
		const u8 *const block,
		const u32 block_size,
		const u32 block_index_unit,
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
		/* refs_node_walk_visitor *visitor */
		visitor,
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
		/* u32 block_index_unit */
		block_index_unit,
		/* block_queue *block_queue */
		&block_queue,
		/* sys_bool add_subnodes_in_offsets_order */
		SYS_TRUE,
		/* void *context */
		&block_queue,
		/* int (*parse_key)(
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
		 *      refs_node_walk_visitor *visitor,
		 *      const char *prefix,
		 *      size_t indent,
		 *      u64 object_id,
		 *      u32 block_index_unit,
		 *      sys_bool is_v3,
		 *      const u8 *key,
		 *      u16 key_size,
		 *      const u8 *value,
		 *      u16 value_offset,
		 *      u16 value_size,
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
	u64 cluster_size = 0;
	u32 block_size = 0;
	u32 block_index_unit = 0;
	u8 *padding = NULL;
	u8 *block = NULL;
	refs_block_map mappings;
	u64 primary_level1_block = 0;
	u64 secondary_level1_block = 0;
	u64 *primary_level2_blocks = NULL;
	size_t primary_level2_blocks_count = 0;
	u64 *secondary_level2_blocks = NULL;
	size_t secondary_level2_blocks_count = 0;
	block_queue level2_queue;
	block_queue level3_queue;
	size_t i = 0;

	memset(&mappings, 0, sizeof(mappings));
	memset(&level2_queue, 0, sizeof(level2_queue));
	memset(&level3_queue, 0, sizeof(level3_queue));

	/* Superblock seems to be at cluster 30. Block is metadata-block
	 * sized. */
	cluster_size =
		((u64) le32_to_cpu(bs->bytes_per_sector)) *
		le32_to_cpu(bs->sectors_per_cluster);
	block_size =
		is_v3 ? sys_max(16U * 1024U, cluster_size) :
		((cluster_size == 4096) ? 12U * 1024U : 16U * 1024U);

	block_index_unit = is_v3 ? cluster_size : 16384;

	visitor->version_major = bs->version_major;
	visitor->version_minor = bs->version_minor;

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
		sys_log_warning("Mismatching level 2 block data in "
			"level 1 blocks. Proceeding with primary...");
	}

	level2_queue.block_numbers = primary_level2_blocks;
	level2_queue.block_queue_length = primary_level2_blocks_count;
	level2_queue.elements_per_entry = is_v3 ? 6 : 3;

	level3_queue.elements_per_entry = 1;

	primary_level2_blocks = NULL;
	primary_level2_blocks_count = 0;

	if(block_map && *block_map) {
		mappings = **block_map;
	}
	else {
		/* For v3 volumes we first iterate over the Level 2 blocks to
		 * find the block region mappings, located in the tree with
		 * object ID 0xB. */
		for(i = 0; is_v3 && i < level2_queue.block_queue_length; ++i) {
			const u64 logical_block_number =
				level2_queue.block_numbers[i * (is_v3 ? 6 : 3)];

			u64 physical_block_number;
			const REFS_V3_BLOCK_HEADER *header = NULL;
			size_t j = 0;
			u64 object_id = 0;

			physical_block_number =
				logical_to_physical_block_number(
					/* REFS_BOOT_SECTOR *bs */
					bs,
					/* mapping_table *mapping_table */
					NULL,
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

			object_id = le64_to_cpu(header->object_id);
			if(object_id != 0xB && object_id != 0xC) {
				/* Not the tree that we are looking for... */
				continue;
			}

			/* We are now sure that this is the 0xB tree, which
			 * describes logical->physical block mappings. If this
			 * is an index node we iterate over the indices in the
			 * order described by the attribute list. */

			err = parse_generic_block(
				/* refs_node_walk_visitor *visitor */
				NULL,
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
				/* u32 block_index_unit */
				block_index_unit,
				/* block_queue *block_queue */
				&level2_queue,
				/* sys_bool add_subnodes_in_offsets_order */
				SYS_TRUE,
				/* void *context */
				(object_id == 0xB) ? &mappings : NULL,
				/* int (*parse_key)(
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
				 *      refs_node_walk_visitor *visitor,
				 *      const char *prefix,
				 *      size_t indent,
				 *      u64 object_id,
				 *      u32 block_index_unit,
				 *      sys_bool is_v3,
				 *      const u8 *key,
				 *      u16 key_size,
				 *      const u8 *value,
				 *      u16 value_offset,
				 *      u16 value_size,
				 *      u32 entry_size,
				 *      void *context) */
				(object_id == 0xB) ?
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
				PRAuz(mappings.length));
			for(j = 0; j < mappings.length; ++j) {
				sys_log_debug("\t[%" PRIuz "]:",
					PRAuz(j));
				sys_log_debug("\t\tStart: %" PRIu64,
					PRAu64(mappings.entries[j].
					start));
				sys_log_debug("\t\tLength: %" PRIu64,
					PRAu64(mappings.entries[j].
					length));
			}
		}
	}

	/* At this point the mappings are set up and we can look up a node by
	 * node number. */
	if(start_node) {
		const u64 logical_block_number = *start_node;
		u64 physical_block_number;
		u64 object_id = 0;
		sys_bool is_valid = SYS_FALSE;

		/* Discard primary level 2 blocks as we want a crawl targeted at
		 * the requested node number. The crawl may still add level 2
		 * blocks to the queue if we encounter a level 2 index node. */
		sys_free(&level2_queue.block_numbers);
		level2_queue.block_queue_length = 0;

		physical_block_number =
			logical_to_physical_block_number(
				/* REFS_BOOT_SECTOR *bs */
				bs,
				/* mapping_table *mapping_table */
				&mappings,
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
			&object_id);
		if(err) {
			goto out;
		}

		if(object_id < 0x500) {
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
					/* REFS_BOOT_SECTOR *bs */
					bs,
					/* mapping_table *mapping_table */
					&mappings,
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
				/* u32 block_index_unit */
				block_index_unit,
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
		size_t i;

		for(i = 0; i < level3_queue.block_queue_length; ++i) {
			const u64 logical_block_number =
				level3_queue.block_numbers[i];
			u64 physical_block_number;

			physical_block_number =
				logical_to_physical_block_number(
					/* REFS_BOOT_SECTOR *bs */
					bs,
					/* mapping_table *mapping_table */
					&mappings,
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
				/* u32 block_index_unit */
				block_index_unit,
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

	if(mappings.entries) {
		sys_free(&mappings.entries);
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
