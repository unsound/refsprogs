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

#include "rb_tree.h"
#include "layout.h"
#include "util.h"
#include "sys.h"


/* Macros. */

#define emit_entry_header(prefix, indent, title, entry_index, num_entries, \
		entry_offset, type) \
	emit((prefix), (indent), "%s %" PRIu32 " / %" PRIu32 " (%s) @ " \
		"%" PRIu32 " / 0x%" PRIX32 ":", \
		(title), \
		PRAu32((entry_index) + 1), \
		PRAu32(num_entries), \
		(type), \
		PRAu32(entry_offset), \
		PRAX32(entry_offset))


/* Type declarations / definitions. */

typedef struct {
	u64 start;
	u64 length;
} block_range;

struct refs_block_map {
	block_range *entries;
	size_t length;
};

typedef struct refs_node_block_queue_element refs_node_block_queue_element;

struct refs_node_block_queue_element {
	u64 block_numbers[4];
	u64 flags;
	u64 checksum;
	refs_node_block_queue_element *next;
};

typedef struct {
	refs_node_block_queue_element *queue;
	refs_node_block_queue_element *queue_tail;
	size_t block_queue_length;
} refs_node_block_queue;

typedef struct refs_node_cache_item refs_node_cache_item;

struct refs_node_cache_item {
	refs_node_cache *cache;
	u64 start_block;
	void *data;
	refs_node_cache_item *lru_list_prev;
	refs_node_cache_item *lru_list_next;
};

struct refs_node_cache {
	size_t node_size;
	struct refs_rb_tree *node_tree;
	refs_node_cache_item *lru_list;
	size_t cur_node_count;
	size_t max_node_count;
};


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

static int refs_node_cache_item_compare(
		struct refs_rb_tree *const self,
		struct refs_rb_node *const a_node,
		struct refs_rb_node *const b_node)
{
	const refs_node_cache_item *const a =
		(const refs_node_cache_item*) a_node->value;
	const refs_node_cache_item *const b =
		(const refs_node_cache_item*) b_node->value;

	(void) self;

	if(a->start_block < b->start_block) {
		return -1;
	}
	else if(a->start_block > b->start_block) {
		return 1;
	}

	return 0;
}

int refs_node_cache_create(
		const size_t max_node_count,
		refs_node_cache **const out_cache)
{
	int err = 0;
	struct refs_rb_tree *node_tree = NULL;

	node_tree = refs_rb_tree_create(
		/* refs_rb_tree_node_cmp_f cmp */
		refs_node_cache_item_compare);
	if(!node_tree) {
		err = ENOMEM;
		goto out;
	}

	err = sys_calloc(sizeof(refs_node_cache), out_cache);
	if(err) {
		goto out;
	}

	(*out_cache)->node_tree = node_tree;
	(*out_cache)->max_node_count = max_node_count;
out:
	return err;
}

static void refs_node_cache_item_add_to_lru(
		refs_node_cache_item *const item)
{
	if(!item->cache->lru_list) {
		item->lru_list_next = item;
		item->lru_list_prev = item;
		item->cache->lru_list = item;
	}
	else {
		/* We insert the new item at the previous location from
		 * the head, i.e. at the tail of the list. Then we pop
		 * off the least recently used item from the head. */
		item->lru_list_prev = item->cache->lru_list->lru_list_prev;
		item->cache->lru_list->lru_list_prev->lru_list_next = item;
		item->cache->lru_list->lru_list_prev = item;
		item->lru_list_next = item->cache->lru_list;
	}

	sys_log_debug("Add to LRU: %p (next: %p, prev: %p)",
		item, item->lru_list_next, item->lru_list_prev);

	++item->cache->cur_node_count;
}

static void refs_node_cache_item_remove_from_lru(
		refs_node_cache_item *const item)
{
	sys_log_debug("Remove from LRU: %p", item);

	if(item->lru_list_next != item) {
		/* Connect the next and previous item bypassing the item that is
		 * being removed. */
		refs_node_cache_item *const next =
			item->lru_list_next;
		refs_node_cache_item *const prev =
			item->lru_list_prev;
		next->lru_list_prev = item->lru_list_prev;
		prev->lru_list_next = item->lru_list_next;
	}

	if(item->cache->lru_list == item) {
		/* If this is the head of the list, replace the head if there
		 * are more items or set it to NULL if there aren't. */
		item->cache->lru_list =
			(item->lru_list_next != item) ? item->lru_list_next :
			NULL;
	}

	item->lru_list_next = NULL;
	item->lru_list_prev = NULL;
}

static void refs_node_cache_remove_rb_tree_callback(
		struct refs_rb_tree *const self,
		struct refs_rb_node *const node)
{
	refs_node_cache_item *const item = (refs_node_cache_item*) node->value;

	(void) self;

	refs_node_cache_item_remove_from_lru(
		/* refs_node_cache_item *item */
		item);
}

static sys_bool refs_node_cache_remove(
		refs_node_cache *const cache,
		const u64 start_block)
{
	sys_bool res;
	refs_node_cache_item search_item;

	memset(&search_item, 0, sizeof(search_item));
	search_item.start_block = start_block;

	if(refs_rb_tree_remove_with_cb(
		/* struct refs_rb_tree *self */
		cache->node_tree,
		/* void *value */
		&search_item,
		/* refs_rb_tree_node_f node_cb) */
		refs_node_cache_remove_rb_tree_callback))
	{
		--cache->cur_node_count;
		res = SYS_TRUE;
	}
	else {
		res = SYS_FALSE;
	}

	return res;
}

void refs_node_cache_destroy(
		refs_node_cache **const cachep)
{
	/* Iterate over cache items and free them. */
	while((*cachep)->lru_list) {
		refs_node_cache_item *item = (*cachep)->lru_list;

		if(!refs_node_cache_remove(
			/* refs_node_cache *cache */
			*cachep,
			/* u64 start_block */
			item->start_block))
		{
			sys_log_critical("Couldn't find cache item in cache at "
				"destroy time.");
		}

		if(item->data) {
			sys_free(&item->data);
		}

		sys_free(&item);
	}

	sys_free(cachep);
}

static const u8* refs_node_cache_search(
		refs_node_cache *const cache,
		const u64 start_block)
{
	refs_node_cache_item search_item;
	refs_node_cache_item *cache_item = NULL;

	memset(&search_item, 0, sizeof(search_item));
	search_item.start_block = start_block;

	cache_item = (refs_node_cache_item*) refs_rb_tree_find(
		/* struct refs_rb_tree *self */
		cache->node_tree,
		/* void *value */
		&search_item);
	if(cache_item) {
		/* A cache hit means we should put the item at the end of the
		 * LRU list to avoid it being evicted next time the cache is
		 * full. */

		refs_node_cache_item_remove_from_lru(
			/* refs_node_cache_item *item */
			cache_item);

		refs_node_cache_item_add_to_lru(
			/* refs_node_cache_item *item */
			cache_item);
	}

	return cache_item ? cache_item->data : NULL;
}

static int refs_node_cache_insert(
		refs_node_cache *const cache,
		const u64 first_block,
		const size_t node_size,
		const u8 *const node_data)
{
	int err = 0;
	refs_node_cache_item *insert_item = NULL;

	if(cache->cur_node_count == cache->max_node_count) {
		sys_log_debug("Evicting cache block %" PRIu64 " because the "
			"cache is full.",
			PRAu64(cache->lru_list->start_block));
		if(!refs_node_cache_remove(
			/* refs_node_cache *cache */
			cache,
			/* u64 start_block */
			cache->lru_list->start_block))
		{
			sys_log_critical("Couldn't find the head to the list "
				"in the cache tree: %" PRIu64,
				PRAu64(cache->lru_list->start_block));
			err = ENXIO;
			goto out;
		}
	}

	err = sys_calloc(sizeof(*insert_item), &insert_item);
	if(err) {
		goto out;
	}

	err = sys_malloc(node_size, &insert_item->data);
	if(err) {
		goto out;
	}

	memcpy(insert_item->data, node_data, node_size);
	insert_item->cache = cache;
	insert_item->start_block = first_block;

	if(!refs_rb_tree_insert(
		/* struct refs_rb_tree *self */
		cache->node_tree,
		/* void *value */
		insert_item))
	{
		err = ENOMEM;
	}
	else {
		refs_node_cache_item_add_to_lru(
			/* refs_node_cache_item *item */
			insert_item);

		/* Ownership passed to the cache. */
		insert_item = NULL;
	}
out:
	if(insert_item) {
		if(insert_item->data) {
			sys_free(&insert_item->data);
		}

		sys_free(&insert_item);
	}

	return err;
}

static int refs_node_block_queue_add(
		refs_node_block_queue *const block_queue,
		const u64 block_numbers[4],
		const u64 flags,
		const u64 checksum)
{
	const size_t new_block_queue_length =
		block_queue->block_queue_length + 1;

	int err = 0;
	refs_node_block_queue_element *new_element = NULL;

	sys_log_debug("Block queue before expansion (%" PRIuz " elements):",
		PRAuz(block_queue->block_queue_length));
#if 1 || SYS_LOG_DEBUG_ENABLED
	{
		refs_node_block_queue_element *cur_element = block_queue->queue;
		size_t i = 0;
		while(cur_element) {
			sys_log_debug("\t[%" PRIuz "]: %" PRIu64,
				PRAuz(i),
				PRAu64(cur_element->block_numbers[0]));
			++i;
			cur_element = cur_element->next;
		}
	}
#endif /* SYS_LOG_DEBUG_ENABLED */

	err = sys_malloc(sizeof(*new_element), &new_element);
	if(err) {
		goto out;
	}

	memset(new_element, 0, sizeof(*new_element));
	new_element->block_numbers[0] = block_numbers[0];
	new_element->block_numbers[1] = block_numbers[1];
	new_element->block_numbers[2] = block_numbers[2];
	new_element->block_numbers[3] = block_numbers[3];
	new_element->flags = flags;
	new_element->checksum = checksum;
	new_element->next = NULL;

	if(!block_queue->queue) {
		block_queue->queue = new_element;
		block_queue->queue_tail = new_element;
	}
	else {
		block_queue->queue_tail->next = new_element;
		block_queue->queue_tail = new_element;
	}

	block_queue->block_queue_length = new_block_queue_length;

	sys_log_debug("Block queue after expansion (%" PRIuz " elements):",
		PRAuz(block_queue->block_queue_length));
#if 1 || SYS_LOG_DEBUG_ENABLED
	{
		refs_node_block_queue_element *cur_element = block_queue->queue;
		size_t i = 0;
		while(cur_element) {
			sys_log_debug("\t[%" PRIuz "]: %" PRIu64,
				PRAuz(i),
				PRAu64(cur_element->block_numbers[0]));
			++i;
			cur_element = cur_element->next;
		}
	}
#endif /* SYS_LOG_DEBUG_ENABLED */
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

	if(bs->version_major < 2 || logical_block_number < linear_block_count) {
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

/**
 * Reads the data of a node and returns it as a @ref sys_malloc allocated buffer
 * in @p out_data.
 *
 * The @p logical_blocks array must have at least one valid element while the
 * @p physical_blocks array may be zeroed if the physical blocks have not yet
 * been resolved by the caller, in which case this function will resolve the
 * physical blocks and write them back into the @p physical_blocks array.
 *
 * If the cluster size is larger than or equal to the node size then it won't
 * need more than one valid block but if the cluster size is less than the node
 * size then either:
 * - All logical and optionally blocks can be supplied by the caller, in which
 *   case the function will simply read these blocks into memory (up to 4
 *   blocks, for a 4k cluster size and 16k node size) or
 * - One logical/physical block is supplied, the rest are zeroed, in which case
 *   the rest of the blocks are resolved from the node header (needs at least 2
 *   reads).
 *   The blocks will be resolved into the @p logical_blocks and
 *   @p physical_blocks array, so that the caller can reuse the results if it
 *   wishes.
 *
 * @param[in] crawl_context
 *      The crawl context of the current session.
 * @param[in, out] logical_blocks
 *      Array of logical blocks to read. At least one element must be valid, but
 *      if all logical blocks are known then they should all be supplied or the
 *      read will be less efficient. After this function returns successfully,
 *      all logical blocks will be valid in this array as they are written back
 *      after being resolved.
 * @param[in, out] physical_blocks
 *      Array of physical blocks to read. These can all be zeroed, in which case
 *      they will be resolved using the node map, but if all physical blocks are
 *      known then they should all be supplied or the read will be less
 *      efficient. After this function returns successfully, all physical blocks
 *      will be valid in this array as they are written back after being
 *      resolved.
 * @param[out] out_data
 *      Pointer to a @p u8* field that will receive the data buffer of the node.
 *      If @p *out_data is non-@p NULL at the start of the function, then no new
 *      allocation will be done and the data will be read into the existing
 *      buffer.
 *
 * @return
 *      0 on success and otherwise a non-0 @p errno value.
 */
static int refs_node_get_node_data(
		refs_node_crawl_context *const crawl_context,
		const size_t node_size,
		u64 *const logical_blocks,
		u64 *const physical_blocks,
		u8 **const out_data)
{
	const size_t bytes_per_read =
		sys_min(crawl_context->cluster_size, node_size);

	int err = 0;
	const u8 *cached_data = NULL;
	u8 *data = NULL;
	size_t bytes_read = 0;
	u8 i = 0;

	if(!logical_blocks[0]) {
		sys_log_error("Can't get node data for logical block 0.");
		err = EINVAL;
		goto out;
	}

	if(*out_data) {
		data = *out_data;
	}
	else {
		err = sys_malloc(node_size, &data);
		if(err) {
			sys_log_perror(err, "Error while allocating "
				"%" PRIu32 "-byte block",
				PRAu32(node_size));
			goto out;
		}
	}

	if(crawl_context->node_cache) {
		cached_data = refs_node_cache_search(
			/* refs_node_cache *cache */
			crawl_context->node_cache,
			/* u64 start_block */
			logical_blocks[0]);
		sys_log_debug("Cache %s for block %" PRIu64 ".",
			cached_data ? "HIT" : "MISS",
			PRAu64(logical_blocks[0]));
	}
	if(cached_data) {
		memcpy(data, cached_data, node_size);
	}
	else while(bytes_read < node_size) {
		if(!logical_blocks[i]) {
			/* The next logical block is unknown so far. Check the
			 * node header. Note that this only happens in v3+
			 * volumes with a cluster size less than 16k. */
			const REFS_V3_NODE_HEADER *const header =
				(const REFS_V3_NODE_HEADER*) data;
			u8 j;

			for(j = i; j < 4; ++j) {
				logical_blocks[j] =
					le64_to_cpu(header->block_numbers[j]);
			}
		}

		if(!physical_blocks[i]) {
			physical_blocks[i] = logical_to_physical_block_number(
				/* refs_node_crawl_context *crawl_context */
				crawl_context,
				/* u64 logical_block_number */
				logical_blocks[i]);
		}

		sys_log_debug("Reading logical block %" PRIu64 " / physical "
			"block %" PRIu64 " into %" PRIuz "-byte buffer %p at "
			"buffer offset %" PRIuz,
			PRAu64(logical_blocks[i]),
			PRAu64(physical_blocks[i]),
			PRAuz(crawl_context->block_size),
			data,
			PRAuz(bytes_read));

		err = sys_device_pread(
			/* sys_device *dev */
			crawl_context->dev,
			/* u64 pos */
			physical_blocks[i] * crawl_context->block_index_unit,
			/* size_t count */
			bytes_per_read,
			/* void *b */
			&data[bytes_read]);
		if(err) {
			sys_log_perror(err, "Error while reading %" PRIuz " "
				"bytes from metadata logical block %" PRIu64 " "
				"/ physical block %" PRIu64 " (offset "
				"%" PRIu64 ")",
				PRAuz(bytes_per_read),
				PRAu64(logical_blocks[i]),
				PRAu64(physical_blocks[i]),
				PRAu64(physical_blocks[i] *
				crawl_context->block_index_unit));
			goto out;
		}

		bytes_read += bytes_per_read;
		++i;
	}

	if(crawl_context->node_cache && !cached_data) {
		/* Add the data read from disk to the node cache. */
		err = refs_node_cache_insert(
			/* refs_node_cache *cache */
			crawl_context->node_cache,
			/* u64 first_block */
			logical_blocks[0],
			/* size_t node_size */
			node_size,
			/* const u8 *node_data */
			data);
		if(err) {
			sys_log_pwarning(err, "Error while adding node data to "
				"cache (ignoring)");
			err = 0;
		}
	}

	*out_data = data;
out:
	return err;
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

static u32 parse_superblock_level1_block_list(
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

	emit(prefix, indent, "Level 1 blocks (%" PRIu32 " bytes @ %" PRIu32 " "
		"/ 0x%" PRIX32 "):",
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

static void parse_node_reference_v1(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const base,
		const u8 *const data)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	print_le64_dec("Block number", prefix, indent,
		base,
		&data[0]);
	print_le64_hex("Flags(?)", prefix, indent,
		base,
		&data[8]);
	print_le64_hex("Checksum(?)", prefix, indent,
		base,
		&data[16]);
}

static void parse_node_reference_v3(
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

static void parse_node_reference(
		refs_node_walk_visitor *const visitor,
		const sys_bool is_v3,
		const char *const prefix,
		const size_t indent,
		const u8 *const base,
		const u8 *const data)
{
	if(is_v3) {
		parse_node_reference_v3(
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
		parse_node_reference_v1(
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

static int parse_node_reference_list_v1(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const char *const list_name,
		const u8 *const block,
		const size_t block_size,
		const u32 *const node_reference_offsets,
		const size_t node_references_size,
		refs_node_block_queue_element **const out_node_references,
		u32 *const out_total_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 total_size = 0;
	size_t i;
	refs_node_block_queue_element *first_element = NULL;
	refs_node_block_queue_element *last_element = NULL;

	emit(prefix, indent - 1, "%s (%" PRIuz " bytes @ %" PRIu32 " / "
		"0x%" PRIX32 "):",
		list_name,
		PRAuz(node_references_size),
		PRAu32(node_reference_offsets[0]),
		PRAX32(node_reference_offsets[0]));
	for(i = 0; i + 24 <= node_references_size; i += 24) {
		const size_t reference_index = i / 24;
		const u32 reference_offset =
			node_reference_offsets[reference_index];

		if(i && reference_offset >
			node_reference_offsets[reference_index - 1] + 24)
		{
			const u32 prev_reference_end =
				node_reference_offsets[reference_index - 1] + 24;

			/* Print padding / data in between node references. */
			print_data_with_base(prefix, indent, prev_reference_end,
				block_size, &block[prev_reference_end],
				reference_offset - prev_reference_end);
			total_size += reference_offset - prev_reference_end;
		}

		emit(prefix, indent, "[%" PRIu32 "] @ %" PRIu32 " / "
			"0x%" PRIX32 ":",
			PRAu32(reference_index),
			PRAu32(reference_offset),
			PRAX32(reference_offset));
		parse_node_reference_v1(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const u8 *base */
			&block[reference_offset],
			/* const u8 *data */
			&block[reference_offset]);
		if(out_node_references) {
			refs_node_block_queue_element *cur_element = NULL;

			err = sys_malloc(sizeof(*cur_element), &cur_element);
			if(err) {
				sys_log_perror(err, "Error while allocating "
					"reference");
				goto out;
			}

			cur_element->block_numbers[0] =
				read_le64(&block[reference_offset + 0]);
			cur_element->block_numbers[1] = 0;
			cur_element->block_numbers[2] = 0;
			cur_element->block_numbers[3] = 0;
			cur_element->flags =
				read_le64(&block[reference_offset + 8]);
			cur_element->checksum =
				read_le64(&block[reference_offset + 16]);
			cur_element->next = NULL;

			if(!first_element) {
				first_element = cur_element;
				last_element = cur_element;
			}
			else {
				last_element->next = cur_element;
				last_element = cur_element;
			}
		}

		total_size += 24;
	}

	if(out_node_references) {
		*out_node_references = first_element;
	}

	if(out_total_size) {
		*out_total_size = total_size;
	}
out:
	return err;
}

static int parse_node_reference_list_v3(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const char *const list_name,
		const u8 *const block,
		const size_t block_size,
		const u32 *const node_reference_offsets,
		const size_t node_references_size,
		refs_node_block_queue_element **const out_node_references,
		u32 *const out_total_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 total_size = 0;
	size_t i;
	refs_node_block_queue_element *first_element = NULL;
	refs_node_block_queue_element *last_element = NULL;

	emit(prefix, indent - 1, "%s (%" PRIuz " bytes @ %" PRIu32 " / "
		"0x%" PRIX32 "):",
		list_name,
		PRAuz(node_references_size),
		PRAu32(node_reference_offsets[0]),
		PRAX32(node_reference_offsets[0]));
	for(i = 0; i + 48 <= node_references_size; i += 48) {
		const size_t reference_index = i / 48;
		const u32 reference_offset =
			node_reference_offsets[reference_index];

		if(i && reference_offset >
			node_reference_offsets[reference_index - 1] + 48)
		{
			const u32 prev_reference_end =
				node_reference_offsets[reference_index - 1] +
				48;

			/* Print padding / data in between node references. */
			print_data_with_base(prefix, indent - 1,
				prev_reference_end, block_size,
				&block[prev_reference_end],
				reference_offset - prev_reference_end);
			total_size += reference_offset - prev_reference_end;
		}

		emit(prefix, indent, "[%" PRIu32 "] @ %" PRIu32 " / "
			"0x%" PRIX32 ":",
			PRAu32(reference_index),
			PRAu32(reference_offset),
			PRAX32(reference_offset));
		parse_node_reference_v3(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const u8 *base */
			&block[reference_offset],
			/* const u8 *data */
			&block[reference_offset]);
		if(out_node_references) {
			refs_node_block_queue_element *cur_element = NULL;

			err = sys_malloc(sizeof(*cur_element), &cur_element);
			if(err) {
				sys_log_perror(err, "Error while allocating "
					"reference");
				goto out;
			}

			cur_element->block_numbers[0] =
				read_le64(&block[reference_offset + 0]);
			cur_element->block_numbers[1] =
				read_le64(&block[reference_offset + 8]);
			cur_element->block_numbers[2] =
				read_le64(&block[reference_offset + 16]);
			cur_element->block_numbers[3] =
				read_le64(&block[reference_offset + 24]);
			cur_element->flags =
				read_le64(&block[reference_offset + 32]);
			cur_element->checksum =
				read_le64(&block[reference_offset + 40]);
			cur_element->next = NULL;

			if(!first_element) {
				first_element = cur_element;
				last_element = cur_element;
			}
			else {
				last_element->next = cur_element;
				last_element = cur_element;
			}
		}

		total_size += 48;
	}

	if(out_node_references) {
		*out_node_references = first_element;
	}

	if(out_total_size) {
		*out_total_size = total_size;
	}
out:
	return err;
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
		emit(prefix, indent, "%s level 1 block (physical block "
			"%" PRIu64 " / 0x%" PRIX64 "):",
			(block_queue_index == 0) ? "Primary" : "Secondary",
			PRAu64(block_number), PRAX64(block_number));
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

static int parse_superblock_v1(
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

	int err = 0;
	u32 level_1_block_list_offset = 0;
	u32 level_1_block_list_count = 0;
	u32 self_reference_offset = 0;
	u32 self_reference_size = 0;
	size_t i = 0;

	print_le64_dechex("Self block index", prefix, indent, header,
		&header->self_block_index);
	print_unknown64(prefix, indent, block, &header->reserved8);
	print_unknown64(prefix, indent, block, &header->reserved16);
	print_unknown64(prefix, indent, block, &header->reserved24);
	print_unknown64(prefix, indent, block, &header->reserved32);
	print_unknown64(prefix, indent, block, &header->reserved40);
	emit(prefix, indent, "GUID @ %" PRIuz " / 0x%" PRIXz ": %" PRIGUID,
		PRAuz(offsetof(REFS_V1_SUPERBLOCK_HEADER, block_guid)),
		PRAXz(offsetof(REFS_V1_SUPERBLOCK_HEADER, block_guid)),
		PRAGUID(header->block_guid));
	print_unknown64(prefix, indent, block, &header->reserved64);
	print_unknown64(prefix, indent, block, &header->reserved72);
	level_1_block_list_offset = le32_to_cpu(header->level1_blocks_offset);
	print_le32_dec("Offset of level 1 block list", prefix, indent,
		header, &header->level1_blocks_offset);
	level_1_block_list_count = le32_to_cpu(header->level1_blocks_count);
	print_le32_dec("Number of level 1 block list", prefix, indent,
		header, &header->level1_blocks_count);
	self_reference_offset = le32_to_cpu(header->self_extents_offset);
	print_le32_dec("Offset of self reference", prefix, indent, header,
		&header->self_extents_offset);
	self_reference_size = le32_to_cpu(header->self_extents_size);
	print_le32_dec("Size of self reference", prefix, indent, header,
		&header->self_extents_size);

	if(sys_min(level_1_block_list_offset, self_reference_offset) > 96)
	{
		print_data_with_base(prefix, indent, 96, block_size, &block[96],
			sys_min(level_1_block_list_offset,
			self_reference_offset) - 96);
	}

	/* TODO: Validate contents past first self reference element based on
	 * prior observations and fail if it deviates. This may be a description
	 * of a fragmented superblock, but we have not seen those yet so we
	 * don't quite know what to expect. */

	if(level_1_block_list_offset < self_reference_offset) {
		i = level_1_block_list_offset;
		i += parse_superblock_level1_block_list(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *const block */
			block,
			/* u32 level_1_blocks_offset */
			level_1_block_list_offset,
			/* u32 level_1_blocks_count */
			level_1_block_list_count,
			/* u64 *out_primary_level1_block */
			out_primary_level1_block,
			/* u64 *out_secondary_level1_block */
			out_secondary_level1_block);
	}
	else {
		u32 total_size = 0;

		i = self_reference_offset;

		err = parse_node_reference_list_v1(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self reference",
			/* const u8 *const block */
			block,
			/* const size_t block_size */
			block_size,
			/* const u32 *node_reference_offsets */
			&self_reference_offset,
			/* u32 node_references_size */
			(self_reference_size > 24) ? 24 : self_reference_size,
			/* refs_node_block_queue_element
			 * **out_node_references */
			NULL,
			/* u32 *out_total_size */
			&total_size);
		if(err) {
			goto out;
		}

		i += total_size;
	}

	if(sys_max(level_1_block_list_offset, self_reference_offset) > i)
	{
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			sys_min(level_1_block_list_offset,
			self_reference_offset) - i);
	}

	if(level_1_block_list_offset < self_reference_offset) {
		u32 total_size = 0;

		i = self_reference_offset;

		err = parse_node_reference_list_v1(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self reference",
			/* const u8 *const block */
			block,
			/* const size_t block_size */
			block_size,
			/* const u32 *node_reference_offsets */
			&self_reference_offset,
			/* u32 node_references_size */
			(self_reference_size > 24) ? 24 : self_reference_size,
			/* refs_node_block_queue_element
			 * **out_node_references */
			NULL,
			/* u32 *out_total_size */
			&total_size);
		if(err) {
			goto out;
		}

		i += total_size;
	}
	else {
		i = level_1_block_list_offset;
		i += parse_superblock_level1_block_list(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *const block */
			block,
			/* u32 level_1_blocks_offset */
			level_1_block_list_offset,
			/* u32 level_1_blocks_count */
			level_1_block_list_count,
			/* u64 *out_primary_level1_block */
			out_primary_level1_block,
			/* u64 *out_secondary_level1_block */
			out_secondary_level1_block);
	}

	if(i < block_size) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			block_size - i);
	}
out:
	return err;
}

static int parse_superblock_v3(
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

	int err = 0;
	u32 level_1_block_list_offset = 0;
	u32 level_1_block_list_count = 0;
	u32 self_reference_offset = 0;
	u32 self_reference_size = 0;
	u32 i = 0;

	const REFS_V3_SUPERBLOCK_HEADER *const sb =
		(const REFS_V3_SUPERBLOCK_HEADER*) block;

	emit(prefix, indent, "Signature @ %" PRIuz " / 0x%" PRIXz ": "
		"\"%" PRIbs "\"",
		PRAuz(i), PRAXz(i), PRAbs(4, sb->signature));
	i += sizeof(sb->signature);

	i += print_unknown32(prefix, indent, sb, &sb->reserved4);
	i += print_unknown32(prefix, indent, sb, &sb->reserved8);
	i += print_unknown32(prefix, indent, sb, &sb->reserved12);

	emit(prefix, indent, "Unknown @ %" PRIuz " / 0x%" PRIXz ":",
		PRAuz(i), PRAXz(i));
	print_data(prefix, indent + 1, sb->reserved16,
		sizeof(sb->reserved16));
	i += sizeof(sb->reserved16);

	i += print_le64_dechex("Self block index", prefix, indent, sb,
		&sb->self_block_index);

	emit(prefix, indent, "Unknown @ %" PRIuz " / 0x%" PRIXz ":",
		PRAuz(i), PRAXz(i));
	print_data(prefix, indent + 1, sb->reserved40,
		sizeof(sb->reserved40));
	i += sizeof(sb->reserved40);

	emit(prefix, indent, "GUID @ %" PRIuz " / 0x%" PRIXz ": %" PRIGUID,
		PRAuz(i), PRAXz(i), PRAGUID(sb->block_guid));
	i += sizeof(sb->block_guid);

	i += print_unknown64(prefix, indent, sb, &sb->reserved96);
	i += print_unknown64(prefix, indent, sb, &sb->reserved104);

	level_1_block_list_offset = le32_to_cpu(sb->reserved112);
	i += print_le32_dec("Offset of level 1 block list", prefix, indent, sb,
		&sb->reserved112);

	level_1_block_list_count = le32_to_cpu(sb->reserved116);
	i += print_le32_dec("Number of level 1 blocks", prefix, indent, sb,
		&sb->reserved116);

	self_reference_offset = le32_to_cpu(sb->reserved120);
	i += print_le32_dec("Offset of self reference", prefix, indent, sb,
		&sb->reserved120);

	self_reference_size = le32_to_cpu(sb->reserved124);
	i += print_le32_dec("Size of self reference", prefix, indent, sb,
		&sb->reserved124);

	if(sys_min(level_1_block_list_offset, self_reference_offset) > i) {
		print_data_with_base(prefix, indent, i, block_size,
			&block[i],
			sys_min(level_1_block_list_offset, self_reference_offset) -
			i);
	}

	/* TODO: Validate contents past first self reference element based on
	 * prior observations and fail if it deviates. This may be a description
	 * of a fragmented superblock, but we have not seen those yet so we
	 * don't quite know what to expect. */

	if(level_1_block_list_offset < self_reference_offset) {
		i = level_1_block_list_offset;
		i += parse_superblock_level1_block_list(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *block */
			block,
			/* u32 level_1_blocks_offset */
			level_1_block_list_offset,
			/* u32 level_1_blocks_count */
			level_1_block_list_count,
			/* u64 *out_primary_level1_block */
			out_primary_level1_block,
			/* u64 *out_secondary_level1_block */
			out_secondary_level1_block);
	}
	else {
		u32 total_size = 0;

		i = self_reference_offset;

		err = parse_node_reference_list_v3(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self reference",
			/* const u8 *block */
			block,
			/* size_t block_size */
			block_size,
			/* const u32 *node_reference_offsets */
			&self_reference_offset,
			/* u32 node_references_size */
			(self_reference_size > 48) ? 48 : self_reference_size,
			/* refs_node_block_queue_element
			 * **out_node_references */
			NULL,
			/* u32 *out_total_size */
			&total_size);
		if(err) {
			goto out;
		}

		i += total_size;
	}

	if(sys_max(level_1_block_list_offset, self_reference_offset) > i) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			sys_min(level_1_block_list_offset, self_reference_offset) -
			i);
	}

	if(level_1_block_list_offset < self_reference_offset) {
		u32 total_size = 0;

		i = self_reference_offset;

		err = parse_node_reference_list_v3(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self reference",
			/* const u8 *block */
			block,
			/* size_t block_size */
			block_size,
			/* const u32 *node_reference_offsets */
			&self_reference_offset,
			/* u32 node_references_size */
			(self_reference_size > 48) ? 48 : self_reference_size,
			/* refs_node_block_queue_element
			 * **out_node_references */
			NULL,
			/* u32 *out_total_size */
			&total_size);
		if(err) {
			goto out;
		}

		i += total_size;
	}
	else {
		i = level_1_block_list_offset;
		i += parse_superblock_level1_block_list(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent,
			/* const u8 *const block */
			block,
			/* u32 level_1_blocks_offset */
			level_1_block_list_offset,
			/* u32 level_1_blocks_count */
			level_1_block_list_count,
			/* u64 *out_primary_level1_block */
			out_primary_level1_block,
			/* u64 *out_secondary_level1_block */
			out_secondary_level1_block);
	}

	if(i < block_size) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			block_size - i);
	}
out:
	return err;
}

static int parse_level1_block_level2_node_reference_list(
		refs_node_crawl_context *const context,
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const block,
		const u32 block_size,
		const u32 node_reference_list_offset,
		u32 **const out_node_reference_list,
		u32 *const out_node_reference_list_count,
		u32 *const out_end_offset)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 offset = node_reference_list_offset;
	u32 node_reference_list_count;
	u64 node_reference_list_size = 0;
	u32 node_reference_list_inset = 0;
	u32 *node_reference_list = NULL;
	u32 i;

	node_reference_list_count = read_le32(&block[offset]);
	emit(prefix, indent, "Number of level 2 node references @ %" PRIuz " / "
		"0x%" PRIXz ": %" PRIu64 " / 0x%" PRIX64,
		PRAuz(node_reference_list_offset),
		PRAXz(node_reference_list_offset),
		PRAu64(node_reference_list_count),
		PRAX64(node_reference_list_count));
	offset += sizeof(le32);
	node_reference_list_size =
		((u64) node_reference_list_count) * sizeof(le32);
	if(node_reference_list_size > block_size - node_reference_list_offset) {
		sys_log_warning("Invalid node references list: Overflows end "
			"of block (%" PRIu64 " > %" PRIu32 ").",
			PRAu64(node_reference_list_size),
			PRAu32(block_size - node_reference_list_offset));
		*out_node_reference_list = NULL;
		*out_node_reference_list_count = 0;
		goto out;
	}

	if(REFS_VERSION_MIN(context->bs->version_major,
		context->bs->version_minor, 3, 14))
	{
		sys_log_debug("Insetting node references list by 5 elements on "
			"ReFS 3.14 and later.");
		/* Not sure what these 5 elements are in version 3.14,
		 * investigating is TODO. */
		node_reference_list_inset = 5 * sizeof(le32);
	}

	if(node_reference_list_inset) {
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
			node_reference_list_offset + sizeof(le32) * 2,
			block_size,
			&block[node_reference_list_offset + sizeof(le32) * 2],
			node_reference_list_inset - sizeof(le32));
		offset += node_reference_list_inset;
	}

	err = sys_malloc((size_t) node_reference_list_size,
		&node_reference_list);
	if(err) {
		sys_log_perror(err, "Error while allocating %" PRIu64 " bytes "
			"for node reference list",
			PRAu64(node_reference_list_size));
		goto out;
	}

	emit(prefix, indent, "Level 2 node reference list offsets:");
	for(i = 0; i < node_reference_list_count; ++i) {
		node_reference_list[i] = read_le32(&block[offset]);
		emit(prefix, indent + 1, "[%" PRIu32 "] @ %" PRIu32 " / "
			"0x%" PRIX32 ": %" PRIu32 " / 0x%" PRIX32,
			PRAu32(i),
			PRAu32(offset),
			PRAX32(offset),
			PRAu32(node_reference_list[i]),
			PRAX32(node_reference_list[i]));
		offset += sizeof(le32);
	}

	*out_node_reference_list = node_reference_list;
	*out_node_reference_list_count = node_reference_list_count;
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
		const u32 block_size,
		refs_node_block_queue_element **const
		out_level2_node_references,
		size_t *const out_level2_node_references_count)
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
	u32 self_reference_offset = 0 ;
	u32 self_reference_size = 0;
	u32 level2_node_reference_count = 0;
	u32 *level2_node_reference_offsets = NULL;
	u64 level2_node_reference_list_size = 0;
	u32 level2_node_reference_offsets_end_offset = 0;
	refs_node_block_queue_element *level2_node_references = NULL;

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
	self_reference_offset = read_le32(&header[0x38]);
	emit(prefix, indent, "Offset of self reference: %" PRIu64,
		PRAu64(self_reference_offset));
	self_reference_size = read_le32(&header[0x3C]);
	emit(prefix, indent, "Size of self reference: %" PRIu64,
		PRAu64(self_reference_size));
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

	err = parse_level1_block_level2_node_reference_list(
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
		/* u32 out_node_reference_list_offset */
		i,
		/* u32 **out_node_reference_list */
		&level2_node_reference_offsets,
		/* u32 *out_out_node_reference_list_count */
		&level2_node_reference_count,
		/* u32 *out_end_offset */
		&level2_node_reference_offsets_end_offset);
	if(err) {
		sys_log_perror(err, "Error while parsing level 2 node "
			"reference list");
		goto out;
	}

	i = level2_node_reference_offsets_end_offset;

	if(self_reference_offset > i) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			sys_min(self_reference_offset, block_size) - i);
	}

	i = self_reference_offset;

	/* TODO: Validate contents past first self reference element based on
	 * prior observations and fail if it deviates. This may be a description
	 * of a fragmented level 1 node, but we have not seen those yet so we
	 * don't quite know what to expect. */
	if(self_reference_offset >= block_size) {
		sys_log_warning("Self reference offset exceeds block size: "
			"%" PRIu32 " != %" PRIuz,
			PRAu32(self_reference_offset), PRAuz(block_size));
	}
	else if(is_v3) {
		u32 total_size = 0;

		err = parse_node_reference_list_v3(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self reference",
			/* const u8 *const block */
			block,
			/* size_t block_size */
			block_size,
			/* const u32 *node_reference_offsets */
			&self_reference_offset,
			/* u32 node_references_size */
			(self_reference_size > 48) ? 48 : self_reference_size,
			/* refs_node_block_queue_element
			 * **out_node_references */
			NULL,
			/* u32 *out_total_size */
			&total_size);
		if(err) {
			goto out;
		}

		i += total_size;
	}
	else {
		u32 total_size = 0;

		i = self_reference_offset;

		err = parse_node_reference_list_v1(
			/* refs_node_walk_visitor *visitor */
			visitor,
			/* const char *prefix */
			prefix,
			/* size_t indent */
			indent + 1,
			/* const char *list_name */
			"Self reference",
			/* const u8 *const block */
			block,
			/* size_t block_size */
			block_size,
			/* const u32 *node_reference_offsets */
			&self_reference_offset,
			/* u32 node_references_size */
			(self_reference_size > 24) ? 24 : self_reference_size,
			/* refs_node_block_queue_element
			 * **out_node_references */
			NULL,
			/* u32 *out_total_size */
			&total_size);
		if(err) {
			goto out;
		}

		i += total_size;
	}

	if(!level2_node_reference_offsets) {
		sys_log_warning("No level 2 node references!");
	}
	else if(level2_node_reference_offsets[0] < i) {
		sys_log_warning("First level 2 node reference offset precedes "
			"end of node reference offsets list: %" PRIu32 " < "
			"%" PRIu32,
			PRAu32(level2_node_reference_offsets[0]), PRAu32(i));
	}
	else {
		if(level2_node_reference_offsets[0] > i) {
			print_data_with_base(prefix, 0, i, block_size,
				&block[i],
				sys_min(level2_node_reference_offsets[0],
				block_size) - i);
		}

		level2_node_reference_list_size =
			level2_node_reference_count *
			(size_t) (is_v3 ? 48 : 24);

		i = level2_node_reference_offsets[0];
		if(is_v3) {
			u32 total_size = 0;

			err = parse_node_reference_list_v3(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent + 1,
				/* const char *list_name */
				"Level 2 node references",
				/* const u8 *const block */
				block,
				/* size_t block_size */
				block_size,
				/* const u32 *node_reference_offsets */
				level2_node_reference_offsets,
				/* size_t node_references_size */
				level2_node_reference_list_size,
				/* refs_node_block_queue_element
				 * **out_node_references */
				&level2_node_references,
				/* u32 *out_total_size */
				&total_size);
			if(err) {
				goto out;
			}

			i += total_size;
		}
		else {
			u32 total_size = 0;

			i = self_reference_offset;

			err = parse_node_reference_list_v1(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent + 1,
				/* const char *list_name */
				"Level 2 node references",
				/* const u8 *const block */
				block,
				/* size_t block_size */
				block_size,
				/* const u32 *node_reference_offsets */
				level2_node_reference_offsets,
				/* u32 node_references_size */
				level2_node_reference_list_size,
				/* refs_node_block_queue_element
				 * **out_node_references */
				&level2_node_references,
				/* u32 *out_total_size */
				&total_size);
			if(err) {
				goto out;
			}

			i += total_size;
		}
	}

	if(i < block_size) {
		print_data_with_base(prefix, indent, i, block_size, &block[i],
			block_size - i);
	}

	*out_level2_node_references_count = level2_node_reference_count;
	*out_level2_node_references = level2_node_references;
out:
	if(level2_node_reference_offsets) {
		sys_free(&level2_node_reference_offsets);
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
		const u32 entry_index,
		const u32 num_entries)
{
	static const char *const prefix = "\t";
	static const size_t indent = 1;

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;

	emit_entry_header(prefix, 0, "Entry", entry_index, num_entries,
		entry_offset, "regular entry");

	emit(prefix, indent, "Size: %" PRIu64,
		PRAu64(entry_size));

	print_data_with_base(prefix, indent, 0x0, 0, &entry[0x0],
		entry_size - 0x0);

	return err;
}

static int parse_index_value(
		refs_node_walk_visitor *const visitor,
		const char *const prefix,
		const size_t indent,
		const sys_bool is_v3,
		const u8 *const value,
		const u16 value_offset,
		const u16 value_size,
		refs_node_block_queue *const block_queue)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
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
		parse_node_reference(
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

		if(block_queue) {
			/* Add the next level block number parsed from the value
			 * to the block queue. */
			const le64 *const value_le64 = (const le64*) &value[j];
			const u64 next_level_block_numbers[4] = {
				read_le64(&value_le64[j]),
				is_v3 ? read_le64(&value_le64[j + 1]) : 0,
				is_v3 ? read_le64(&value_le64[j + 2]) : 0,
				is_v3 ? read_le64(&value_le64[j + 3]) : 0
			};
			const u64 flags =
				read_le64(&value_le64[j + (is_v3 ? 4 : 1)]);
			const u64 checksum =
				read_le64(&value_le64[j + (is_v3 ? 5 : 2)]);

			sys_log_debug("next_level_block_numbers[0]: %" PRIu64,
				PRAu64(next_level_block_numbers[0]));
			if(next_level_block_numbers[0]) {
				err = refs_node_block_queue_add(
					/* refs_node_block_queue *block_queue */
					block_queue,
					/* const u64 block_numbers[4] */
					next_level_block_numbers,
					/* u64 flags */
					flags,
					/* u64 checksum */
					checksum);
				if(err) {
					goto out;
				}
			}
			else {
				sys_log_warning("No next level block number "
					"found for index node entry.");
			}
		}

		j += (is_v3 ? 0x30 : 0x18);
	}

	if(value_size > j) {
		print_data_with_base(prefix, indent, j, value_size,
			&value[j], value_size - j);
	}
out:
	return err;
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
		(crawl_context->bs->version_major >= 2) ? SYS_TRUE : SYS_FALSE;
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
		const u32 num_entries,
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
		refs_node_block_queue *const block_queue)
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
			entry_index,
			/* u32 num_entries */
			num_entries);
		goto out;
	}

	emit_entry_header(prefix, indent, "Entry", entry_index, num_entries,
		entry_offset, "regular entry");

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
		err = parse_index_value(
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
			/* refs_node_block_queue *block_queue */
			block_queue);
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
		refs_node_block_queue *const block_queue,
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

	sys_log_trace("%s(crawl_context=%p, visitor=%p, indent=%" PRIuz ", "
		"cluster_number=%" PRIu64 ", block_number=%" PRIu64 ", "
		"block_queue_index=%" PRIu64 ", level=%" PRIu8 ", block=%p, "
		"block_size=%" PRIu32 ", block_queue=%p, "
		"add_subnodes_in_offsets_order=%d, context=%p, parse_key=%p, "
		"parse_leaf_value=%p, leaf_entry_handler=%p): Entering...",
		__FUNCTION__, crawl_context, visitor, PRAuz(indent),
		PRAu64(cluster_number), PRAu64(block_number),
		PRAu64(block_queue_index), PRAu8(level), block,
		PRAu32(block_size), block_queue, add_subnodes_in_offsets_order,
		context, parse_key, parse_leaf_value, leaf_entry_handler);

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

	emit(prefix, indent, "Node header @ %" PRIu32 " / 0x%" PRIX32 ":",
		PRAu32(i), PRAX32(i));

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

	emit(prefix, indent, "Node allocation entry @ %" PRIu32 " / "
		"0x%" PRIX32 ":",
		PRAu32(i), PRAX32(i));

	err = parse_block_allocation_entry(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const char *prefix */
		prefix,
		/* size_t indent */
		indent + 1,
		/* sys_bool is_v3 */
		(crawl_context->bs->version_major >= 3) ? SYS_TRUE : SYS_FALSE,
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
			/* u32 num_entries */
			values_count,
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
			/* refs_node_block_queue *block_queue */
			(!is_index_node || !add_subnodes_in_offsets_order) ?
			NULL : block_queue);
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
				goto out;
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
				smallest_matching_entryno,
				/* u32 num_entries */
				values_count,
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
				/* refs_node_block_queue *block_queue */
				(!is_index_node ||
				add_subnodes_in_offsets_order) ? NULL :
				block_queue);
			if(err) {
				goto out;
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

	sys_log_trace("%s(crawl_context=%p, visitor=%p, indent=%" PRIuz ", "
		"cluster_number=%" PRIu64 ", block_number=%" PRIu64 ", "
		"block_queue_index=%" PRIu64 ", level=%" PRIu8 ", block=%p, "
		"block_size=%" PRIu32 ", block_queue=%p, "
		"add_subnodes_in_offsets_order=%d, context=%p, parse_key=%p, "
		"parse_leaf_value=%p, leaf_entry_handler=%p): Leaving.",
		__FUNCTION__, crawl_context, visitor, PRAuz(indent),
		PRAu64(cluster_number), PRAu64(block_number),
		PRAu64(block_queue_index), PRAu8(level), block,
		PRAu32(block_size), block_queue, add_subnodes_in_offsets_order,
		context, parse_key, parse_leaf_value, leaf_entry_handler);

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
	u64 object_id;
	refs_node_block_queue *level3_block_queue;
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
	u64 block_numbers[4] = { 0, 0, 0, 0 };
	u64 flags = 0;
	u64 checksum = 0;

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
		block_numbers[0] = read_le64(&value[i]);
		if(is_v3) {
			block_numbers[1] =
				read_le64(&value[i + 1 * sizeof(le64)]);
			block_numbers[2] =
				read_le64(&value[i + 2 * sizeof(le64)]);
			block_numbers[3] =
				read_le64(&value[i + 3 * sizeof(le64)]);
			flags = read_le64(&value[i + 4 * sizeof(le64)]);
			checksum = read_le64(&value[i + 5 * sizeof(le64)]);
		}
		else {
			flags = read_le64(&value[i + 1 * sizeof(le64)]);
			checksum = read_le64(&value[i + 2 * sizeof(le64)]);
		}

		parse_node_reference(
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

			if(object_id && context->object_id == object_id) {
				err = refs_node_block_queue_add(
					/* refs_node_block_queue *block_queue */
					context->level3_block_queue,
					/* const u64 block_numbers[4] */
					block_numbers,
					/* u64 flags */
					flags,
					/* u64 checksum */
					checksum);
			}
		}
		else if(context->level3_block_queue) {
			err = refs_node_block_queue_add(
				/* refs_node_block_queue *block_queue */
				context->level3_block_queue,
				/* const u64 block_numbers[4] */
				block_numbers,
				/* u64 flags */
				flags,
				/* u64 checksum */
				checksum);
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
		refs_node_crawl_context *const crawl_context,
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
	const sys_bool is_v3plus =
		(crawl_context->bs->version_major >= 3) ? SYS_TRUE : SYS_FALSE;

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
	if(!is_v3plus) {
		print_le64_dechex("Block range start", prefix, indent, value,
			&value[0x28]);
		if(out_block_range_start) {
			*out_block_range_start = read_le64(&value[0x28]);
		}

		print_le64_dechex("Block range length", prefix, indent, value,
			&value[0x30]);
		if(out_block_range_length) {
			*out_block_range_length = read_le64(&value[0x30]);
		}
	}
	else {
		print_unknown64(prefix, indent, value, &value[0x28]);
		print_unknown32(prefix, indent, value, &value[0x30]);
	}
	print_unknown32(prefix, indent, value, &value[0x34]);

	i = 0x40;

	if(value_size >= 0x50) {
		print_unknown64(prefix, indent, value, &value[0x40]);
		print_unknown32(prefix, indent, value, &value[0x48]);
		print_unknown32(prefix, indent, value, &value[0x4C]);

		i = 0x50;

		if(is_v3plus && value_size - i > 0x10) {
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
	block_range *const range = (block_range*) context;

	int err = 0;

	(void) object_id;
	(void) key;
	(void) key_offset;
	(void) key_size;
	(void) entry_offset;

	parse_level2_block_0xB_0xC_table_leaf_value(
		/* refs_node_crawl_context *crawl_context */
		crawl_context,
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
	refs_block_map *const mappings = (refs_block_map*) context;

	int err = 0;
	block_range leaf_range;

	(void) object_id;
	(void) key;
	(void) key_offset;
	(void) key_size;
	(void) entry_offset;

	memset(&leaf_range, 0, sizeof(leaf_range));

	parse_level2_block_0xB_0xC_table_leaf_value(
		/* refs_node_crawl_context *crawl_context */
		crawl_context,
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
		const u32 entry_index,
		const u32 num_entries)
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

	emit_entry_header(prefix, indent, "Entry", entry_index, num_entries,
		entry_offset, "regular entry");

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
		const u32 entry_index,
		const u32 num_entries)
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

	emit_entry_header(prefix, indent - 1, "Entry", entry_index, num_entries,
		entry_offset, "regular entry");

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
		const u32 entry_index,
		const u32 num_entries)
{
	static const char *const prefix = "\t";

	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;

	emit_entry_header(prefix, indent, "Entry", entry_index, num_entries,
		entry_offset, "regular entry");

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
		(crawl_context->bs->version_major >= 2) ? SYS_TRUE : SYS_FALSE;

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
		const u64 *const object_id_mapping,
		refs_node_block_queue *const level2_queue,
		refs_node_block_queue *const level3_queue)
{
	int err = 0;
	sys_bool is_valid = SYS_FALSE;
	sys_bool is_v3 = SYS_FALSE;
	u64 object_id = 0;
	level2_0x2_leaf_parse_context context;

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

	if(object_id_mapping) {
		context.is_mapping = SYS_TRUE;
		context.object_id = *object_id_mapping;
	}
	else {
		context.is_mapping = SYS_FALSE;
	}

	context.level3_block_queue = level3_queue;

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
		/* refs_node_block_queue *block_queue */
		level2_queue,
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
		size_t i = 0;
		refs_node_block_queue_element *cur_element = NULL;

		sys_log_debug("Level 2 block queue after processing block "
			"(%" PRIuz " elements):",
			PRAuz(level2_queue->block_queue_length));

		cur_element = level2_queue->queue;
		while(cur_element) {
			sys_log_debug("\t[%" PRIuz "]: %" PRIu64,
				PRAuz(i),
				PRAu64(cur_element->block_numbers[0]));
			++i;
			cur_element = cur_element->next;
		}
	}

	if(level3_queue) {
		size_t i = 0;
		refs_node_block_queue_element *cur_element = NULL;

		sys_log_debug("Level 3 block queue after processing block "
			"(%" PRIuz " elements):",
			PRAuz(level3_queue->block_queue_length));
		while(cur_element) {
			sys_log_debug("\t[%" PRIuz "]: %" PRIu64,
				PRAuz(i),
				PRAu64(cur_element->block_numbers[0]));
			++i;
			cur_element = cur_element->next;
		}
	}
out:
	return err;
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
		const u16 key_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;

	(void) key_size;

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
		const u16 key_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	size_t i = 0;

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
		const u16 key_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	size_t i = 0;

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
		const u32 entry_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;

	(void) crawl_context;

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
	(void) context;

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
			key_size);
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
			key_size);
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
			key_size);
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
			entry_size);
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
	const sys_bool is_v35plus =
		REFS_VERSION_MIN(crawl_context->bs->version_major,
		crawl_context->bs->version_minor, 3, 5);
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 j_start = *jp;
	const u16 key_end = j_start + key_size;

	u16 j = j_start;

	/* v1/v3: 0x10 */
	if(j + 8 <= key_end) {
		j += print_unknown64(prefix, indent, key, &key[j]);
	}
	/* v3: 0x18 */
	if(is_v35plus && j + 2 <= key_end) {
		j += print_unknown16(prefix, indent, key, &key[j]);
	}
	/* v3: 0x1A */
	if(is_v35plus && j + 2 <= key_end) {
		j += print_unknown16(prefix, indent, key, &key[j]);
	}
	/* v1: 0x18 v3: 0x1C */
	if(j + 2 <= key_end) {
		j += print_le16_hex("Attribute type (unnamed $DATA)", prefix,
			indent, key, &key[j]);
	}
	/* v1: 0x1A */
	if(!is_v35plus && j + 2 <= key_end) {
		j += print_unknown16(prefix, indent, key, &key[j]);
	}
	/* v1: 0x1C */
	if(!is_v35plus && j + 2 <= key_end) {
		j += print_unknown16(prefix, indent, key, &key[j]);
	}
	/* v1/v3: 0x1E */
	if(j + 2 <= key_end) {
		j += print_unknown16(prefix, indent, key, &key[j]);
	}
	/* v3: 0x20 */
	if(is_v35plus && j + 8 <= key_end) {
		j += print_unknown64(prefix, indent, key, &key[j]);
	}
	/* v3: 0x28 */
	if(is_v35plus && j + 8 <= key_end) {
		j += print_unknown64(prefix, indent, key, &key[j]);
	}
	/* v3: 0x30 */
	if(is_v35plus && j + 8 <= key_end) {
		j += print_unknown64(prefix, indent, key, &key[j]);
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
		(crawl_context->bs->version_major >= 2) ? SYS_TRUE : SYS_FALSE;
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

	if(attribute_type == 0x0080) {
		/* Data stream. */

		sys_log_debug("Parsing data stream attribute key.");

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
	}
	else if(attribute_type == 0x00E0) {
		/* This attribute type appears to be inline data for the
		 * EA stream. Likely same format as the above. */
		sys_log_debug("Parsing $EA attribute key.");

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
		/* This attribute type contains data about alternate data
		 * streams. */

		sys_log_debug("Parsing named stream key.");

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
	}
	else if(key_offset == 0x0010 && key_size == 0x50) {
		sys_log_debug("Parsing named stream extent key.");

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
	}
	else {
		sys_log_debug("Parsing unknown key.");
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
		(crawl_context->bs->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	const sys_bool is_v35plus =
		REFS_VERSION_MIN(crawl_context->bs->version_major,
		crawl_context->bs->version_minor, 3, 5);
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
	if(!is_v35plus && value_end - j >= 8) {
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
	if(is_v35plus && value_end - j >= 4) {
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
	if(is_v35plus && value_end - j >= 4) {
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
		u64 block_count = 0;

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
		(crawl_context->bs->version_major >= 2) ? SYS_TRUE : SYS_FALSE;
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
		const u64 first_logical_block =
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
		(crawl_context->bs->version_major >= 2) ? SYS_TRUE : SYS_FALSE;
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
		err = refs_node_get_node_data(
			/* refs_node_crawl_context *crawl_context */
			crawl_context,
			/* size_t node_size */
			crawl_context->block_size,
			/* u64 logical_blocks[4] */
			logical_blocks,
			/* u64 physical_blocks[4] */
			physical_blocks,
			/* u8 **out_data */
			&block);
		if(err) {
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
			/* refs_node_block_queue *block_queue */
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
		if(err == -1) {
			goto out;
		}
		else if(err) {
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
		(crawl_context->bs->version_major >= 2) ? SYS_TRUE : SYS_FALSE;
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 attribute_type_offset =
		REFS_VERSION_MIN(crawl_context->bs->version_major,
		crawl_context->bs->version_minor, 3, 5) ? 0x0C : 0x08;
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

	if(attribute_type == 0x0080) {
		/* Data stream. */
		u16 data_stream_type;

		sys_log_debug("Parsing data stream value.");

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
	}
	else if(attribute_type == 0x00E0) {
		/* This attribute type appears to be inline data for the
		 * EA stream. Likely same format as the above. */
		sys_log_debug("Parsing $EA attribute value.");

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

		sys_log_debug("Parsing named stream value.");

		/* This attribute type contains data about alternate data
		 * streams. */

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
		}

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
	}
	else if(key_offset == 0x0010 && key_size == 0x50) {
		const u64 stream_id = read_le64(&key[0x30]);

		sys_log_debug("Parsing named stream extent value.");

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
	}
	else {
		sys_log_debug("Parsing unknown value.");
	}
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
		const u16 attribute_size)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;
	const u16 remaining_in_attribute =
		sys_min(remaining_in_value, attribute_size);

	u16 j = 0;

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
		const u16 remaining_in_attribute,
		const u8 *const attribute,
		u16 *const jp)
{
	refs_node_print_visitor *const print_visitor =
		visitor ? &visitor->print_visitor : NULL;

	int err = 0;
	u32 reparse_tag = 0;
	u16 reparse_data_size = 0;
	u16 j = *jp;

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
			u16 name_size = 0;
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
		(crawl_context->bs->version_major >= 2) ? SYS_TRUE : SYS_FALSE;
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
	u16 attribute_number = 0;
	u32 attributes_offset_base = 0;
	size_t remaining_in_value = 0;
	u32 number_of_attributes = 0;
	u32 value_offsets_start = 0;
	u32 value_offsets_end = 0;
	u16 attributes_start = 0;
	u16 offsets_start = 0;
	u16 j = 0;
	char *cstr = NULL;

	(void) context;

	sys_log_trace("%s(crawl_context=%p, visitor=%p, prefix=%s%s%s, "
		"indent=%" PRIuz ", parent_node_object_id=%" PRIu64 ", "
		"entry_offset=%" PRIu16 ", key=%p, key_size=%" PRIu16 ", "
		"value=%p, value_offset=%" PRIu16 ", value_size=%" PRIu16 ", "
		"context=%p): Entering...",
		__FUNCTION__,
		crawl_context,
		visitor,
		prefix ? "\"" : "", prefix ? prefix : "NULL",
		prefix ? "\"" : "",
		PRAuz(indent),
		PRAu64(parent_node_object_id),
		PRAu16(entry_offset),
		key,
		PRAu16(key_size),
		value,
		PRAu16(value_offset),
		PRAu16(value_size),
		context);

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

	if(attribute_size < value_size && i < attribute_size) {
		print_data_with_base(prefix, indent + 1, i, attribute_size,
			&value[i], attribute_size - i);
		i += attribute_size - i;
	}

	attributes_offset_base = i;
	remaining_in_value = value_size - i;
	if(remaining_in_value < 0x18) {
		goto out;
	}

	emit(prefix, indent, "Attribute header @ %" PRIuz " / 0x%" PRIXz ":",
		PRAuz(i), PRAXz(i));

	/* After the standard information "fixed" info follows a node allocation
	 * entry, as if there's an embedded node within this value, where all
	 * the attributes are located. However the block header and node header
	 * are not present. */
	attribute_size = read_le16(&value[i]);
	if(attribute_size < 0x18 || remaining_in_value < attribute_size) {
		goto out;
	}

	err = parse_block_allocation_entry(
		/* refs_node_walk_visitor *visitor */
		visitor,
		/* const char *prefix */
		prefix,
		/* size_t indent */
		indent + 1,
		/* sys_bool is_v3 */
		(crawl_context->bs->version_major >= 3) ? SYS_TRUE : SYS_FALSE,
		/* const u8 *entry */
		&value[i],
		/* u32 entry_size */
		attribute_size,
		/* u32 entry_offset */
		i,
		/* u32 *out_flags */
		NULL,
		/* u32 *out_value_offsets_start */
		&value_offsets_start,
		/* u32 *out_value_offsets_end */
		&value_offsets_end,
		/* u32 *out_value_count */
		&number_of_attributes);
	if(err) {
		goto out;
	}

	/* The value offsets start/end values are counted from the start of the
	 * allocation entry, so add 'i' to the offsets before incrementing to
	 * get an absolute byte offset from the start of the value data. */
	if(value_offsets_end < value_offsets_start ||
		value_offsets_start > 0xFFFFFFFFUL - i ||
		value_offsets_end > 0xFFFFFFFFUL - i)
	{
		/* Overflow guard. */
		sys_log_warning("Invalid start/end offsets for attribute "
			"offsets array: %" PRIu32 " / %" PRIu32 "(%s)",
			PRAu32(value_offsets_start), PRAu32(value_offsets_end),
			(value_offsets_end < value_offsets_start) ?
			"invalid start/end order" : "would overflow type");
		goto out;
	}

	value_offsets_start += i;
	value_offsets_end += i;

	if(number_of_attributes > value_size) {
		sys_log_warning("Inconsistent number of attributes: "
			"%" PRIu32 " > %" PRIu16 " (size of value)",
			PRAu32(number_of_attributes),
			PRAu16(value_size));
		number_of_attributes = 0;
	}
	else if(value_offsets_start >= value_size ||
		value_offsets_end > value_size ||
		value_offsets_end - value_offsets_start !=
		number_of_attributes * 4)
	{
		sys_log_warning("Invalid start/end offsets for attribute "
			"offsets array: %" PRIu32 " / %" PRIu32 "(%s)",
			PRAu32(value_offsets_start), PRAu32(value_offsets_end),
			(value_offsets_start >= value_size ||
			value_offsets_end > value_size) ? "overflows value" :
			"doesn't match the number of attributes");
		goto out;
	}

	i += (u16) sys_min(attribute_size, remaining_in_value);
	attributes_start = i;

	while(attribute_number < number_of_attributes) {
		const size_t offset_in_value = i;
		const le16 *const value_offsets =
			(const le16*) &value[value_offsets_start];

		u16 remaining_in_attribute = 0;
		u16 attr_key_offset = 0;
		u16 attr_key_size = 0;
		u16 attr_value_offset = 0;
		u16 attr_value_size = 0;
		u16 attribute_type_offset = 0;
		u16 key_end = 0 ;
		u16 attribute_type = 0;
		const u8 *attribute = NULL;
		u16 attribute_index = 0;

		if(print_visitor && print_visitor->print_message) {
			/* We iterate in descending order when printing. Search
			 * for the next attribute offset in the index. */
			u16 next_offset = value_offsets_start;

			if(i + 2 > value_size) {
				break;
			}

			for(j = 0; j < number_of_attributes; ++j) {
				const u16 cur_value =
					read_le16(&value_offsets[j * 2]);
				const u32 cur_offset =
					attributes_offset_base + cur_value;

				if(cur_offset < attributes_start ||
					cur_offset + 2 > value_size)
				{
					sys_log_warning("Invalid offset for "
						"attribute %" PRIu16 ": "
						"%" PRIu32,
						PRAu16(j), PRAu32(cur_offset));
					break;
				}

				if(cur_offset >= i && cur_offset < next_offset)
				{
					next_offset = (u16) cur_offset;
					attribute_index = j;
				}
			}

			if(next_offset >= value_offsets_start) {
				sys_log_warning("Could not find next offset "
					"following: %" PRIu32, PRAu32(i));
				break;
			}

			if(i < next_offset) {
				print_data_with_base(prefix, indent, i,
					value_size, &value[i],
					next_offset - i);
				i = next_offset;
			}

			attribute = &value[i];
		}
		else {
			/* When not printing, we iterate in the order that the
			 * attributes are listed in the attrbute offsets to have
			 * the attributes returned to the caller in the right
			 * order. */
			const u16 attribute_offset_value =
				read_le16(&value_offsets[attribute_number * 2]);
			const u32 attribute_offset =
				attributes_offset_base + attribute_offset_value;

			if(attribute_offset < attributes_start ||
				attribute_offset + 2 > value_size)
			{
				sys_log_warning("Invalid offset for attribute "
					"%" PRIu16 ": %" PRIu32,
					PRAu16(attribute_number),
					PRAu32(attribute_offset));
				break;
			}

			attribute = &value[attribute_offset];
			attribute_index = attribute_number;
		}

		attribute_size = 0;
		remaining_in_value = value_size - offset_in_value;
		if(remaining_in_value >= 2) {
			attribute_size = read_le16(&attribute[0]);
		}

		if(!attribute_size) {
			break;
		}

		remaining_in_attribute =
			(u16) sys_min(attribute_size, remaining_in_value);

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

		attribute_type_offset =
			REFS_VERSION_MIN(crawl_context->bs->version_major,
			crawl_context->bs->version_minor, 3, 5) ? 0x0C : 0x08;
		key_end =
			(u16) sys_min(attr_key_offset + (u32) attr_key_size,
			remaining_in_attribute);

		if(attr_key_offset + attribute_type_offset + 2 <= key_end) {
			attribute_type =
				read_le16(&attribute[attr_key_offset +
				attribute_type_offset]);
		}

		emit(prefix, indent, "Attribute %" PRIu16 " / %" PRIu32 " @ "
			"%" PRIuz " / 0x%" PRIXz ":",
			PRAu16(attribute_index + 1),
			PRAu32(number_of_attributes),
			PRAuz(offset_in_value),
			PRAXz(offset_in_value));

		++attribute_number;

		j = 0;

		if(remaining_in_value < 8) {
			break;
		}

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
			attribute_size);

		if(attribute_type == 0x0080) {
			u16 data_stream_type;

			sys_log_debug("Parsing data stream attribute.");

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
		}
		else if(attribute_type == 0x00E0) {
			/* This attribute type appears to be inline data for the
			 * EA stream. Likely same format as the above. */

			sys_log_debug("Parsing $EA attribute.");

			emit(prefix, indent + 1, "Key @ %" PRIuz " / "
				"0x%" PRIXz " (size: %" PRIuz " / "
				"0x%" PRIXz "):",
				PRAuz(j), PRAXz(j), PRAuz(attr_key_size),
				PRAXz(attr_key_size));
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
		}
		else if(attribute_type == 0x00B0) {
			size_t cstr_length = 0;

			sys_log_debug("Parsing named stream attribute.");

			/* This attribute type contains data relating to
			 * alternate data streams. */

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
		}
		else if(attr_key_offset == 0x0010 && attr_key_size == 0x50) {
			u64 stream_id = 0;

			sys_log_debug("Parsing named stream extent attribute.");

			emit(prefix, indent + 1, "Key @ %" PRIuz " / "
				"0x%" PRIXz " (size: %" PRIuz " / "
				"0x%" PRIXz "):",
				PRAuz(j), PRAXz(j), PRAuz(attr_key_size),
				PRAXz(attr_key_size));

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
		}
		else if(attr_key_offset == 0x0010 && attribute_type == 0x00C0) {
			err = parse_reparse_point_attribute(
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* const char *prefix */
				prefix,
				/* size_t indent */
				indent,
				/* u16 remaining_in_attribute */
				remaining_in_attribute,
				/* const u8 *attribute */
				attribute,
				/* u16 *jp */
				&j);
			if(err) {
				goto out;
			}
		}
		else if(attr_key_offset == 0x10 && attr_key_size == 0x00) {
			/* This appears to contain an independently allocated
			 * (non-resident) attribute list. */

			sys_log_debug("Parsing non-resident attribute list "
				"entry.");

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
		}
		else {
			sys_log_debug("Parsing unknown attribute.");
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

	if(value_offsets_start && value_offsets_start < value_size) {
		offsets_start = value_offsets_start;
	}
	else {
		offsets_start = value_size - number_of_attributes * 4;
	}

	if(i < offsets_start) {
		print_data_with_base(prefix, indent, i, value_size, &value[i],
			offsets_start - i);
		i = offsets_start;
	}

	for(j = 0; j < number_of_attributes; ++j) {
		if(i + 4 > value_size) {
			break;
		}

		emit(prefix, indent, "Index of attribute %" PRIu16 " @ "
			"%" PRIuz " / 0x%" PRIXz ": %" PRIu16 " (absolute: "
			"%" PRIu32 ", flags: 0x%" PRIX16 ")",
			PRAu16(j + 1), PRAuz(i), PRAXz(i),
			PRAu16(read_le16(&value[i])),
			PRAu32(attributes_offset_base + read_le16(&value[i])),
			PRAX16(read_le16(&value[i + 2])));
		i += 4;
	}
out:
	if(!err && i < value_size) {
		print_data_with_base(prefix, indent, i, value_size, &value[i],
			value_size - i);
		i = value_size;
	}

	if(cstr) {
		sys_free(&cstr);
	}

	sys_log_trace("%s(crawl_context=%p, visitor=%p, prefix=%s%s%s, "
		"indent=%" PRIuz ", parent_node_object_id=%" PRIu64 ", "
		"entry_offset=%" PRIu16 ", key=%p, key_size=%" PRIu16 ", "
		"value=%p, value_offset=%" PRIu16 ", value_size=%" PRIu16 ", "
		"context=%p): Leaving",
		__FUNCTION__,
		crawl_context,
		visitor,
		prefix ? "\"" : "", prefix ? prefix : "NULL",
		prefix ? "\"" : "",
		PRAuz(indent),
		PRAu64(parent_node_object_id),
		PRAu16(entry_offset),
		key,
		PRAu16(key_size),
		value,
		PRAu16(value_offset),
		PRAu16(value_size),
		context);

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
		(crawl_context->bs->version_major >= 2) ? SYS_TRUE : SYS_FALSE;
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

	sys_log_trace("%s(crawl_context=%p, visitor=%p, prefix=%s%s%s, "
		"indent=%" PRIuz ", parent_node_object_id=%" PRIu64 ", "
		"entry_offset=%" PRIu16 ", key=%p, key_size=%" PRIu16 ", "
		"value=%p, value_offset=%" PRIu16 ", value_size=%" PRIu16 ", "
		"context=%p): Entering...",
		__FUNCTION__,
		crawl_context,
		visitor,
		prefix ? "\"" : "", prefix ? prefix : "NULL",
		prefix ? "\"" : "",
		PRAuz(indent),
		PRAu64(parent_node_object_id),
		PRAu16(entry_offset),
		key,
		PRAu16(key_size),
		value,
		PRAu16(value_offset),
		PRAu16(value_size),
		context);

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
	sys_log_trace("%s(crawl_context=%p, visitor=%p, prefix=%s%s%s, "
		"indent=%" PRIuz ", parent_node_object_id=%" PRIu64 ", "
		"entry_offset=%" PRIu16 ", key=%p, key_size=%" PRIu16 ", "
		"value=%p, value_offset=%" PRIu16 ", value_size=%" PRIu16 ", "
		"context=%p): Leaving.",
		__FUNCTION__,
		crawl_context,
		visitor,
		prefix ? "\"" : "", prefix ? prefix : "NULL",
		prefix ? "\"" : "",
		PRAuz(indent),
		PRAu64(parent_node_object_id),
		PRAu16(entry_offset),
		key,
		PRAu16(key_size),
		value,
		PRAu16(value_offset),
		PRAu16(value_size),
		context);

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
		refs_node_block_queue *const level3_queue)
{
	int err = 0;

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
		/* refs_node_block_queue *block_queue */
		level3_queue,
		/* sys_bool add_subnodes_in_offsets_order */
		SYS_TRUE,
		/* void *context */
		NULL,
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
		refs_node_cache **const node_cachep,
		const u64 *const start_node,
		const u64 *const object_id)
{
	const sys_bool is_v3 = (bs->version_major >= 2) ? SYS_TRUE : SYS_FALSE;

	refs_node_print_visitor *const print_visitor =
		(visitor && visitor->print_visitor.print_message) ?
		&visitor->print_visitor : NULL;

	int err = 0;
	u64 cluster_size_64 = 0;
	u32 cluster_size = 0;
	u32 block_size = 0;
	u32 block_index_unit = 0;
	refs_node_cache *node_cache = NULL;
	refs_node_crawl_context crawl_context;
	u8 *padding = NULL;
	u8 *block = NULL;
	refs_block_map *mappings = NULL;
	u64 primary_level1_block = 0;
	u64 secondary_level1_block = 0;
	refs_node_block_queue_element *primary_level2_blocks = NULL;
	size_t primary_level2_blocks_count = 0;
	refs_node_block_queue_element *secondary_level2_blocks = NULL;
	size_t secondary_level2_blocks_count = 0;
	refs_node_block_queue level2_queue;
	refs_node_block_queue level3_queue;
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

	if(node_cachep) {
		if(!*node_cachep) {
			err = refs_node_cache_create(
				/* size_t max_node_count */
				128,
				/* refs_node_cache **const out_cache */
				&node_cache);
			if(err) {
				sys_log_perror(err, "Error creating node "
					"cache");
				goto out;
			}

			*node_cachep = node_cache;
		}
		else {
			node_cache = *node_cachep;
		}
	}

	crawl_context = refs_node_crawl_context_init(
		/* sys_device *dev */
		dev,
		/* REFS_BOOT_SECTOR *bs */
		bs,
		/* refs_block_map *block_map */
		NULL,
		/* refs_node_cache *node_cache */
		node_cache,
		/* u32 cluster_size */
		cluster_size,
		/* u32 block_size */
		block_size,
		/* u32 block_index_unit */
		block_index_unit);

	if(print_visitor && print_visitor->verbose) {
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

	err = sys_malloc(
		(block_index_unit > block_size) ? block_index_unit : block_size,
		&block);
	if(err) {
		sys_log_perror(err, "Error while allocating %" PRIu32 " bytes "
			"for metadata block",
			PRAu32((block_index_unit > block_size) ?
			block_index_unit : block_size));
		goto out;
	}

	if(!(sb && *sb)) {
		u64 logical_block_numbers[4] = { 30, 31, 32, 33 };
		u64 physical_block_numbers[4] = {
			logical_block_numbers[0], 
			logical_block_numbers[1], 
			logical_block_numbers[2], 
			logical_block_numbers[3] 
		};

		err = refs_node_get_node_data(
			/* refs_node_crawl_context *crawl_context */
			&crawl_context,
			/* size_t node_size */
			block_size,
			/* u64 logical_blocks[4] */
			logical_block_numbers,
			/* u64 physical_blocks[4] */
			physical_block_numbers,
			/* u8 **out_data */
			&block);
		if(err) {
			goto out;
		}
	}

	emit("", 0, "Superblock (physical block %" PRIu64 " / 0x%" PRIX64 "):",
		PRAu64(30), PRAX64(30));

	if(!is_v3) {
		err = parse_superblock_v1(
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
		err = parse_superblock_v3(
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
	if(err) {
		sys_log_perror(err, "Error while parsing superblock");
		goto out;
	}

	if(!primary_level1_block || !secondary_level1_block) {
		sys_log_error("Level 1 block references are invalid.");
		err = EIO;
		goto out;
	}

	if(primary_level1_block) {
		if(!(primary_level1_node && *primary_level1_node)) {
			u64 logical_block_numbers[4] = {
				primary_level1_block,
				primary_level1_block + 1,
				primary_level1_block + 2,
				primary_level1_block + 3
			};
			u64 physical_block_numbers[4] = {
				logical_block_numbers[0], 
				logical_block_numbers[1], 
				logical_block_numbers[2], 
				logical_block_numbers[3] 
			};

			err = refs_node_get_node_data(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* size_t node_size */
				block_size,
				/* u64 logical_blocks[4] */
				logical_block_numbers,
				/* u64 physical_blocks[4] */
				physical_block_numbers,
				/* u8 **out_data */
				&block);
			if(err) {
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
			/* u32 block_size */
			block_size,
			/* refs_node_block_queue_element **out_level2_extents */
			&primary_level2_blocks,
			/* size_t *out_level2_extents_count */
			&primary_level2_blocks_count);
		if(err) {
			goto out;
		}
	}

	if(secondary_level1_block) {
		if(!(secondary_level1_node && *secondary_level1_node)) {
			u64 logical_block_numbers[4] = {
				secondary_level1_block,
				secondary_level1_block + 1,
				secondary_level1_block + 2,
				secondary_level1_block + 3
			};
			u64 physical_block_numbers[4] = {
				logical_block_numbers[0], 
				logical_block_numbers[1], 
				logical_block_numbers[2], 
				logical_block_numbers[3] 
			};

			err = refs_node_get_node_data(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* size_t node_size */
				block_size,
				/* u64 logical_blocks[4] */
				logical_block_numbers,
				/* u64 physical_blocks[4] */
				physical_block_numbers,
				/* u8 **out_data */
				&block);
			if(err) {
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
			/* u32 block_size */
			block_size,
			/* refs_node_block_queue_element **out_level2_extents */
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

	if(primary_level2_blocks_count != secondary_level2_blocks_count) {
		sys_log_warning("Mismatching level 2 block count in "
			"level 1 blocks: %" PRIu32 " != %" PRIu32 " "
			"Proceeding with primary...",
			PRAu32(primary_level2_blocks_count),
			PRAu32(secondary_level2_blocks_count));
	}
	else {
		refs_node_block_queue_element *cur_primary =
			primary_level2_blocks;
		refs_node_block_queue_element *cur_secondary =
			secondary_level2_blocks;
		sys_bool mismatch = SYS_FALSE;

		while(cur_primary && cur_secondary) {
			if(memcmp(cur_primary, cur_secondary,
				offsetof(refs_node_block_queue_element, next)))
			{
				mismatch = SYS_TRUE;
				break;
			}

			cur_primary = cur_primary->next;
			cur_secondary = cur_secondary->next;
		}

		if(!!cur_primary != !!cur_secondary) {
			sys_log_critical("Internal error: Primary and "
				"secondary queue chains are not equally long! "
				"Primary ends %s secondary.",
				!cur_primary ? "before" : "after");
			err = ENXIO;
			goto out;
		}
		else if(!mismatch);
		else if(block_map && *block_map) {
			sys_log_debug("Mismatching level 2 block data in "
				"level 1 blocks. Proceeding with primary...");
		}
		else {
			sys_log_warning("Mismatching level 2 block data in "
				"level 1 blocks. Proceeding with primary...");
		}
	}

	level2_queue.queue = primary_level2_blocks;
	/* Find the tail. */
	level2_queue.queue_tail = primary_level2_blocks;
	while(level2_queue.queue_tail->next) {
		level2_queue.queue_tail = level2_queue.queue_tail->next;
	}
	level2_queue.block_queue_length = primary_level2_blocks_count;

	primary_level2_blocks = NULL;
	primary_level2_blocks_count = 0;

	if(block_map && *block_map) {
		mappings = *block_map;
	}
	else {
		refs_node_block_queue_element *const saved_queue_head =
			level2_queue.queue;
		refs_node_block_queue_element *const saved_queue_tail =
			level2_queue.queue_tail;
		const size_t saved_queue_length =
			level2_queue.block_queue_length;

		refs_node_block_queue_element *cur_element = NULL;

		err = sys_calloc(sizeof(*mappings), &mappings);
		if(err) {
			sys_log_perror(err, "Error while allocating mappings "
				"base struct");
			goto out;
		}

		/* For v3 volumes we first iterate over the Level 2 blocks to
		 * find the block region mappings, located in the tree with
		 * object ID 0xB. */
		if(!is_v3);
		else for(i = 0; level2_queue.queue; ++i,
			level2_queue.queue = level2_queue.queue->next,
			--level2_queue.block_queue_length)
		{
			u64 *const logical_block_numbers =
				level2_queue.queue->block_numbers;

			u64 physical_block_numbers[4];
			const REFS_V3_BLOCK_HEADER *header = NULL;
			size_t j = 0;
			u64 tree_object_id = 0;

			for(j = 0; j < 4; ++j) {
				physical_block_numbers[j] =
					(!is_v3 && j) ? 0 :
					logical_to_physical_block_number(
						/* refs_node_crawl_context
						 * *crawl_context */
						&crawl_context,
						/* u64 logical_block_number */
						logical_block_numbers[j]);
			}
			if(!physical_block_numbers[0]) {
				continue;
			}

			sys_log_debug("Reading block %" PRIuz " / %" PRIuz ": "
				"%" PRIu64 " -> %" PRIu64,
				PRAuz(i),
				PRAuz(level2_queue.block_queue_length),
				PRAu64(logical_block_numbers[0]),
				PRAu64(physical_block_numbers[0]));

			err = refs_node_get_node_data(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* size_t node_size */
				block_size,
				/* u64 logical_blocks[4] */
				logical_block_numbers,
				/* u64 physical_blocks[4] */
				physical_block_numbers,
				/* u8 **out_data */
				&block);
			if(err) {
				continue;
			}

			header = (const REFS_V3_BLOCK_HEADER*) block;

			if(memcmp(header->signature, "MSB+", 4) ||
				le64_to_cpu(header->block_number) !=
				logical_block_numbers[0])
			{
				sys_log_warning("Invalid data while reading "
					"block with identity mapping: %" PRIu64,
					PRAu64(logical_block_numbers[0]));
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
				physical_block_numbers[0],
				/* u64 block_number */
				logical_block_numbers[0],
				/* u64 block_queue_index */
				i,
				/* u8 level */
				2,
				/* const u8 *block */
				block,
				/* u32 block_size */
				block_size,
				/* refs_node_block_queue *block_queue */
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

		/* Restore queue head for later iteration. */
		level2_queue.queue = saved_queue_head;
		level2_queue.queue_tail = saved_queue_tail;
		level2_queue.block_queue_length = saved_queue_length;

		/* Free any items added after the previous tail. */
		if(saved_queue_tail) {
			cur_element = saved_queue_tail->next;
			saved_queue_tail->next = NULL;
		}
		while(cur_element) {
			refs_node_block_queue_element *const next_element =
				cur_element->next;
			sys_free(&cur_element);
			cur_element = next_element;
		}

		if(block_map) {
			*block_map = mappings;
		}
	}

	crawl_context.block_map = mappings;

	/* At this point the mappings are set up and we can look up a node by
	 * node number. */
	if(start_node) {
		u64 logical_block_numbers[4] = { *start_node, 0, 0, 0 };
		u64 physical_block_numbers[4] = { 0, 0, 0, 0 };
		u64 start_object_id = 0;
		sys_bool is_valid = SYS_FALSE;

		/* Discard primary level 2 blocks as we want a crawl targeted at
		 * the requested node number. The crawl may still add level 2
		 * blocks to the queue if we encounter a level 2 index node. */
		while(level2_queue.queue) {
			refs_node_block_queue_element *const next_element =
				level2_queue.queue->next;
			sys_free(&level2_queue.queue);
			level2_queue.queue = next_element;
		}

		level2_queue.queue_tail = NULL;
		level2_queue.block_queue_length = 0;

		physical_block_numbers[0] =
			logical_to_physical_block_number(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* u64 logical_block_number */
				logical_block_numbers[0]);

		sys_log_debug("Reading block %" PRIuz " / %" PRIuz ": "
			"%" PRIu64 " -> %" PRIu64,
			PRAuz(i),
			PRAuz(level2_queue.block_queue_length),
			PRAu64(logical_block_numbers[0]),
			PRAu64(physical_block_numbers[0]));

		err = refs_node_get_node_data(
			/* refs_node_crawl_context *crawl_context */
			&crawl_context,
			/* size_t node_size */
			block_size,
			/* u64 logical_blocks[4] */
			logical_block_numbers,
			/* u64 physical_blocks[4] */
			physical_block_numbers,
			/* u8 **out_data */
			&block);
		if(err) {
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
			physical_block_numbers[0],
			/* u64 block_number */
			logical_block_numbers[0],
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

		err = refs_node_block_queue_add(
			/* refs_node_block_queue *block_queue */
			&level3_queue,
			/* const u64 block_numbers[4] */
			logical_block_numbers,
			/* u64 flags */
			0,
			/* u64 checksum */
			0);
		if(err) {
			goto out;
		}
	}

	if(level2_queue.block_queue_length) {
		refs_node_block_queue_element *next_element = NULL;

		for(i = 0; level2_queue.queue; ++i,
			next_element = level2_queue.queue->next,
			sys_free(&level2_queue.queue),
			level2_queue.queue = next_element,
			--level2_queue.block_queue_length)
		{
			u64 *const logical_block_numbers =
				level2_queue.queue->block_numbers;

			u8 j;
			u64 physical_block_numbers[4] = { 0, 0, 0, 0 };
			u64 object_id_mapping = 0;

			for(j = 0; j < 4; ++j) {
				physical_block_numbers[j] =
					logical_to_physical_block_number(
						/* refs_node_crawl_context
						 * *crawl_context */
						&crawl_context,
						/* u64 logical_block_number */
						logical_block_numbers[j]);
			}

			sys_log_debug("Reading level %d block %" PRIuz " / "
				"%" PRIuz ": %" PRIu64 " -> %" PRIu64,
				2,
				PRAuz(i),
				PRAuz(level3_queue.block_queue_length),
				PRAu64(logical_block_numbers[0]),
				PRAu64(physical_block_numbers[0]));

			err = refs_node_get_node_data(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* size_t node_size */
				block_size,
				/* u64 logical_blocks[4] */
				logical_block_numbers,
				/* u64 physical_blocks[4] */
				physical_block_numbers,
				/* u8 **out_data */
				&block);
			if(err) {
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
				physical_block_numbers[0],
				/* u64 block_number */
				logical_block_numbers[0],
				/* u64 block_queue_index */
				i,
				/* const u8 *block */
				block,
				/* u32 block_size */
				block_size,
				/* const u64 *object_id_mapping */
				object_id ? &object_id_mapping : NULL,
				/* refs_node_block_queue *const level2_queue */
				&level2_queue,
				/* refs_node_block_queue *const level3_queue */
				&level3_queue);
			if(err) {
				goto out;
			}
		}

		if(!level2_queue.queue) {
			level2_queue.queue_tail = NULL;
		}
	}

	if(level3_queue.block_queue_length) {
		refs_node_block_queue_element *next_element = NULL;

		for(i = 0; level3_queue.queue; ++i,
			next_element = level3_queue.queue->next,
			sys_free(&level3_queue.queue),
			level3_queue.queue = next_element,
			--level3_queue.block_queue_length)
		{
			u64 *const logical_block_numbers =
				level3_queue.queue->block_numbers;
			u64 physical_block_numbers[4] = { 0, 0, 0, 0 };

			physical_block_numbers[0] =
				logical_to_physical_block_number(
					/* refs_node_crawl_context
					 * *crawl_context */
					&crawl_context,
					/* u64 logical_block_number */
					logical_block_numbers[0]);

			sys_log_debug("Reading level %d block %" PRIuz " / "
				"%" PRIuz ": %" PRIu64 " -> %" PRIu64,
				3,
				PRAuz(i),
				PRAuz(level3_queue.block_queue_length),
				PRAu64(logical_block_numbers[0]),
				PRAu64(physical_block_numbers[0]));

			err = refs_node_get_node_data(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* size_t node_size */
				block_size,
				/* u64 logical_blocks[4] */
				logical_block_numbers,
				/* u64 physical_blocks[4] */
				physical_block_numbers,
				/* u8 **out_data */
				&block);
			if(err) {
				goto out;
			}

			err = parse_level3_block(
				/* refs_node_crawl_context *crawl_context */
				&crawl_context,
				/* refs_node_walk_visitor *visitor */
				visitor,
				/* u64 cluster_number */
				physical_block_numbers[0],
				/* u64 block_number */
				logical_block_numbers[0],
				/* u64 block_queue_index */
				i,
				/* const u8 *block */
				block,
				/* u32 block_size */
				block_size,
				/* refs_node_block_queue *level3_queue */
				&level3_queue);
			if(err) {
				goto out;
			}
		}

		if(!level3_queue.queue) {
			level3_queue.queue_tail = NULL;
		}
	}
out:
	if(level3_queue.queue) {
		while(level3_queue.queue) {
			refs_node_block_queue_element *const next_element =
				level3_queue.queue->next;
			sys_free(&level3_queue.queue);
			level3_queue.queue = next_element;
		}
	}

	if(level2_queue.queue) {
		while(level2_queue.queue) {
			refs_node_block_queue_element *const next_element =
				level2_queue.queue->next;
			sys_free(&level2_queue.queue);
			level2_queue.queue = next_element;
		}
	}

	if(secondary_level2_blocks) {
		while(secondary_level2_blocks) {
			refs_node_block_queue_element *const next_element =
				secondary_level2_blocks->next;
			sys_free(&secondary_level2_blocks);
			secondary_level2_blocks = next_element;
		}
	}

	if(primary_level2_blocks) {
		while(primary_level2_blocks) {
			refs_node_block_queue_element *const next_element =
				primary_level2_blocks->next;
			sys_free(&primary_level2_blocks);
			primary_level2_blocks = next_element;
		}
	}

	if(block) {
		sys_free(&block);
	}

	if(mappings && !(block_map && *block_map == mappings)) {
		refs_block_map_destroy(
			/* refs_block_map **block_map */
			&mappings);
	}

	if(node_cache && !(node_cachep && *node_cachep == node_cache)) {
		refs_node_cache_destroy(
			/* refs_node_cache **node_cachep */
			&node_cache);
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
		refs_node_cache **const node_cache,
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
		/* refs_node_cache **node_cache */
		node_cache,
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
	if(cluster_size > 0xFFFFFFFFUL) {
		sys_log_error("Invalid cluster size (exceeds 32-bit range): %" PRIu64,
			PRAu64(cluster_size));
		err = EINVAL;
		goto out;
	}

	block_size =
		(bs->version_major == 1) ?
		((cluster_size == 4096) ? 12U * 1024U : 16U * 1024U) :
		sys_max(16U * 1024U, (u32) cluster_size);
	clusters_per_block =
		(block_size > cluster_size) ? block_size / cluster_size : 1;
	device_size = le64_to_cpu(bs->num_sectors) * sector_size;

	block_index_unit = (bs->version_major == 1) ? 16384 : (u32) cluster_size;

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
				(u32) ((device_size - i) / cluster_size);

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
	if(buffer) {
		sys_free(&buffer);
	}

	if(padding) {
		sys_free(&padding);
	}

	return err;
}
