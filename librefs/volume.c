/*-
 * volume.c - ReFS volume handling definitions.
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

#include "volume.h"

#include "sys.h"
#include "layout.h"
#include "node.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>

int refs_volume_create(
		sys_device *const dev,
		refs_volume **const out_vol)
{
	int err = 0;
	refs_volume *vol = NULL;
	u32 device_sector_size = 0;
	u32 filesystem_sector_size = 0;
	size_t bs_size = 0;
	u32 sectors_per_cluster = 0;
	u32 cluster_size = 0;
	REFS_BOOT_SECTOR *bs = NULL;
	size_t bytes_read = 0;

	err = sys_malloc(sizeof(*vol), &vol);
	if(err) {
		sys_log_perror(err, "Error while allocating volume struct");
		goto out;
	}

	memset(vol, 0, sizeof(*vol));

	err = sys_device_get_sector_size(
		/* sys_device *dev */
		dev,
		/* u32 *out_sector_size */
		&device_sector_size);
	if(err) {
		sys_log_pdebug(err, "Error while getting sector size "
			"(defaulting to the sector size specfied in the boot "
			"sector)");
		device_sector_size = 0;
		bs_size = 65536;
	}
	else {
		bs_size =
			((sizeof(*bs) + device_sector_size - 1) /
			device_sector_size) * device_sector_size;
	}

	err = sys_malloc(bs_size, &bs);
	if(err) {
		sys_log_perror(err, "Error while allocating volume struct");
		goto out;
	}

	err = sys_device_pread(
		dev,
		0,
		bs_size,
		bs);
	if(err) {
		sys_log_perror(err, "Error while reading boot sector");
		goto out;
	}

	if(memcmp(bs->signature, "FSRS", 4)) {
		sys_log_error("Not an ReFS volume (signature is missing).");
		err = EIO;
		goto out;
	}
	else if(memcmp(bs->oem_id, "ReFS", 4)) {
		sys_log_error("Not an ReFS volume (unexpected OEM ID: "
			"%.*s).",
			(int) sizeof(bs->oem_id), bs->oem_id);
		err = EIO;
		goto out;
	}

	filesystem_sector_size = le32_to_cpu(bs->bytes_per_sector);
	if(filesystem_sector_size < 512 || filesystem_sector_size > 65536 ||
		((filesystem_sector_size - 1) & filesystem_sector_size))
	{
		sys_log_error("Unsupported filesystem sector size: %" PRIu32,
			PRAu32(device_sector_size));
		err = EIO;
		goto out;
	}

	sectors_per_cluster = le32_to_cpu(bs->sectors_per_cluster);
	if(sectors_per_cluster < 8 || sectors_per_cluster > 128) {
		sys_log_error("Unsupported number of sectors per cluster: "
			"%" PRIu32,
			PRAu32(cluster_size));
		err = EIO;
		goto out;
	}

	/* Note: Given the sanity checks above, 32-bit overflow should be
	 * impossible in the below calculation. */
	cluster_size = sectors_per_cluster * filesystem_sector_size;
	if(cluster_size < 4096 || cluster_size > 65536 ||
		((cluster_size - 1) & cluster_size))
	{
		sys_log_error("Unsupported cluster size: %" PRIu32,
			PRAu32(cluster_size));
		err = EIO;
		goto out;
	}

	if(!device_sector_size && bs_size != filesystem_sector_size) {
		REFS_BOOT_SECTOR *new_bs = NULL;

		err = sys_realloc(bs, filesystem_sector_size, &new_bs);
		if(err) {
			sys_log_perror(err, "Error while shrinking boot "
				"sector to %" PRIu32 " bytes",
				PRAu32(filesystem_sector_size));
			goto out;
		}

		bs = new_bs;
		bs_size = filesystem_sector_size;
	}
	else if(device_sector_size != filesystem_sector_size) {
		sys_log_warning("Mismatching filesystem/device sector size: "
			"%" PRIu32 " / %" PRIu32,
			PRAu32(filesystem_sector_size),
			PRAu32(device_sector_size));
	}

	vol->dev = dev;
	vol->bs = bs;
	vol->sector_size = filesystem_sector_size;
	vol->cluster_size = cluster_size;
	vol->sector_count = le64_to_cpu(bs->num_sectors);
	vol->cluster_count =
		vol->sector_count / le32_to_cpu(bs->sectors_per_cluster);
	bs = NULL;

	*out_vol = vol;
	vol = NULL;
out:
	if(bs) {
		sys_free(&bs);
	}

	if(vol) {
		sys_free(&vol);
	}

	return err;
}

void refs_volume_destroy(
		refs_volume **const out_vol)
{
	refs_volume *const vol = *out_vol;

	sys_free(&vol->bs);
	sys_free(out_vol);
}

typedef struct {
	refschar *name;
	size_t name_length;
	sys_bool found;
	sys_bool is_directory;
	u64 directory_object_id;
	u8 **record;
	size_t *record_size;
} refs_volume_lookup_context;

static int refs_volume_lookup_node_file_entry(
		void *_context,
		const refschar *file_name,
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
	refs_volume_lookup_context *const context =
		(refs_volume_lookup_context*) _context;

	int err = 0;

	(void) file_flags;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) file_size;
	(void) allocated_size;

	if(file_name_length == context->name_length &&
		!memcmp(file_name, context->name,
		file_name_length * sizeof(refschar)))
	{
		context->found = SYS_TRUE;
		context->is_directory = SYS_FALSE;

		if(context->record) {
			err = sys_malloc(record_size, context->record);
			if(err) {
				goto out;
			}

			memcpy(*context->record, record, record_size);
		}

		if(context->record_size) {
			*context->record_size = record_size;
		}
	}
out:
	return err;
}

static int refs_volume_lookup_node_directory_entry(
		void *_context,
		const refschar *file_name,
		u16 file_name_length,
		u32 file_flags,
		u64 object_id,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		const u8 *record,
		size_t record_size)
{
	refs_volume_lookup_context *const context =
		(refs_volume_lookup_context*) _context;

	int err = 0;

	(void) file_flags;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;

	if(file_name_length == context->name_length &&
		!memcmp(file_name, context->name,
		file_name_length * sizeof(refschar)))
	{
		context->found = SYS_TRUE;
		context->is_directory = SYS_TRUE;
		context->directory_object_id = object_id;

		if(context->record) {
			err = sys_malloc(record_size, context->record);
			if(err) {
				goto out;
			}

			memcpy(*context->record, record, record_size);
		}

		if(context->record_size) {
			*context->record_size = record_size;
		}
	}
out:
	return err;
}

static int next_path_element(const void **const path,
		const size_t path_size,
		void *const out_element, size_t *const out_element_length)
{
	const char *const pathp = (const char*) *path;
	const size_t pathp_len = path_size;
	const char *slashp;

	int err = 0;

	size_t element_length;

	sys_log_trace("Entering: path=%p path_size=%" PRIuz " out_element=%p "
		"out_element_length=%" PRIuz,
		path, PRAuz(path_size), out_element, PRAuz(out_element_length));

	if(!pathp_len) {
		sys_log_error("Got empty subpath when getting next POSIX path "
			"element.");
		err = EINVAL;
		goto out;
	}

	slashp = memchr(pathp, '/', pathp_len);
	if(slashp) {
		element_length = (slashp - pathp);
	}
	else {
		element_length = pathp_len;
	}

	sys_log_debug("  element_length=%" PRIuz, PRAuz(element_length));
	if(out_element_length) {
		sys_log_debug("  *out_element_length=%" PRIuz,
			PRAuz(*out_element_length));
	}
	sys_log_debug("  Processing path element: \"%" PRIbs "\"",
		PRAbs(element_length, pathp));

	if(out_element_length) {
		refschar *out_element_tmp;

		if(!element_length) {
			*out_element_length = 0;
		}
		else if(!*out_element_length) {
			err = ERANGE;
			goto out;
		}
		else if(!out_element) {
			sys_log_critical("Non-empty element but no output "
				"buffer.");
			err = ENXIO;
			goto out;
		}

		out_element_tmp = (refschar*) out_element;

		err = sys_unistr_encode(
			pathp,
			element_length,
			&out_element_tmp,
			out_element_length);
		if(err == ERANGE) {
			goto out;
		}
		else if(err) {
			sys_log_perror(err, "Error while encoding "
				"pathname element string");
			goto out;
		}
		else if(out_element_tmp != out_element) {
			sys_free(&out_element_tmp);
			sys_log_critical("Preallocated buffer was "
				"unexpectedly reallocated when "
				"converting pathname element "
				"\"%.*s\" to UTF-16LE.",
				(int) element_length, pathp);
			err = ENXIO;
			goto out;
		}
	}

	*path = &pathp[element_length + (slashp ? 1 : 0)];

	sys_log_debug("Advancing path from \"%" PRIbs "\" (length: %" PRIuz ") "
		"to \"%" PRIbs "\" (length: %" PRIuz ")...",
		PRAbs(pathp_len, pathp),
		PRAuz(pathp_len),
		PRAbs(pathp_len - (element_length + (slashp ? 1 : 0)),
		(const char*) *path),
		PRAuz(pathp_len - (element_length + (slashp ? 1 : 0))));
out:
	return err;
}

static int refs_volume_lookup(
		refs_volume *const vol,
		const void *const path,
		u64 *const out_parent_directory_object_id,
		u64 *const out_directory_object_id,
		u8 **const out_record,
		size_t *const out_record_size)
{
	const size_t path_size = strlen(path);

	int err = 0;
	refs_node_walk_visitor visitor;
	refs_volume_lookup_context context;
	const void *cur_path = path;
	size_t cur_path_length = path_size;
	u64 cur_object_id = 0x600;
	refschar *cur_element = NULL;
	size_t cur_element_capacity = 255;
	size_t cur_element_length = 0;

	memset(&visitor, 0, sizeof(visitor));

	err = sys_malloc(cur_element_capacity, &cur_element);
	if(err) {
		goto out;
	}

	visitor.node_file_entry = refs_volume_lookup_node_file_entry;
	visitor.node_directory_entry = refs_volume_lookup_node_directory_entry;
	visitor.context = &context;

	while(1) {

		cur_element_length = cur_element_capacity;

		err = next_path_element(
			/* const void **path */
			&cur_path,
			/* size_t path_size */
			cur_path_length,
			/* void *out_element */
			cur_element,
			/* size_t *out_element_length */
			&cur_element_length);
		if(err) {
			sys_log_perror(err, "Error while encoding path element "
				"as UTF-16");
			goto out;
		}

		cur_path_length =
			path_size - ((size_t) cur_path - (size_t) path);


		memset(&context, 0, sizeof(context));
		context.name = cur_element;
		context.name_length = cur_element_length;

		if(!cur_path_length) {
			/* Final element. */
			if(out_record) {
				*out_record = NULL;
				context.record = out_record;
			}

			if(out_record_size) {
				*out_record_size = 0;
				context.record_size = out_record_size;
			}
		}

		err = refs_node_walk(
			/* refs_device *dev */
			vol->dev,
			/* REFS_BOOT_SECTOR *bs */
			vol->bs,
			/* REFS_SUPERBLOCK **sb */
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
			&cur_object_id,
			/* refs_node_walk_visitor *visitor */
			&visitor);
		if(err) {
			goto out;
		}

		if(!context.found) {
			break;
		}

		if(!cur_path_length) {
			/* Last element. */
			if(out_parent_directory_object_id) {
				*out_parent_directory_object_id = cur_object_id;
			}

			if(out_directory_object_id) {
				*out_directory_object_id =
					context.is_directory ?
					context.directory_object_id : 0;
			}

			break;
		}
		else if(!context.is_directory) {
			/* Intermediate pathname element is non-directory. */
			break;
		}

		cur_object_id = context.directory_object_id;
	}
out:
	if(cur_element) {
		sys_free(&cur_element);
	}

	return err;
}

int refs_volume_lookup_by_posix_path(
		refs_volume *const vol,
		const char *const path,
		u64 *const out_parent_directory_object_id,
		u64 *const out_directory_object_id,
		u8 **const out_record,
		size_t *const out_record_size)
{
	int err = 0;
	const char *cur_path = path;

	if(cur_path[0] != '/') {
		err = EINVAL;
		goto out;
	}

	while(cur_path[0] == '/') {
		++cur_path;
	}

	if(!cur_path[0]) {
		/* The request is for the root directory. We can't supply a
		 * record for it, only the object ID. */
		if(out_parent_directory_object_id) {
			*out_parent_directory_object_id = 0x600;
		}

		if(out_directory_object_id) {
			*out_directory_object_id = 0x600;
		}

		if(out_record) {
			*out_record = NULL;
		}

		if(out_record_size) {
			*out_record_size = 0;
		}

		goto out;
	}

	err = refs_volume_lookup(
		/* refs_volume *vol */
		vol,
		/* const void *path */
		cur_path,
		/* u64 *out_parent_directory_object_id */
		out_parent_directory_object_id,
		/* u64 *out_directory_object_id */
		out_directory_object_id,
		/* u8 **out_record */
		out_record,
		/* size_t *out_record_size */
		out_record_size);
out:
	return err;
}

int refs_volume_lookup_by_object_id(
		refs_volume *const vol,
		const u64 object_id,
		refs_node **const out_node)
{
	int err = 0;
	refs_node_walk_visitor visitor;

	memset(&visitor, 0, sizeof(visitor));

	err = refs_node_walk(
		/* refs_device *dev */
		vol->dev,
		/* REFS_BOOT_SECTOR *bs */
		vol->bs,
		/* REFS_SUPERBLOCK **sb */
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
		&object_id,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err) {
		goto out;
	}
out:
	return err;
}

static inline int refs_volume_generate_metadata_bitmap_mark_cluster(
		u8 *const bitmap,
		const size_t bitmap_size,
		const u64 cluster_number)
{
	const u64 bitmap_byte = cluster_number / 8;
	const u8 bitmap_bit = 7 - cluster_number % 8;

	int err = 0;

	if(bitmap_byte >= bitmap_size) {
		sys_log_error("Attempted to mark cluster %" PRIu64 " beyond "
			"the end of the %" PRIu64 " cluster bitmap...",
			PRAu64(cluster_number), PRAu64(bitmap_size * (u64) 8));
		err = ERANGE;
		goto out;
	}

	bitmap[bitmap_byte] |= 1U << bitmap_bit;
out:
	return err;
}

typedef struct {
	u8 *bitmap;
	size_t bitmap_size;
} refs_generate_metadata_bitmap_context;

static int refs_volume_generate_metadata_bitmap_visit_node(
		void *const _context,
		const u64 cluster_number,
		const u32 cluster_count,
		const REFS_V3_BLOCK_HEADER *const header)
{
	refs_generate_metadata_bitmap_context *const context =
		(refs_generate_metadata_bitmap_context*) _context;

	int err = 0;
	u32 i;

	(void) header;

	for(i = 0; i < cluster_count; ++i) {
		sys_log_debug("Marking node cluster %" PRIu64 "...",
			PRAu64(cluster_number + i));

		err = refs_volume_generate_metadata_bitmap_mark_cluster(
			/* u8 *bitmap */
			context->bitmap,
			/* size_t bitmap_size */
			context->bitmap_size,
			/* u64 cluster_number */
			cluster_number + i);
		if(err) {
			goto out;
		}
	}
out:
	return err;
}

int refs_volume_generate_metadata_bitmap(
		refs_volume *const vol,
		u8 **const out_bitmap,
		size_t *const out_bitmap_size)
{
	const u64 block_index_unit =
		(vol->bs->version_major == 1) ? 16384 : vol->cluster_size;
	const u64 block_index_end = block_index_unit * 31;

	int err = 0;
	u8 *bitmap = NULL;
	size_t bitmap_size = 0;
	refs_generate_metadata_bitmap_context context;
	refs_node_scan_visitor visitor;
	u64 i;

	memset(&context, 0, sizeof(context));
	memset(&visitor, 0, sizeof(visitor));

	bitmap_size =
		(((vol->sector_count * vol->sector_size + vol->cluster_size -
		1) / vol->cluster_size) + 7) / 8;
	err = sys_calloc(bitmap_size, &bitmap);
	if(err) {
		sys_log_perror(err, "Error while allocating %" PRIuz " bytes "
			"of bitmap data", PRAuz(bitmap_size));
		goto out;
	}

	context.bitmap = bitmap;
	context.bitmap_size = bitmap_size,

	visitor.context = &context;
	visitor.visit_node = refs_volume_generate_metadata_bitmap_visit_node;

	/* Mark boot sector and clusters < 30. */
	for(i = 0; i < block_index_end; i += vol->cluster_size) {
		sys_log_debug("Marking boot region cluster %" PRIu64 "...",
			PRAu64(i / vol->cluster_size));

		err = refs_volume_generate_metadata_bitmap_mark_cluster(
			/* u8 *bitmap */
			bitmap,
			/* size_t bitmap_size */
			bitmap_size,
			/* u64 cluster_number */
			i / vol->cluster_size);
		if(err) {
			sys_log_perror(err, "Error while marking boot region "
				"cluster %" PRIu64,
				PRAu64(i / vol->cluster_size));
			goto out;
		}
	}

	/* Mark alternate boot sector. */
	err = refs_volume_generate_metadata_bitmap_mark_cluster(
		/* u8 *bitmap */
		bitmap,
		/* size_t bitmap_size */
		bitmap_size,
		/* u64 cluster_number */
		((vol->sector_count - 1) * vol->sector_size) /
		vol->cluster_size);
	if(err) {
		sys_log_perror(err, "Error while marking alternate boot sector "
			"cluster %" PRIu64,
			PRAu64(((vol->sector_count - 1) * vol->sector_size) /
			vol->cluster_size));
		goto out;
	}

	err = refs_node_scan(
		/* refs_device *dev */
		vol->dev,
		/* REFS_BOOT_SECTOR *bs */
		vol->bs,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err) {
		sys_log_perror(err, "Error while scanning volume");
		goto out;
	}

	*out_bitmap = bitmap;
	*out_bitmap_size = bitmap_size;
	bitmap = NULL;
out:
	if(bitmap) {
		sys_free(&bitmap);
	}

	return err;
}
