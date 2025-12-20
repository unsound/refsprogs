/*-
 * volume.c - ReFS volume handling definitions.
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

#include "volume.h"

#include "sys.h"
#include "layout.h"
#include "node.h"

static int refs_volume_create_visit_node_header(
		void *context,
		u64 node_number,
		u64 node_first_cluster,
		u64 object_id,
		const u8 *data,
		const size_t data_size,
		const size_t header_offset,
		size_t header_size)
{
	(void) context;
	(void) node_number;
	(void) node_first_cluster;
	(void) data;
	(void) data_size;
	(void) header_offset;
	(void) header_size;

	sys_log_debug("%sreaking at node header with node number %" PRIu64 ", "
		"first cluster %" PRIu64 ", object ID %" PRIu64 ".",
		object_id ? "B" : "Not b", PRAu64(node_number),
		PRAu64(node_first_cluster), PRAu64(object_id));

	/* Break at first level 2 node header. */
	return object_id ? -1 : 0;
}

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
	refs_node_walk_visitor visitor;

	memset(&visitor, 0, sizeof(visitor));

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
		/* sys_device *dev */
		dev,
		/* u64 offset */
		0,
		/* size_t nbytes */
		bs_size,
		/* void *buf */
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

		err = sys_realloc(bs, bs_size, filesystem_sector_size, &new_bs);
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
	vol->metadata_block_size =
		(bs->version_major >= 2) ? sys_max(16U * 1024U, cluster_size) :
		((cluster_size == 4096) ? 12U * 1024U : 16U * 1024U);
	vol->sector_count = le64_to_cpu(bs->num_sectors);
	vol->cluster_count =
		vol->sector_count / le32_to_cpu(bs->sectors_per_cluster);

	visitor.node_header =
		refs_volume_create_visit_node_header;

	/* Preload all the necessary metadata by walking the tree and stopping
	 * at the first node. */
	err = refs_node_walk(
		/* refs_device *dev */
		vol->dev,
		/* const REFS_BOOT_SECTOR *bs */
		vol->bs,
		/* REFS_SUPERBLOCK **sb */
		&vol->sb,
		/* REFS_LEVEL1_NODE **primary_level1_node */
		&vol->primary_level1_node,
		/* REFS_LEVEL1_NODE **secondary_level1_node */
		&vol->secondary_level1_node,
		/* refs_block_map **block_map */
		&vol->block_map,
		/* refs_node_cache **node_cache */
		&vol->node_cache,
		/* const u64 *start_node */
		NULL,
		/* const u64 *object_id */
		NULL,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err == -1) {
		err = 0;
	}
	else if(err) {
		goto out;
	}

	bs = NULL;

	*out_vol = vol;
	vol = NULL;
out:
	if(bs) {
		sys_free(sizeof(*bs), &bs);
	}

	if(vol) {
		sys_free(sizeof(*vol), &vol);
	}

	return err;
}

void refs_volume_destroy(
		refs_volume **const out_vol)
{
	refs_volume *const vol = *out_vol;

	if(vol->node_cache) {
		refs_node_cache_destroy(
			/* refs_node_cache **node_cache */
			&vol->node_cache);
	}

	if(vol->block_map) {
		refs_block_map_destroy(
			/* refs_block_map **block_map */
			&vol->block_map);
	}

	sys_free(sizeof(*vol->bs), &vol->bs);
	sys_free(sizeof(**out_vol), out_vol);
}

typedef struct {
	refschar *name;
	size_t name_length;
	sys_bool found;
	sys_bool is_hard_link;
	sys_bool hard_link_found;
	sys_bool is_short_entry;
	sys_bool is_directory;
	u64 hard_link_id;
	u64 hard_link_parent_object_id;
	u64 directory_object_id;
	u16 *entry_offset;
	u8 **key;
	size_t *key_size;
	u8 **record;
	size_t *record_size;
} refs_volume_lookup_context;

static int refs_volume_lookup_node_long_entry(
		void *const _context,
		const refschar *const file_name,
		const u16 file_name_length,
		const u16 child_entry_offset,
		const u32 file_flags,
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
	refs_volume_lookup_context *const context =
		(refs_volume_lookup_context*) _context;

	int err = 0;

	(void) file_flags;
	(void) parent_node_object_id;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) file_size;
	(void) allocated_size;

	if(file_name_length != context->name_length ||
		memcmp(file_name, context->name,
		file_name_length * sizeof(refschar)))
	{
		goto out;
	}

	context->found = SYS_TRUE;
	context->is_short_entry = SYS_FALSE;
	context->is_directory = SYS_FALSE;

	if(context->entry_offset) {
		*context->entry_offset = child_entry_offset;
	}

	if(context->key) {
		err = sys_malloc(key_size, context->key);
		if(err) {
			goto out;
		}

		memcpy(*context->key, key, key_size);
	}

	if(context->key_size) {
		*context->key_size = key_size;
	}

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

	err = -1;
out:
	return err;
}

static int refs_volume_lookup_node_short_entry(
		void *const _context,
		const refschar *const file_name,
		const u16 file_name_length,
		const u16 child_entry_offset,
		const u32 file_flags,
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
	refs_volume_lookup_context *const context =
		(refs_volume_lookup_context*) _context;

	int err = 0;

	(void) parent_node_object_id;
	(void) hard_link_id;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) file_size;
	(void) allocated_size;

	if(file_name_length != context->name_length ||
		memcmp(file_name, context->name,
		file_name_length * sizeof(refschar)))
	{
		goto out;
	}

	context->found = SYS_TRUE;
	if(!(file_flags & 0x10000000UL) && hard_link_id) {
		context->is_hard_link = SYS_TRUE;
		context->hard_link_id = hard_link_id;
		context->hard_link_parent_object_id = object_id;
	}
	else {
		context->is_short_entry = SYS_TRUE;
		context->is_directory =
			(file_flags & 0x10000000UL) ? SYS_TRUE : SYS_FALSE;
		context->directory_object_id =
			context->is_directory ? object_id : 0;

		if(context->entry_offset) {
			*context->entry_offset = child_entry_offset;
		}

		if(context->key) {
			err = sys_malloc(key_size, context->key);
			if(err) {
				goto out;
			}

			memcpy(*context->key, key, key_size);
		}

		if(context->key_size) {
			*context->key_size = key_size;
		}

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

                err = -1;
	}
out:
	return err;
}

static int refs_volume_lookup_node_hardlink_entry(
		void *const _context,
		const u64 hard_link_id,
		const u64 parent_id,
		const u16 child_entry_offset,
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

	sys_log_debug("Got hardlink entry with id: 0x%" PRIX64 " / parent: "
		"0x%" PRIX64, PRAX64(hard_link_id), PRAX64(parent_id));

	if(context->hard_link_id != hard_link_id ||
		context->hard_link_parent_object_id != parent_id)
	{
		goto out;
	}

	sys_log_debug("Match found! key=%p, key_size=%" PRIuz ", record=%p, "
		"record_size=%" PRIuz,
		key, PRAuz(key_size), record, PRAuz(record_size));
	context->hard_link_found = SYS_TRUE;
	context->is_short_entry = SYS_FALSE;
	context->is_directory = SYS_FALSE;
	context->directory_object_id = 0;

	if(context->entry_offset) {
		*context->entry_offset = child_entry_offset;
	}

	if(context->key) {
		err = sys_malloc(key_size, context->key);
		if(err) {
			goto out;
		}

		memcpy(*context->key, key, key_size);
	}

	if(context->key_size) {
		*context->key_size = key_size;
	}

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

	err = -1;
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
		"out_element_length=%p (->%" PRIuz ")",
		path, PRAuz(path_size), out_element, out_element_length,
		PRAuz(out_element_length ? *out_element_length : 0));

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
			/* const char *ins */
			pathp,
			/* size_t ins_len */
			element_length,
			/* refschar **outs */
			&out_element_tmp,
			/* size_t *outs_len */
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
			sys_free((*out_element_length + 1) *
				sizeof(out_element_tmp[0]), &out_element_tmp);
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
		const size_t path_length,
		const u64 *const start_object_id,
		u64 *const out_parent_directory_object_id,
		u64 *const out_directory_object_id,
		sys_bool *const out_is_short_entry,
		u16 *const out_entry_offset,
		u8 **const out_key,
		size_t *const out_key_size,
		u8 **const out_record,
		size_t *const out_record_size)
{
	int err = 0;
	refs_node_walk_visitor visitor;
	refs_volume_lookup_context context;
	const void *cur_path = path;
	size_t cur_path_length = path_length;
	u64 cur_object_id = start_object_id ? *start_object_id : 0x600;
	refschar *cur_element = NULL;
	size_t cur_element_capacity = 255;
	size_t cur_element_length = 0;

	memset(&visitor, 0, sizeof(visitor));

	err = sys_malloc(cur_element_capacity * sizeof(refschar), &cur_element);
	if(err) {
		goto out;
	}

	visitor.node_long_entry = refs_volume_lookup_node_long_entry;
	visitor.node_short_entry = refs_volume_lookup_node_short_entry;
	visitor.context = &context;

	while(1) {
		cur_element_length = cur_element_capacity;

		sys_log_debug("Processing path element \"%" PRIbs "\"...",
			PRAbs(cur_path_length, (const char*) cur_path));
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
			path_length - ((size_t) cur_path - (size_t) path);

		memset(&context, 0, sizeof(context));
		context.name = cur_element;
		context.name_length = cur_element_length;

		if(!cur_path_length) {
			/* Final element. */
			if(out_entry_offset) {
				*out_entry_offset = 0;
				context.entry_offset = out_entry_offset;
			}

			if(out_key) {
				*out_key = NULL;
				context.key = out_key;
			}

			if(out_key_size) {
				*out_key_size = 0;
				context.key_size = out_key_size;
			}

			if(out_record) {
				*out_record = NULL;
				context.record = out_record;
			}

			if(out_record_size) {
				*out_record_size = 0;
				context.record_size = out_record_size;
			}
		}

		sys_log_debug("Walking node %" PRIu64 " with node cache %p.",
			PRAu64(cur_object_id), vol->node_cache);

		err = refs_node_walk(
			/* refs_device *dev */
			vol->dev,
			/* const REFS_BOOT_SECTOR *bs */
			vol->bs,
			/* REFS_SUPERBLOCK **sb */
			&vol->sb,
			/* REFS_LEVEL1_NODE **primary_level1_node */
			&vol->primary_level1_node,
			/* REFS_LEVEL1_NODE **secondary_level1_node */
			&vol->secondary_level1_node,
			/* refs_block_map **block_map */
			&vol->block_map,
			/* refs_node_cache **node_cache */
			&vol->node_cache,
			/* const u64 *start_node */
			NULL,
			/* const u64 *object_id */
			&cur_object_id,
			/* refs_node_walk_visitor *visitor */
			&visitor);
		if(err == -1) {
			err = 0;
		}
		else if(err) {
			goto out;
		}

		sys_log_debug("    %sound in object ID 0x%" PRIX64 ".",
			context.found ? "F" : "Not f",
			PRAX64(cur_object_id));

		if(!context.found) {
			break;
		}

		if(!cur_path_length && context.is_hard_link) {
			/* Last element and this is a hard link. Look up the
			 * hard link target. */
			visitor.node_long_entry = NULL;
			visitor.node_short_entry = NULL;
			visitor.node_hardlink_entry =
				refs_volume_lookup_node_hardlink_entry;

			sys_log_debug("Resolving hard link entry to parent "
				"0x%" PRIX64 " / id %" PRIX64 " in leaf.",
				PRAX64(context.hard_link_parent_object_id),
				PRAX64(context.hard_link_id));

			err = refs_node_walk(
				/* refs_device *dev */
				vol->dev,
				/* const REFS_BOOT_SECTOR *bs */
				vol->bs,
				/* REFS_SUPERBLOCK **sb */
				&vol->sb,
				/* REFS_LEVEL1_NODE **primary_level1_node */
				&vol->primary_level1_node,
				/* REFS_LEVEL1_NODE **secondary_level1_node */
				&vol->secondary_level1_node,
				/* refs_block_map **block_map */
				&vol->block_map,
				/* refs_node_cache **node_cache */
				&vol->node_cache,
				/* const u64 *start_node */
				NULL,
				/* const u64 *object_id */
				&context.hard_link_parent_object_id,
				/* refs_node_walk_visitor *visitor */
				&visitor);
			if(err == -1) {
				err = 0;
			}
			else if(err) {
				goto out;
			}

			if(!context.hard_link_found) {
				sys_log_error("Couldn't find hard link target "
					"with parent 0x%" PRIX64 " / id "
					"0x%" PRIX64 ".",
					PRAX64(context.
					hard_link_parent_object_id),
					PRAX64(context.hard_link_id));
				err = EIO;
				goto out;
			}

			sys_log_debug("Hard link to parent 0x%" PRIX64 " / id "
				"0x%" PRIX64 " resolved to: key=%p, "
				"key_size=%" PRIuz ", record=%p, "
				"record_size=%" PRIuz,
				PRAX64(context.hard_link_parent_object_id),
				PRAX64(context.hard_link_id),
				context.key ? *context.key : NULL,
				PRAuz(context.key_size ? *context.key_size : 0),
				context.record ? *context.record : NULL,
				PRAuz(context.record_size ?
					*context.record_size : 0));

			cur_object_id = context.hard_link_parent_object_id;
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

			if(out_is_short_entry) {
				*out_is_short_entry = context.is_short_entry;
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
		sys_free(cur_element_capacity * sizeof(cur_element[0]),
			&cur_element);
	}

	return err;
}

int refs_volume_lookup_by_posix_path(
		refs_volume *const vol,
		const char *const path,
		const size_t path_length,
		const u64 *const start_object_id,
		u64 *const out_parent_directory_object_id,
		u64 *const out_directory_object_id,
		sys_bool *const out_is_short_entry,
		u16 *const out_entry_offset,
		u8 **const out_key,
		size_t *const out_key_size,
		u8 **const out_record,
		size_t *const out_record_size)
{
	int err = 0;
	const char *cur_path = path;
	size_t cur_path_length = path_length;

	while(cur_path_length && cur_path[0] == '/') {
		++cur_path;
		--cur_path_length;
	}

	if(!start_object_id && !cur_path_length) {
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
	else if(!cur_path_length) {
		/* Not found. */
		if(out_parent_directory_object_id) {
			*out_parent_directory_object_id = 0;
		}

		if(out_directory_object_id) {
			*out_directory_object_id = 0;
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
		/* size_t cur_path_length */
		cur_path_length,
		/* const u64 *start_object_id */
		start_object_id,
		/* u64 *out_parent_directory_object_id */
		out_parent_directory_object_id,
		/* u64 *out_directory_object_id */
		out_directory_object_id,
		/* sys_bool *out_is_short_entry */
		out_is_short_entry,
		/* u16 *out_entry_offset */
		out_entry_offset,
		/* u8 **out_key */
		out_key,
		/* size_t *out_key_size */
		out_key_size,
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
		/* const REFS_BOOT_SECTOR *bs */
		vol->bs,
		/* REFS_SUPERBLOCK **sb */
		&vol->sb,
		/* REFS_LEVEL1_NODE **primary_level1_node */
		&vol->primary_level1_node,
		/* REFS_LEVEL1_NODE **secondary_level1_node */
		&vol->secondary_level1_node,
		/* refs_block_map **block_map */
		&vol->block_map,
		/* refs_node_cache **node_cache */
		&vol->node_cache,
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
	context.bitmap_size = bitmap_size;

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
		/* const REFS_BOOT_SECTOR *bs */
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
		sys_free(bitmap_size, &bitmap);
	}

	return err;
}
