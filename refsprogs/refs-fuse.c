/*-
 * refs-fuse.c - FUSE driver interface to librefs.
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

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include "node.h"
#include "sys.h"
#include "volume.h"

static int refs_fuse_fill_stat(
		struct stat *stbuf,
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
	struct stat stbuf;
	char *cname = NULL;
	size_t cname_length = 0;

	err = refs_fuse_fill_stat(
		/* struct stat *stbuf */
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
		/* const struct stat *stbuf */
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

static int refs_fuse_op_getattr_visit_directory_entry(
		void *context,
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
	(void) file_name;
	(void) file_name_length;
	(void) object_id;
	(void) record;
	(void) record_size;

	return refs_fuse_fill_stat(
		/* struct stat *stbuf */
		(struct stat*) context,
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
		0,
		/* u64 allocated_size */
		0);
}

static int refs_fuse_op_getattr_visit_file_entry(
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
		(struct stat*) context,
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

static int refs_fuse_op_getattr(const char *path, struct stat *stbuf)
{
	refs_volume *const vol =
		(refs_volume*) fuse_get_context()->private_data;
	int err = 0;
	u8 *record = NULL;
	size_t record_size = 0;
	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;
	refs_node_walk_visitor visitor;

	memset(&visitor, 0, sizeof(visitor));

	err = refs_volume_lookup_by_posix_path(
		/* refs_volume *vol */
		vol,
		/* const char *path */
		path,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* u8 **out_record */
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

	visitor.context = stbuf;
	if(directory_object_id) {
		visitor.node_directory_entry =
			refs_fuse_op_getattr_visit_directory_entry;
		err = parse_level3_directory_value(
			/* refs_node_walk_visitor *visitor */
			&visitor,
			/* const char *prefix */
			"",
			/* size_t indent */
			1,
			/* sys_bool is_v3 */
			(vol->bs->version_major >= 3) ? SYS_TRUE : SYS_FALSE,
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
		visitor.node_file_entry =
			refs_fuse_op_getattr_visit_file_entry;
		err = parse_level3_file_value(
			/* refs_node_walk_visitor *visitor */
			&visitor,
			/* const char *prefix */
			"",
			/* size_t indent */
			1,
			/* u32 block_index_unit */
			(vol->bs->version_major == 1) ? 16384 :
			vol->cluster_size,
			/* sys_bool is_v3 */
			(vol->bs->version_major >= 3) ? SYS_TRUE : SYS_FALSE,
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
	if(record) {
		sys_free(&record);
	}

	return -err;
}

static int refs_fuse_op_open(const char *path, struct fuse_file_info *fi)
{
	refs_volume *const vol =
		(refs_volume*) fuse_get_context()->private_data;
	int err = 0;
	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;

	err = refs_volume_lookup_by_posix_path(
		/* refs_volume *vol */
		vol,
		/* const char *path */
		path,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* u8 **out_record */
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

static int refs_fuse_op_read(const char *path, char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	refs_volume *const vol =
		(refs_volume*) fuse_get_context()->private_data;
	int err = 0;
	u8 *record = NULL;
	size_t record_size = 0;
	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;
	refs_fuse_op_read_context context;
	refs_node_walk_visitor visitor;

	memset(&context, 0, sizeof(context));
	memset(&visitor, 0, sizeof(visitor));

	err = refs_volume_lookup_by_posix_path(
		/* refs_volume *vol */
		vol,
		/* const char *path */
		path,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* u8 **out_record */
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
	visitor.context = &context;
	visitor.node_file_extent = refs_fuse_op_read_visit_file_extent;

	err = parse_level3_file_value(
		/* refs_node_walk_visitor *visitor */
		&visitor,
		/* const char *prefix */
		"",
		/* size_t indent */
		1,
		/* u32 block_index_unit */
		(vol->bs->version_major == 1) ? 16384 : vol->cluster_size,
		/* sys_bool is_v3 */
		(vol->bs->version_major >= 3) ? SYS_TRUE : SYS_FALSE,
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
	if(record) {
		sys_free(&record);
	}

	return err ? -err : (size - context.size);
}

static int refs_fuse_op_statfs(const char *path, struct statvfs *stvbuf)
{
	memset(stvbuf, 0, sizeof(*stvbuf));

	return 0;
}

static int refs_fuse_op_release(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

static int refs_fuse_op_readdir_visit_directory_entry(
		void *context,
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
	(void) object_id;
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
		0,
		/* u64 allocated_size */
		0);
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

	err = refs_volume_lookup_by_posix_path(
		/* refs_volume *vol */
		vol,
		/* const char *path */
		path,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* u8 **out_record */
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
	visitor.node_file_entry = refs_fuse_op_readdir_visit_file_entry;
	visitor.node_directory_entry =
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
	return err;
}

struct fuse_operations refs_fuse_operations = {
	/* int (*getattr) (const char *, struct stat *) */
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
};

int main(int argc, char **argv)
{
	int err = 0;
	sys_device *dev = NULL;
	refs_volume *vol = NULL;

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
out:
	if(vol) {
		refs_volume_destroy(&vol);
	}

	if(dev) {
		sys_device_close(&dev);
	}

	return err ? (EXIT_FAILURE) : (EXIT_SUCCESS);
}
