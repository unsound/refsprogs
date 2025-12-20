/*-
 * refscat.c - Print the data of a file on an ReFS volume to stdout.
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

/*
 * This is a simple utility that looks up a file from a path and outputs its
 * data to stdout. Returns 0 on success and non-zero on error.
 */

/* Headers - Autoconf-generated config.h, if present. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Headers - librefs. */
#include "volume.h"
#include "sys.h"

/* Headers - ANSI C standard libraries. */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#define BINARY_NAME "refscat"

static struct refscat_options {
	char *device_name;
	sys_bool path_defined;
	char *path;
	sys_bool ea_defined;
	char *ea;
	sys_bool stream_defined;
	char *stream;
	sys_bool about;
	sys_bool help;
} options;

static void print_help(FILE *out)
{
	fprintf(out, BINARY_NAME " %s\n", VERSION);
	fprintf(out, "usage: " BINARY_NAME " -p <file path> [-e <ea name>] "
		"[-s <stream name>] <device|file>\n");
}

static void print_about(FILE *out)
{
	fprintf(out, BINARY_NAME " %s\n", VERSION);
	fprintf(out, "Copyright (c) 2022-2025 Erik Larsson\n");
}

typedef struct {
	refs_volume *vol;
	refschar *name;
	u16 name_length;
	char *ea_name;
	size_t ea_name_length;
	char *stream_name;
	size_t stream_name_length;
	sys_bool name_matches;
	sys_bool is_sparse;
	sys_bool is_hard_link;
	sys_bool hard_link_found;
	sys_bool stream_found;
	u64 hard_link_parent_object_id;
	u64 hard_link_id;
	u64 stream_non_resident_id;

	/* Stream state variables. */
	u64 cur_offset;
	u64 remaining_bytes;
} refscat_print_data_ctx;

static int refscat_node_file_extent(
		void *const _context,
		const u64 first_logical_block,
		const u64 first_physical_block,
		const u64 block_count,
		const u32 block_index_unit)
{
	refscat_print_data_ctx *const context =
		(refscat_print_data_ctx*) _context;

	int err = 0;
	size_t buf_size = 0;
	char *buf = NULL;

	if(context->name_matches &&
		(!context->is_hard_link || context->hard_link_found) &&
		!context->ea_name && !context->stream_name)
	{
		const u64 extent_logical_start =
			first_logical_block * block_index_unit;
		const u64 extent_size = block_count * block_index_unit;
		const u64 bytes_to_extent_end =
			(extent_logical_start + extent_size) -
			context->cur_offset;
		u64 cur_pos = first_physical_block * block_index_unit;
		u64 bytes_remaining =
			sys_min(bytes_to_extent_end, context->remaining_bytes);

		context->stream_found = SYS_TRUE;

		sys_log_debug("Got file extent - First logical block: "
			"%" PRIu64 " First physical block: %" PRIu64 " "
			"Block count: %" PRIu64,
			PRAu64(first_logical_block),
			PRAu64(first_physical_block), PRAu64(block_count));

		if(!context->is_sparse &&
			extent_logical_start > context->cur_offset)
		{
			sys_log_error("Missing region for non-sparse file: "
				"[%" PRIu64 " - %" PRIu64 "] (%" PRIu64 " "
				"bytes)",
				PRAu64(context->cur_offset),
				PRAu64(extent_logical_start),
				PRAu64(extent_logical_start -
				context->cur_offset));
			err = EIO;
			goto out;
		}

		buf_size =
			(size_t) sys_min(bytes_remaining, 4U * 1024UL * 1024U);
		err = sys_malloc(buf_size, &buf);
		if(err) {
			sys_log_perror(err, "Error while allocating temporary "
				"buffer for printing data");
			goto out;
		}

		while(bytes_remaining) {
			const size_t bytes_to_process =
				(size_t) sys_min(bytes_remaining, buf_size);
			const u64 bytes_to_extent =
				(extent_logical_start > context->cur_offset) ?
				extent_logical_start - context->cur_offset : 0;
			const size_t bytes_to_fill =
				(size_t) sys_min(bytes_to_extent,
				bytes_to_process);
			const size_t bytes_to_read =
				bytes_to_process - bytes_to_fill;

			ssize_t bytes_written = 0;

			sys_log_trace("[%" PRIu64 "] remaining: %" PRIu64 " "
				"(in extent: %" PRIu64 "), bytes_to_process: "
				"%" PRIuz ", bytes_to_fill: %" PRIuz ", "
				"bytes_to_read: %" PRIuz,
				PRAu64(context->cur_offset),
				PRAu64(context->remaining_bytes),
				PRAu64(bytes_remaining),
				PRAuz(bytes_to_process), PRAuz(bytes_to_fill),
				PRAuz(bytes_to_read));

			if(bytes_to_fill) {
				memset(buf, 0, bytes_to_fill);
			}

			if(bytes_to_read) {
				err = sys_device_pread(
					/* sys_device *dev */
					context->vol->dev,
					/* u64 pos */
					cur_pos,
					/* size_t count */
					bytes_to_read,
					/* void *b */
					&buf[bytes_to_fill]);
				if(err) {
					sys_log_perror(err, "Error while "
						"reading data from device "
						"offset %" PRIu64,
						PRAu64(cur_pos));
					goto out;
				}
			}

			/* sys_device_pread ensures that we always read all of
			 * the requested data or an error is thrown. */
			context->remaining_bytes -= bytes_to_process;
			context->cur_offset += bytes_to_process;

			bytes_written = write(STDOUT_FILENO, buf,
				bytes_to_process);
			if(bytes_written < 0) {
				err = (err = errno) ? err : EIO;;
				sys_log_perror(err, "Error while writing "
					"%" PRIuz " bytes to stdout",
					PRAuz(bytes_to_process));
				goto out;
			}
			else if((size_t) bytes_written != bytes_to_process) {
				sys_log_perror(errno, "Partial write of file "
					"data to stdout: %" PRIuz " / "
					"%" PRIuz " bytes written",
					PRAuz((size_t) bytes_written),
					PRAuz(bytes_to_process));
				err = EIO;
				goto out;
			}

			if(bytes_remaining == bytes_to_process) {
				break;
			}

			cur_pos += bytes_to_read;
			bytes_remaining -= bytes_to_process;
		}
	}
out:
	if(buf) {
		sys_free(buf_size, &buf);
	}

	return err;
}

static int refscat_node_file_data(
		void *const _context,
		const void *const data,
		const size_t size)
{
	refscat_print_data_ctx *const context =
		(refscat_print_data_ctx*) _context;

	int err = 0;

	if(context->name_matches &&
		(!context->is_hard_link || context->hard_link_found) &&
		!context->ea_name && !context->stream_name)
	{
		ssize_t bytes_written = 0;

		context->stream_found = SYS_TRUE;
		context->remaining_bytes -= size;

		bytes_written = write(STDOUT_FILENO, data, size);
		if(bytes_written < 0) {
			err = (err = errno) ? err : EIO;
			sys_log_perror(err, "Error while writing "
				"%" PRIuz " bytes to stdout",
				PRAuz(size));
			goto out;
		}
		else if((size_t) bytes_written != size) {
			err = EIO;
			sys_log_perror(errno, "Partial write of file "
				"data to stdout: %" PRIuz " / "
				"%" PRIuz " bytes written",
				PRAuz((size_t) bytes_written),
				PRAuz(size));
			goto out;
		}
	}
out:
	return err;
}

static int refscat_node_long_entry(
		void *const _context,
		const refschar *const file_name,
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
	refscat_print_data_ctx *const context =
		(refscat_print_data_ctx*) _context;

	int err = 0;

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

	if(context->name_matches) {
		/* We have found our match, so break here. */
		return -1;
	}

	if(file_name_length == context->name_length &&
		!memcmp(file_name, context->name,
		file_name_length * sizeof(refschar)))
	{
		context->name_matches = SYS_TRUE;
		if(!(context->ea_name || context->stream_name)) {
			context->remaining_bytes = file_size;
		}

		if(!context->ea_name && !context->stream_name &&
			(file_flags & REFS_FILE_ATTRIBUTE_SPARSE_FILE))
		{
			context->is_sparse = SYS_TRUE;
		}
	}

	return err;
}

static int refscat_node_short_entry(
		void *_context,
		const le16 *file_name,
		u16 file_name_length,
		const u16 child_entry_offset,
		u32 file_flags,
		const u64 node_number,
		const u64 parent_node_object_id,
		u64 object_id,
		u64 hard_link_id,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		const u64 file_size,
		const u64 allocated_size,
		const u8 *const key,
		const size_t key_size,
		const u8 *record,
		size_t record_size)
{
	refscat_print_data_ctx *const context =
		(refscat_print_data_ctx*) _context;

	(void) child_entry_offset;
	(void) file_flags;
	(void) node_number;
	(void) parent_node_object_id;
	(void) object_id;
	(void) hard_link_id;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) allocated_size;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	if(context->name_matches) {
		/* We have found our match, so break here. */
		return -1;
	}

	if(file_name_length == context->name_length &&
		!memcmp(file_name, context->name,
		file_name_length * sizeof(refschar)))
	{
		context->name_matches = SYS_TRUE;
		if(hard_link_id) {
			sys_log_debug("Got short entry for hard link with id "
				"%" PRIu64 " / parent %" PRIu64,
				PRAu64(hard_link_id), PRAu64(object_id));
			if(context->is_hard_link) {
				sys_log_critical("Got short entry but we are "
					"already hardlinked? Internal error.");
				return EIO;
			}
			context->is_hard_link = SYS_TRUE;
			context->hard_link_id = hard_link_id;
			context->hard_link_parent_object_id = object_id;
		}
		else if(!(context->ea_name || context->stream_name)) {
			context->remaining_bytes = file_size;
		}

		/* We don't expect anything else of interest here. This is a
		 * short value and doesn't have any attributes. So break. */
		return -1;
	}

	return 0;
}

static int refscat_node_hardlink_entry(
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
	refscat_print_data_ctx *const context =
		(refscat_print_data_ctx*) _context;

	int err = 0;

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

	if(context->hard_link_found) {
		/* We have found our match, so break here. */
		return -1;
	}

	sys_log_debug("Got hardlink entry with id: %" PRIu64 " / parent: "
		"%" PRIu64, PRAu64(hard_link_id), PRAu64(parent_id));
	if(context->hard_link_id == hard_link_id &&
		context->hard_link_parent_object_id == parent_id)
	{
		context->hard_link_found = SYS_TRUE;

		if(!(context->ea_name || context->stream_name)) {
			context->remaining_bytes = file_size;
		}
	}

	return err;
}

static int refscat_node_ea(
		void *_context,
		const char *name,
		size_t name_length,
		const void *data,
		size_t data_size)
{
	refscat_print_data_ctx *const context =
		(refscat_print_data_ctx*) _context;
	int err = 0;

	if(context->name_matches &&
		(!context->is_hard_link || context->hard_link_found) &&
		name_length == context->ea_name_length &&
		!memcmp(name, context->ea_name, name_length))
	{
		ssize_t bytes_written = 0;

		context->stream_found = SYS_TRUE;
		context->remaining_bytes = data_size;

		bytes_written = write(STDOUT_FILENO, data, data_size);
		if(bytes_written < 0) {
			err = (err = errno) ? err : EIO;
			sys_log_perror(err, "Error while writing "
				"%" PRIuz " bytes to stdout",
				PRAuz(data_size));
			goto out;
		}
		else if((size_t) bytes_written != data_size) {
			err = EIO;
			sys_log_perror(errno, "Partial write of file "
				"data to stdout: %" PRIuz " / "
				"%" PRIuz " bytes written",
				PRAuz((size_t) bytes_written),
				PRAuz(data_size));
			goto out;
		}

		context->remaining_bytes -= data_size;
	}
out:
	return err;	
}

static int refscat_node_stream(
		void *_context,
		const char *name,
		size_t name_length,
		u64 data_size,
		const refs_node_stream_data *data_reference)
{
	refscat_print_data_ctx *const context =
		(refscat_print_data_ctx*) _context;
	int err = 0;

	if(!context->name_matches ||
		(context->is_hard_link && !context->hard_link_found) ||
		name_length != context->stream_name_length ||
		memcmp(name, context->stream_name, name_length))
	{
		/* No match. */
		goto out;
	}

	context->stream_found = SYS_TRUE;
	if(!context->remaining_bytes) {
		context->remaining_bytes = data_size;
	}

	if(data_reference->resident) {
		ssize_t bytes_written = 0;

		sys_log_debug("Writing %" PRIuz " bytes of resident data to "
			"stdout.", PRAuz(data_size));
		bytes_written = write(STDOUT_FILENO,
			data_reference->data.resident, data_size);
		if(bytes_written < 0) {
			err = (err = errno) ? err : EIO;
			sys_log_perror(err, "Error while writing "
				"%" PRIuz " bytes to stdout",
				PRAuz(data_size));
			goto out;
		}
		else if((size_t) bytes_written != data_size) {
			err = EIO;
			sys_log_perror(errno, "Partial write of file "
				"data to stdout: %" PRIuz " / "
				"%" PRIuz " bytes written",
				PRAuz((size_t) bytes_written),
				PRAuz(data_size));
			goto out;
		}

		context->remaining_bytes -= data_size;
	}
	else {
		context->stream_non_resident_id =
			data_reference->data.non_resident.stream_id;
	}
out:
	return err;
}

static int refscat_node_stream_extent(
		void *_context,
		u64 stream_id,
		u64 first_logical_block,
		u64 first_physical_block,
		u32 block_index_unit,
		u32 cluster_count)
{
	refscat_print_data_ctx *const context =
		(refscat_print_data_ctx*) _context;
	const u64 extent_size = cluster_count * context->vol->cluster_size;
	const u64 valid_extent_size =
		sys_min(extent_size, context->remaining_bytes);
	const u64 aligned_extent_size =
		(valid_extent_size + (context->vol->sector_size - 1)) &
		~((u64) (context->vol->sector_size - 1));
	const size_t buf_size =
		(size_t) sys_min(aligned_extent_size, 1024UL * 1024U);

	int err = 0;
	char *buf = NULL;
	u64 cur_pos = first_physical_block * block_index_unit;
	u64 bytes_remaining = valid_extent_size;
	u64 aligned_bytes_remaining = aligned_extent_size;

	/* XXX: Can stream extents be sparse? */
	(void) first_logical_block;

	sys_log_debug("Got stream extent with stream id 0x%" PRIX64 ", first "
		"block 0x%" PRIX64 "...",
		PRAX64(stream_id), PRAX64(first_physical_block));

	if(stream_id != context->stream_non_resident_id) {
		/* Not the stream that we are looking for. */
		goto out;
	}

	sys_log_debug("Reading %" PRIuz " bytes (%" PRIuz " sector-aligned "
		"bytes) of non-resident named stream data from block "
		"%" PRIu64 " / 0x%" PRIX64 " to stdout.",
		PRAuz(bytes_remaining), PRAuz(aligned_bytes_remaining),
		PRAu64(first_physical_block), PRAX64(first_physical_block));

	err = sys_malloc(buf_size, &buf);
	if(err) {
		sys_log_perror(err, "Error while allocating temporary "
			"buffer for printing data");
		goto out;
	}

	while(bytes_remaining) {
		const size_t bytes_to_read =
			(size_t) sys_min(aligned_bytes_remaining, buf_size);
		size_t bytes_read = 0;
		ssize_t bytes_written = 0;

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
			sys_log_perror(err, "Error while reading data "
				"from device offset %" PRIu64,
				PRAu64(cur_pos));
			goto out;
		}

		/* sys_device_pread ensures that we always read all of
		 * the requested data or an error is thrown. */
		bytes_read =
			(bytes_to_read > bytes_remaining) ?
			bytes_remaining : bytes_to_read;
		context->remaining_bytes -= bytes_read;

		bytes_written = write(STDOUT_FILENO, buf, bytes_read);
		if(bytes_written < 0) {
			err = errno;
			sys_log_perror(err, "Error while writing "
				"%" PRIuz " bytes to stdout",
				PRAuz(bytes_read));
			goto out;
		}
		else if((size_t) bytes_written != bytes_read) {
			sys_log_perror(errno, "Partial write of file "
				"data to stdout: %" PRIuz " / "
				"%" PRIuz " bytes written",
				PRAuz((size_t) bytes_written),
				PRAuz(bytes_read));
			goto out;
		}

		if(bytes_remaining == bytes_read) {
			break;
		}

		cur_pos += bytes_read;
		bytes_remaining -= bytes_read;
		aligned_bytes_remaining -= bytes_read;
	}
out:
	if(buf) {
		sys_free(buf_size, &buf);
	}

	return err;
}

int main(int argc, char **argv)
{
	int err = 0;
	int ret = (EXIT_FAILURE);

	sys_device *dev = NULL;
	sys_bool dev_open = SYS_FALSE;
	refs_volume *vol = NULL;
	const char *pathp = NULL;
	const char *last_elementp = NULL;
	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;
	refscat_print_data_ctx context;
	size_t name_length = 0;
	refs_node_walk_visitor visitor;

	memset(&context, 0, sizeof(context));
	memset(&visitor, 0, sizeof(visitor));

	while(argc > 2) {
		if(argc > 3 &&
			(!strcmp(argv[1], "-p") ||
			(!strcmp(argv[1], "--path"))))
		{
			options.path_defined = SYS_TRUE;
			options.path = argv[2];
			argv = &argv[2];
			argc -= 2;
		}
		else if(argc > 3 &&
			(!strcmp(argv[1], "-e") ||
			(!strcmp(argv[1], "--ea"))))
		{
			options.ea_defined = SYS_TRUE;
			options.ea = argv[2];
			argv = &argv[2];
			argc -= 2;
		}
		else if(argc > 3 &&
			(!strcmp(argv[1], "-s") ||
			(!strcmp(argv[1], "--stream"))))
		{
			options.stream_defined = SYS_TRUE;
			options.stream = argv[2];
			argv = &argv[2];
			argc -= 2;
		}
		else if((!strcmp(argv[1], "-h") ||
			!strcmp(argv[1], "--help")))
		{
			options.help = SYS_TRUE;
			argv = &argv[1];
			argc -= 1;
		}
		else if(!strcmp(argv[1], "--about")) {
			options.about = SYS_TRUE;
			argv = &argv[1];
			argc -= 1;
		}
		else if(!strcmp(argv[1], "--")) {
			argv = &argv[1];
			argc -= 1;
			break;
		}
		else {
			break;
		}
	}

	if(argc != 2 || !options.path) {
		print_help(stderr);
		goto out;
	}
	else if(options.ea_defined && options.stream_defined) {
		fprintf(stderr, "Error: Cannot specify both EA and stream.\n");
		print_help(stderr);
		goto out;
	}

	options.device_name = argv[1];

	if(options.help) {
		print_help(stdout);
		ret = (EXIT_SUCCESS);
		goto out;
	}
	else if(options.about) {
		print_about(stdout);
		ret = (EXIT_SUCCESS);
		goto out;
	}

	err = sys_device_open(
		/* sys_device **dev */
		&dev,
		/* const char *path */
		options.device_name);
	if(err) {
		fprintf(stderr, "Error while opening device \"%s\": %s\n",
			options.device_name, strerror(err));
		goto out;
	}

	dev_open = SYS_TRUE;

	err = refs_volume_create(
		/* sys_device *dev */
		dev,
		/* refs_volume **out_vol */
		&vol);
	if(err) {
		fprintf(stderr, "Error while opening volume \"%s\": %s\n",
			options.device_name, strerror(err));
		goto out;
	}

	for(pathp = options.path; *pathp; ++pathp) {
		if(*pathp == '/') {
			last_elementp = &pathp[1];
		}
	}

	err = refs_volume_lookup_by_posix_path(
		/* refs_volume *vol */
		vol,
		/* const char *path */
		options.path ? options.path : "/",
		/* size_t path_length */
		options.path ? strlen(options.path) : 1,
		/* const u64 *start_object_id */
		NULL,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* sys_bool *out_is_short_entry */
		NULL,
		/* u64 *out_node_number */
		NULL,
		/* u16 *out_entry_offset */
		NULL,
		/* u8 *key */
		NULL,
		/* size_t key_size */
		NULL,
		/* u8 **out_record */
		NULL,
		/* size_t *out_record_size */
		NULL);
	if(err) {
		sys_log_perror(err, "Error while looking up path \"%s\"",
			options.path);
		goto out;
	}
	else if(!parent_directory_object_id) {
		fprintf(stderr, "Error: The path \"%s\" was not found in the "
			"filesystem.\n", options.path);
		goto out;
	}
	else if(directory_object_id) {
		fprintf(stderr, "Error: The path \"%s\" resolves to a "
			"directory.\n", options.path);
		goto out;
	}

	if(!last_elementp || !*last_elementp) {
		fprintf(stderr, "Error: The path \"%s\" is an invalid "
			"reference to a file.\n", options.path);
		goto out;
	}

	err = sys_unistr_encode(
		/* const char *mbstr */
		last_elementp,
		/* size_t mbstr_len */
		strlen(last_elementp),
		/* refschar **utf16str */
		&context.name,
		/* size_t *utf16str_len */
		&name_length);
	if(err) {
		sys_log_perror(err, "Error while encoding the last pathname "
			"component \"%s\" as UTF-16LE", last_elementp);
		goto out;
	}
	else if(name_length > UINT16_MAX) {
		sys_log_error("Invalid filename: \"%s\"", last_elementp);
		goto out;
	}

	context.vol = vol;
	context.name_length = (u16) name_length;
	context.ea_name = options.ea_defined ? options.ea : NULL;
	context.ea_name_length = options.ea_defined ? strlen(options.ea) : 0;
	context.stream_name = options.stream_defined ? options.stream : NULL;
	context.stream_name_length =
		options.stream_defined ? strlen(options.stream) : 0;
	visitor.context = &context;
	visitor.node_long_entry = refscat_node_long_entry;
	visitor.node_short_entry = refscat_node_short_entry;
	visitor.node_file_data = refscat_node_file_data;
	visitor.node_file_extent = refscat_node_file_extent;
	visitor.node_ea = refscat_node_ea;
	visitor.node_stream = refscat_node_stream;

#ifdef O_BINARY
	setmode(fileno(stdout), O_BINARY);
#endif

	err = refs_node_walk(
		/* sys_device *dev */
		dev,
		/* const REFS_BOOT_SECTOR *bs */
		vol->bs,
		/* REFS_SUPERBLOCK_HEADER **sb */
		&vol->sb,
		/* REFS_LEVEL1_NODE **primary_level1_node */
		&vol->primary_level1_node,
		/* REFS_LEVEL1_NODE **secondary_level1_node */
		&vol->secondary_level1_node,
		/* refs_block_map **block_map */
		&vol->block_map,
		/* refs_node_cache **node_cache */
		NULL,
		/* const u64 *start_node */
		NULL,
		/* const u64 *object_id */
		&parent_directory_object_id,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err == -1) {
		/* Manual break code, this one is expected. */
		err = 0;
	}
	else if(err) {
		sys_log_perror(err, "Error while listing directory");
		goto out;
	}

	if(context.is_hard_link) {
		/* We encountered a hard linked entry. Iterate over the node
		 * again to find the hard link target. */

		parent_directory_object_id = context.hard_link_parent_object_id;

		visitor.context = &context;
		visitor.node_short_entry = NULL;
		visitor.node_long_entry = NULL;
		visitor.node_hardlink_entry = refscat_node_hardlink_entry;

		sys_log_debug("Walking directory 0x%" PRIX64 " to find hard "
			"link target for id 0x%" PRIX64 "...",
			PRAX64(context.hard_link_parent_object_id),
			PRAX64(context.hard_link_id));
		err = refs_node_walk(
			/* sys_device *dev */
			dev,
			/* const REFS_BOOT_SECTOR *bs */
			vol->bs,
			/* REFS_SUPERBLOCK_HEADER **sb */
			&vol->sb,
			/* REFS_LEVEL1_NODE **primary_level1_node */
			&vol->primary_level1_node,
			/* REFS_LEVEL1_NODE **secondary_level1_node */
			&vol->secondary_level1_node,
			/* refs_block_map **block_map */
			&vol->block_map,
			/* refs_node_cache **node_cache */
			NULL,
			/* const u64 *start_node */
			NULL,
			/* const u64 *object_id */
			&parent_directory_object_id,
			/* refs_node_walk_visitor *visitor */
			&visitor);
		if(err == -1) {
			/* Manual break code, this one is expected. */
			err = 0;
		}
		else if(err) {
			sys_log_perror(err, "Error while listing directory");
			goto out;
		}

		if(!context.hard_link_found) {
			sys_log_error("Unable to find hard link with id "
				"0x%" PRIX64 " in parent directory "
				"0x%" PRIX64 ".",
				PRAX64(context.hard_link_id),
				PRAX64(context.hard_link_parent_object_id));
			goto out;
		}
	}

	if(context.stream_non_resident_id) {
		/* We encountered a non-resident stream. Iterate again to find
		 * its associated stream extents. */
		memset(&visitor, 0, sizeof(visitor));
		visitor.context = &context;
		visitor.node_stream_extent = refscat_node_stream_extent;

		sys_log_debug("Walking the tree a second time to find "
			"non-resident stream data for id %" PRIX64 "...",
			PRAX64(context.stream_non_resident_id));
		err = refs_node_walk(
			/* sys_device *dev */
			dev,
			/* const REFS_BOOT_SECTOR *bs */
			vol->bs,
			/* REFS_SUPERBLOCK_HEADER **sb */
			&vol->sb,
			/* REFS_LEVEL1_NODE **primary_level1_node */
			&vol->primary_level1_node,
			/* REFS_LEVEL1_NODE **secondary_level1_node */
			&vol->secondary_level1_node,
			/* refs_block_map **block_map */
			&vol->block_map,
			/* refs_node_cache **node_cache */
			NULL,
			/* const u64 *start_node */
			NULL,
			/* const u64 *object_id */
			&parent_directory_object_id,
			/* refs_node_walk_visitor *visitor */
			&visitor);
		if(err == -1) {
			/* Manual break code, this one is expected. */
			err = 0;
		}
		else if(err) {
			sys_log_perror(err, "Error while listing directory");
			goto out;
		}
	}

	if(!context.name_matches) {
		sys_log_error("Unable to find node \"%s\" in its parent "
			"directory", last_elementp);
		goto out;
	}
	else if(!context.is_sparse && !context.stream_found) {
		fprintf(stderr, "Unable to find %s stream%s%" PRIbs "%s in "
			"node \"%s\".\n",
			(context.ea_name ? "$EA" :
			(context.stream_name ? "named" : "data")),
			(context.ea_name || context.stream_name) ? " \"" : "",
			PRAbs((context.ea_name || context.stream_name) ?
				(context.ea_name ? context.ea_name_length :
				context.stream_name_length) : 0,
			(context.ea_name || context.stream_name) ?
				(context.ea_name ? context.ea_name :
				context.stream_name) : ""),
			(context.ea_name || context.stream_name) ? "\"" : "",
			options.path);
		goto out;
	}
	else if(context.remaining_bytes) {
		if(!context.is_sparse) {
			sys_log_error("Unable to write all data to stdout: "
				"%" PRIu64 " bytes remaining after iterating "
				"over file extents.",
				PRAu64(context.remaining_bytes));
			goto out;
		}
		else {
			/* Simulate final 0-block extent to fill the tail
			 * part. */
			const u32 block_index_unit =
				(vol->bs->version_major == 1) ? 16384 :
				vol->cluster_size;

			err = refscat_node_file_extent(
				/* void *context */
				&context,
				/* u64 first_logical_block */
				(context.cur_offset + context.remaining_bytes +
				(block_index_unit - 1)) / block_index_unit,
				/* u64 first_physical_block */
				0,
				/* u64 block_count */
				0,
				/* u32 block_index_unit */
				block_index_unit);
			if(err) {
				goto out;
			}
		}
	}

	ret = (EXIT_SUCCESS);
out:
	if(context.name) {
		sys_free(context.name_length + 1, &context.name);
	}

	if(vol) {
		refs_volume_destroy(&vol);
	}

	if(dev_open) {
		sys_device_close(&dev);
	}

	return ret;
}
