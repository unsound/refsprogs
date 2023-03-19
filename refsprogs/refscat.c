/*-
 * refscat.c - Print the data of a file on an ReFS volume to stdout.
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
	sys_bool about;
	sys_bool help;
} options;

static void print_help(FILE *out, const char *invoke_cmd)
{
	fprintf(out, BINARY_NAME " %s\n", VERSION);
	fprintf(out, "usage: " BINARY_NAME " <device|file>\n");
}

static void print_about(FILE *out)
{
	fprintf(out, BINARY_NAME " %s\n", VERSION);
	fprintf(out, "Copyright (c) 2022-2023 Erik Larsson\n");
}

typedef struct {
	refs_volume *vol;
	refschar *name;
	u16 name_length;
	sys_bool name_matches;
	u64 remaining_bytes;
} refscat_print_data_ctx;

static int refscat_node_file_extent(
		void *const _context,
		const u64 first_block,
		const u64 block_count,
		const u32 block_index_unit)
{
	refscat_print_data_ctx *const context =
		(refscat_print_data_ctx*) _context;

	int err = 0;

	if(context->name_matches) {
		char *buf = NULL;
		u64 extent_size = block_count * block_index_unit;
		u64 valid_extent_size =
			sys_min(extent_size, context->remaining_bytes);
		u64 cur_pos = first_block * block_index_unit;
		u64 bytes_remaining = valid_extent_size;
		size_t buf_size =
			(size_t) sys_min(valid_extent_size, 1024UL * 1024U);

		err = sys_malloc(buf_size, &buf);
		if(err) {
			sys_log_perror(err, "Error while allocating temporary "
				"buffer for printing data");
			goto out;
		}

		while(bytes_remaining) {
			const size_t bytes_to_read =
				(size_t) sys_min(bytes_remaining, buf_size);
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
			bytes_read = bytes_to_read;
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
		}
	}
out:
	return err;
}

static int refscat_node_file_entry(
		void *const _context,
		const refschar *const file_name,
		const u16 file_name_length,
		const u32 file_flags,
		const u64 create_time,
		const u64 last_access_time,
		const u64 last_write_time,
		const u64 last_mft_change_time,
		const u64 file_size,
		const u64 allocated_size,
		const u8 *const record,
		const size_t record_size)
{
	refscat_print_data_ctx *const context =
		(refscat_print_data_ctx*) _context;

	int err = 0;

	(void) file_flags;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) allocated_size;
	(void) record;
	(void) record_size;

	{
		char *cstr = NULL;
		size_t cstr_length = 0;

		sys_unistr_decode(file_name, file_name_length, &cstr,
			&cstr_length);
	}

	if(context->name_matches) {
		/* We have found our match, so break here. */
		return -1;
	}

	if(file_name_length == context->name_length &&
		!memcmp(file_name, context->name,
		file_name_length * sizeof(refschar)))
	{
		context->name_matches = SYS_TRUE;
		context->remaining_bytes = file_size;
	}

	return err;
}

int main(int argc, char **argv)
{
	const char *const cmd = argv[0];

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

	if(argc != 2) {
		print_help(stderr, cmd);
		goto out;
	}

	options.device_name = argv[1];

	if(options.help) {
		print_help(stdout, argv[0]);
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
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
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
		fprintf(stderr, "Error: The path \"%s\" is an invalid reference "
			"to a file.\n", options.path);
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
	visitor.context = &context;
	visitor.node_file_entry = refscat_node_file_entry;
	visitor.node_file_extent = refscat_node_file_extent;

	err = refs_node_walk(
		/* sys_device *dev */
		dev,
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

	if(!context.name_matches) {
		sys_log_error("Unable to find node \"%s\" in its parent "
			"directory", last_elementp);
		goto out;
	}
	else if(context.remaining_bytes) {
		sys_log_error("Unable to write all data to stdout: %" PRIu64 " "
			"bytes remaining after iterating over file extents.",
			PRAu64(context.remaining_bytes));
		goto out;
	}

	ret = (EXIT_SUCCESS);
out:
	if(dev_open) {
		sys_device_close(&dev);
	}

	return ret;
}
