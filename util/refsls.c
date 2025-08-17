/*-
 * refsls.c - List files on an ReFS volume.
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
 * This is a simple utility that lists the files of the root or a user-specified
 * directory of a ReFS volume to stdout. Returns 0 on success and non-zero on
 * error.
 */

/* Headers - Autoconf-generated config.h, if present. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Headers - librefs. */
#include "volume.h"

/* Headers - ANSI C standard libraries. */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#define BINARY_NAME "refsls"

static struct refsls_options {
	char *device_name;
	char *path;
	sys_bool show_all;
	sys_bool show_eas;
	sys_bool show_streams;
	sys_bool long_format;
	sys_bool recursive;
	sys_bool about;
	sys_bool help;
} options;

static int refsls_node_long_entry(
		void *const context,
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
		const size_t record_size);

static int refsls_node_short_entry(
		void *const context,
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
		const size_t record_size);

static int refsls_node_ea(
		void *context,
		const char *name,
		size_t name_length,
		const void *data,
		size_t data_size);

static int refsls_node_stream(
		void *context,
		const char *name,
		size_t name_length,
		u64 data_size,
		const refs_node_stream_data *data_reference);

static int refsls_node_symlink(
		void *const context,
		const refs_symlink_type type,
		const char *const target,
		const size_t target_length);


static void print_help(FILE *out)
{
	fprintf(out, "%s %s\n", BINARY_NAME, VERSION);
	fprintf(out, "usage: " BINARY_NAME " [-a] [-e] [-l] [-R] [-p <path>] "
		"[-s] <device|file>\n");
}

static void print_about(FILE *out)
{
	fprintf(out, "%s %s\n", BINARY_NAME, VERSION);
	fprintf(out, "Copyright (c) 2022-2025 Erik Larsson\n");
}

typedef struct {
	refs_volume *vol;
	sys_bool first_line;
	sys_bool long_format;
	sys_bool show_eas;
	sys_bool show_streams;
	char *prefix;
	char *cur_name;
	size_t cur_name_length;
	u64 cur_hard_link_id;
} refsls_list_dir_fill_ctx;

static int refsls_print_dirent(
		void *const context,
		const sys_bool is_directory,
		const refschar *const name,
		const size_t name_len,
		const u32 file_flags,
		const u64 last_access_time,
		const u64 file_size,
		const u64 directory_object_id,
		const u64 hard_link_target_id)
{
	refsls_list_dir_fill_ctx *const ctx =
		(refsls_list_dir_fill_ctx*) context;

	int err = 0;

	char *cstr = NULL;
	size_t cstr_len = 0;

	if((file_flags & REFS_FILE_ATTRIBUTE_HIDDEN) && !options.show_all) {
		/* Ignore this entry. */
		goto out;
	}

	if(ctx->cur_name) {
		sys_free(&ctx->cur_name);
	}
	ctx->cur_name_length = 0;
	ctx->cur_hard_link_id = 0;

	if(name) {
		err = sys_unistr_decode(
			/* const refschar *ins */
			name,
			/* size_t ins_len */
			name_len,
			/* char **outs */
			&cstr,
			/* size_t *outs_len */
			&cstr_len);
		if(err) {
			fprintf(stderr, "Error: Failed to decode filename "
				"string.\n");
			goto out;
		}

		ctx->cur_name = cstr;
		ctx->cur_name_length = cstr_len;
	}
	else {
		ctx->cur_hard_link_id = hard_link_target_id;
	}


	{
		if(!ctx->first_line) {
			fprintf(stdout, "\n");
		}

		if(options.long_format) {
			static const s64 filetime_offset =
				((s64) (369 * 365 + 89)) * 24 * 3600 * 10000000;
			const sys_bool is_read_only =
				((file_flags & REFS_FILE_ATTRIBUTE_READONLY) ?
				SYS_TRUE : SYS_FALSE);
			const sys_bool is_hidden =
				((file_flags & REFS_FILE_ATTRIBUTE_HIDDEN) ?
				SYS_TRUE : SYS_FALSE);
			const sys_bool is_system =
				((file_flags & REFS_FILE_ATTRIBUTE_SYSTEM) ?
				SYS_TRUE : SYS_FALSE);
			const sys_bool is_archive =
				((file_flags & REFS_FILE_ATTRIBUTE_ARCHIVE) ?
				SYS_TRUE : SYS_FALSE);
			const time_t last_access_time_sec =
				(last_access_time - filetime_offset) / 10000000;
			struct tm *last_access_tm;

			memset(&last_access_tm, 0, sizeof(last_access_tm));

			fprintf(stdout, "%" PRIPAD(13) PRIu64,
				PRAu64(is_directory ? 0 : file_size));

			fprintf(stdout, " %c%c%c%c%c",
				is_archive   ? 'A' : '-',
				is_directory ? 'D' : '-',
				is_system    ? 'S' : '-',
				is_hidden    ? 'H' : '-',
				is_read_only ? 'R' : '-');

			last_access_tm = gmtime(&last_access_time_sec);

			fprintf(stdout, " %" PRI0PAD(4) PRId64 "-"
				"%" PRI0PAD(2) PRIu8 "-%" PRI0PAD(2) PRIu8 " "
				"%" PRI0PAD(2) PRIu8 ":"
				"%" PRI0PAD(2) PRIu8,
				PRAd64(1900 + last_access_tm->tm_year),
				PRAu8(1 + last_access_tm->tm_mon),
				PRAu8(last_access_tm->tm_mday),
				PRAu8(last_access_tm->tm_hour),
				PRAu8(last_access_tm->tm_min));

			fprintf(stdout, " ");
		}

		if(ctx->prefix) {
			fprintf(stdout, "%s/", ctx->prefix);
		}

		if(name) {
			fprintf(stdout, "%" PRIbs, PRAbs(cstr_len, cstr));
		}
		else {
			fprintf(stdout, "<Hard link entry with id "
				"0x%" PRIX64 ">", PRAX64(hard_link_target_id));
		}

		if(name && hard_link_target_id) {
			fprintf(stdout, " -> <Hard linked to id 0x%" PRIX64 " "
				"in directory 0x%" PRIX64 ">",
				PRAX64(hard_link_target_id),
				PRAX64(directory_object_id));
		}
	}

	ctx->first_line = SYS_FALSE;

	if(is_directory && (options.recursive ||
		(file_flags & REFS_FILE_ATTRIBUTE_REPARSE_POINT)))
	{
		refsls_list_dir_fill_ctx subdir_ctx;
		size_t subdir_prefix_string_length;
		size_t prev_prefix_length = 0;
		refs_node_walk_visitor subdir_visitor;

		memset(&subdir_ctx, 0, sizeof(subdir_ctx));
		memset(&subdir_visitor, 0, sizeof(subdir_visitor));

		subdir_ctx.vol = ctx->vol;
		subdir_ctx.long_format = ctx->long_format;
		subdir_ctx.show_eas = ctx->show_eas;
		subdir_ctx.show_streams = ctx->show_streams;
		subdir_ctx.prefix = NULL;

		/* Build the prefix string for the subdirectory's fill
		 * context. */
		if(ctx->prefix) {
			prev_prefix_length =
				strlen(ctx->prefix) + 1 /* '/' */;
		}

		subdir_prefix_string_length =
			prev_prefix_length + cstr_len + 1 /* '\0' */;

		err = sys_malloc(subdir_prefix_string_length,
			&subdir_ctx.prefix);
		if(err) {
			sys_log_perror(err, "Error while allocating "
				"subdirectory prefix string");
			goto out;
		}

		if(prev_prefix_length) {
			memcpy(subdir_ctx.prefix, ctx->prefix,
				prev_prefix_length - 1);
			subdir_ctx.prefix[prev_prefix_length - 1] = '/';
		}
		memcpy(&subdir_ctx.prefix[prev_prefix_length], cstr, cstr_len);
		subdir_ctx.prefix[prev_prefix_length + cstr_len] = '\0';

		subdir_visitor.context = &subdir_ctx;
		subdir_visitor.node_long_entry = refsls_node_long_entry;
		subdir_visitor.node_short_entry = refsls_node_short_entry;
		subdir_visitor.node_ea = refsls_node_ea;
		subdir_visitor.node_stream = refsls_node_stream;
		subdir_visitor.node_symlink = refsls_node_symlink;

		err = refs_node_walk(
			/* sys_device *dev */
			subdir_ctx.vol->dev,
			/* REFS_BOOT_SECTOR *bs */
			subdir_ctx.vol->bs,
			/* REFS_SUPERBLOCK_HEADER **sb */
			&subdir_ctx.vol->sb,
			/* REFS_LEVEL1_NODE **primary_level1_node */
			&subdir_ctx.vol->primary_level1_node,
			/* REFS_LEVEL1_NODE **secondary_level1_node */
			&subdir_ctx.vol->secondary_level1_node,
			/* refs_block_map **block_map */
			&subdir_ctx.vol->block_map,
			/* const u64 *start_node */
			NULL,
			/* const u64 *object_id */
			&directory_object_id,
			/* refs_node_walk_visitor *visitor */
			&subdir_visitor);
		if(err) {
			sys_log_perror(err, "Error while listing "
				"subdirectory");
		}

		sys_free(&subdir_ctx.prefix);

		if(err) {
			goto out;
		}
	}
out:
	return err;
}

static int refsls_node_long_entry(
		void *const context,
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
	int err = 0;

	(void) child_entry_offset;
	(void) parent_node_object_id;
	(void) create_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) allocated_size;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	err = refsls_print_dirent(
		/* void *context */
		context,
		/* sys_bool is_directory */
		SYS_FALSE,
		/* const refschar *name */
		file_name,
		/* size_t name_len */
		file_name_length,
		/* u32 file_flags */
		file_flags,
		/* u64 last_access_time */
		last_access_time,
		/* u64 file_size */
		file_size,
		/* u64 directory_object_id */
		0,
		/* u64 hard_link_target_id */
		0);

	return err;
}

static int refsls_node_short_entry(
		void *const context,
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
	int err = 0;

	(void) child_entry_offset;
	(void) parent_node_object_id;
	(void) create_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) allocated_size;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	err = refsls_print_dirent(
		/* void *const context */
		context,
		/* sys_bool is_directory */
		(file_flags & 0x10000000) ? SYS_TRUE : SYS_FALSE,
		/* const refschar *name */
		file_name,
		/* size_t name_len */
		file_name_length,
		/* u32 file_flags */
		file_flags,
		/* u64 last_access_time */
		last_access_time,
		/* u64 file_size */
		file_size,
		/* u64 directory_object_id */
		object_id,
		/* u64 hard_link_target_id */
		hard_link_id);

	return err;
}

static int refsls_node_hardlink_entry(
		void *context,
		u64 hard_link_id,
		u64 parent_id,
		const u16 child_entry_offset,
		u32 file_flags,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size,
		const u8 *const key,
		const size_t key_size,
		const u8 *record,
		size_t record_size)
{
	int err = 0;

	(void) child_entry_offset;
	(void) create_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) allocated_size;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	err = refsls_print_dirent(
		/* void *const context */
		context,
		/* sys_bool is_directory */
		(file_flags & 0x10000000) ? SYS_TRUE : SYS_FALSE,
		/* const refschar *name */
		NULL,
		/* size_t name_len */
		0,
		/* u32 file_flags */
		file_flags,
		/* u64 last_access_time */
		last_access_time,
		/* u64 file_size */
		file_size,
		/* u64 directory_object_id */
		parent_id,
		/* u64 hard_link_target_id */
		hard_link_id);

	return err;
}

static int refsls_node_ea(
		void *context,
		const char *name,
		size_t name_length,
		const void *data,
		size_t data_size)
{
	refsls_list_dir_fill_ctx *const ctx =
		(refsls_list_dir_fill_ctx*) context;

	(void) data;

	if(ctx->show_eas) {
		fprintf(stdout, "\n");

		if(ctx->long_format) {
			fprintf(stdout, "%" PRIPAD(13) PRIu64
				"                        ",
				PRAu64(data_size));
		}

		if(ctx->cur_name) {
			fprintf(stdout, "%s%s%" PRIbs ":$EA:%" PRIbs,
				ctx->prefix ? ctx->prefix : "",
				ctx->prefix ? "/" : "",
				PRAbs(ctx->cur_name_length, ctx->cur_name),
				PRAbs(name_length, name));
		}
		else {
			fprintf(stdout, "<Hard link entry with id "
				"0x%" PRIX64 ">:$EA:%" PRIbs,
				PRAX64(ctx->cur_hard_link_id),
				PRAbs(name_length, name));
		}
	}

	return 0;
}

static int refsls_node_stream(
		void *context,
		const char *name,
		size_t name_length,
		u64 data_size,
		const refs_node_stream_data *data_reference)
{
	refsls_list_dir_fill_ctx *const ctx =
		(refsls_list_dir_fill_ctx*) context;

	(void) data_reference;

	if(ctx->show_streams) {
		fprintf(stdout, "\n");

		if(ctx->long_format) {
			fprintf(stdout, "%" PRIPAD(13) PRIu64
				"                        ",
				PRAu64(data_size));
		}

		if(ctx->cur_name) {
			fprintf(stdout, "%s%s%" PRIbs ":%" PRIbs ":$DATA%s",
				ctx->prefix ? ctx->prefix : "",
				ctx->prefix ? "/" : "",
				PRAbs(ctx->cur_name_length, ctx->cur_name),
				PRAbs(name_length, name),
				data_reference->resident ? " (resident)" :
				" (non-resident)");
		}
		else {
			fprintf(stdout, "%s%s<Hard link entry with id "
				"0x%" PRIX64 ">:%" PRIbs ":$DATA%s",
				ctx->prefix ? ctx->prefix : "",
				ctx->prefix ? "/" : "",
				PRAX64(ctx->cur_hard_link_id),
				PRAbs(name_length, name),
				data_reference->resident ? " (resident)" :
				" (non-resident)");
		}
	}

	return 0;
}

static int refsls_node_symlink(
		void *const context,
		const refs_symlink_type type,
		const char *const target,
		const size_t target_length)
{
	(void) context;
	(void) type;

	fprintf(stdout, " -> %" PRIbs, PRAbs(target_length, target));

	return 0;
}

int main(int argc, char **argv)
{
	int err = 0;
	int ret = (EXIT_FAILURE);

	sys_device *dev = NULL;
	sys_bool dev_open = SYS_FALSE;
	refs_volume *vol = NULL;
	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;
	refs_node_walk_visitor visitor;
	refsls_list_dir_fill_ctx context;

	memset(&visitor, 0, sizeof(visitor));
	memset(&context, 0, sizeof(context));

	while(argc > 2) {
		if((!strcmp(argv[1], "-a") ||
			(!strcmp(argv[1], "--show-all"))))
		{
			options.show_all = SYS_TRUE;
			argv = &argv[1];
			argc -= 1;
		}
		else if((!strcmp(argv[1], "-e") ||
			(!strcmp(argv[1], "--show-eas"))))
		{
			options.show_eas = SYS_TRUE;
			argv = &argv[1];
			argc -= 1;
		}
		else if((!strcmp(argv[1], "-s") ||
			(!strcmp(argv[1], "--show-streams"))))
		{
			options.show_streams= SYS_TRUE;
			argv = &argv[1];
			argc -= 1;
		}
		else if(!strcmp(argv[1], "-l") ||
			(!strcmp(argv[1], "--long-format")))
		{
			options.long_format = SYS_TRUE;
			argv = &argv[1];
			argc -= 1;
		}
		else if(!strcmp(argv[1], "-R") ||
			(!strcmp(argv[1], "--recursive")))
		{
			options.recursive = SYS_TRUE;
			argv = &argv[1];
			argc -= 1;
		}
		else if(argc > 3 &&
			(!strcmp(argv[1], "-p") ||
			(!strcmp(argv[1], "--path"))))
		{
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

	err = sys_device_open(&dev, options.device_name);
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
	else if(!directory_object_id) {
		fprintf(stderr, "Error: The path \"%s\" resolves to a file.\n",
			options.path);
		goto out;
	}

	context.vol = vol;
	context.first_line = SYS_TRUE;
	context.long_format = options.long_format;
	context.show_eas = options.show_eas;
	context.show_streams = options.show_streams;
	visitor.context = &context;
	visitor.node_long_entry = refsls_node_long_entry;
	visitor.node_short_entry = refsls_node_short_entry;
	visitor.node_hardlink_entry = refsls_node_hardlink_entry;
	visitor.node_ea = refsls_node_ea;
	visitor.node_stream = refsls_node_stream;
	visitor.node_symlink = refsls_node_symlink;

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
		&directory_object_id,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err) {
		sys_log_perror(err, "Error while listing directory");
		goto out;
	}

	if(!context.first_line) {
		fprintf(stdout, "\n");
	}

	ret = (EXIT_SUCCESS);
out:
	if(context.cur_name) {
		sys_free(&context.cur_name);
	}

	if(vol) {
		refs_volume_destroy(&vol);
	}

	if(dev_open) {
		sys_device_close(&dev);
	}

	return ret;
}
