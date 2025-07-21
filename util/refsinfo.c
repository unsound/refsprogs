/*-
 * refsinfo.c - Print information about a ReFS volume.
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

/* Headers - librefs. */
#include "layout.h"
#include "volume.h"
#include "node.h"
#include "util.h"

/* Headers - ANSI C standard libraries. */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

#define BINARY_NAME "refsinfo"

#define emit_raw(format, ...) \
	fprintf(stdout, format, ##__VA_ARGS__)

#define vemit_raw(format, ap) \
	vfprintf(stdout, format, ap)

#define emitln(format, ...) \
	do { \
		emit_raw(format, ##__VA_ARGS__); \
		emit_raw("\n"); \
		fflush(stdout); \
	} while(0)

#define vemitln(format, ap) \
	do { \
		vemit_raw(format, ap); \
		emit_raw("\n"); \
		fflush(stdout); \
	} while(0)

typedef enum {
	INFO_TYPE_UNKNOWN,
	INFO_TYPE_VOLUME,
	INFO_TYPE_PATH,
	INFO_TYPE_NODE_NUMBER,
	INFO_TYPE_OBJECT_ID,
	INFO_TYPE_BOOT_SECTOR,
	INFO_TYPE_BACKUP_BOOT_SECTOR,
} refs_info_type;

static struct refsinfo_options {
	const char *device_name;

	sys_bool boot_sector;
	sys_bool backup_boot_sector;
	sys_bool path_defined;
	char *path;
	sys_bool node_number_defined;
	u64 node_number;
	sys_bool object_id_defined;
	u64 object_id;
	sys_bool verbose;
	sys_bool about;
	sys_bool help;
} options;


static int generic_print_message(
		void *context,
		const char *format,
		...)
		__attribute__((format(printf, 2, 3)));

static int print_object_id_info(
		refs_volume *const vol,
		const u64 object_id);


static refs_node_print_visitor generic_print_visitor = {
	.context = NULL,
	.print_message = generic_print_message,
	.verbose = SYS_FALSE,
};

static refs_node_print_visitor *const print_visitor = &generic_print_visitor;

static int generic_print_message(
		void *context,
		const char *format,
		...)
{
	va_list ap;

	(void) context;

	va_start(ap, format);
	vemitln(format, ap);
	va_end(ap);

	return 0;
}

static void print_help(FILE *out, const char *invoke_cmd)
{
	fprintf(out, "%s %s\n", BINARY_NAME, VERSION);
	fprintf(out, "usage: " BINARY_NAME " [-a] [-b] [-n <node number>] "
		"[-o <object ID>] [-p <path>] <device|file>\n");
}

static void print_about(FILE *out)
{
	fprintf(out, "%s %s\n", BINARY_NAME, VERSION);
	fprintf(out, "Copyright (c) 2022-2025 Erik Larsson\n");
}

static void print_boot_sector(REFS_BOOT_SECTOR *const bs)
{
	static const char *const prefix = "\t";

	emitln("%sJump instruction: 0x%" PRI0PAD(2) PRIX8 "%" PRI0PAD(2) PRIX8
		"%" PRI0PAD(2) PRIX8,
		prefix,
		PRAX8(bs->jump[0]), PRAX8(bs->jump[1]), PRAX8(bs->jump[2]));
	emitln("%sOEM ID: \"%" PRIbs "\"",
		prefix,
		PRAbs(8, bs->oem_id));
	emitln("%sReserved:", prefix);
	print_data(prefix, 1, bs->reserved7, sizeof(bs->reserved7));
	emitln("%sSignature: \"%" PRIbs "\"",
		prefix,
		PRAbs(4, bs->signature));
	emitln("%sUnknown @ 20:", prefix);
	print_data(prefix, 1, bs->reserved20, sizeof(bs->reserved20));
	emitln("%sNumber of sectors: %" PRIu64 " (%" PRIu64 " bytes)",
		prefix, PRAu64(le64_to_cpu(bs->num_sectors)),
		PRAu64(le32_to_cpu(bs->bytes_per_sector) *
		le64_to_cpu(bs->num_sectors)));
	emitln("%sBytes per sector: %" PRIu32 " bytes",
		prefix, PRAu32(le32_to_cpu(bs->bytes_per_sector)));
	emitln("%sSectors per cluster: %" PRIu32 " (%" PRIu64 " bytes)",
		prefix, PRAu32(le32_to_cpu(bs->sectors_per_cluster)),
		PRAu64(((u64) le32_to_cpu(bs->sectors_per_cluster)) *
		le32_to_cpu(bs->bytes_per_sector)));
	emitln("%sVersion: %" PRIu8 ".%" PRIu8,
		prefix,
		PRAu8(bs->version_major), PRAu8(bs->version_minor));
	print_unknown16(prefix, 0, bs, &bs->reserved42);
	print_unknown32(prefix, 0, bs, &bs->reserved44);
	print_unknown64(prefix, 0, bs, &bs->reserved48);
	emitln("%sSerial number: 0x%" PRIx64,
		prefix, PRAx64(le64_to_cpu(bs->serial_number)));

	if(options.verbose) {
		emitln("%sUnknown @ 64:", prefix);
		print_data(prefix, 1, bs->reserved64,
			sizeof(bs->reserved64));
	}
#if 0
	emitln("%sBoot signature: 0x%" PRI0PAD(4) PRIX16,
		prefix, PRAX16(le16_to_cpu(bs->end_of_sector_signature)));
#endif
}

static void print_volume_info(
		refs_volume *const vol)
{
	emitln("Volume information:");
	emitln("\tReFS version: %" PRIu8 ".%" PRIu8,
		PRAu8(vol->bs->version_major),
		PRAu8(vol->bs->version_minor));
	emitln("\tVolume serial number: %" PRI0PAD(16) PRIx64,
		PRAx64(le64_to_cpu(vol->bs->serial_number)));
	emitln("\tSector size: %" PRIu32,
		PRAu32(vol->sector_size));
	emitln("\tNumber of sectors: %" PRIu64,
		PRAu64(vol->sector_count));
	emitln("\tCluster size: %" PRIu32,
		PRAu32(vol->cluster_size));
	emitln("\tNumber of clusters: %" PRIu64,
		PRAu64(vol->cluster_count));
}

static int print_leaf_by_path_print_message(
		void *context,
		const char *format,
		...)
		__attribute__((format(printf, 2, 3)));

static int print_leaf_by_path_print_message(
		void *context,
		const char *format,
		...)
{
	va_list ap;

	(void) context;

	va_start(ap, format);
	vemitln(format, ap);
	va_end(ap);

	return 0;
}

static int print_leaf_by_path(
		refs_volume *const vol,
		const char *const path)
{
	int err = 0;

	u64 parent_directory_object_id = 0;
	u64 directory_object_id = 0;
	sys_bool is_short_entry = SYS_FALSE;
	u8 *record = NULL;
	size_t record_size = 0;
	u8 *key = NULL;
	size_t key_size = 0;
	refs_node_crawl_context crawl_context;
	refs_node_walk_visitor visitor;

	memset(&crawl_context, 0, sizeof(crawl_context));
	memset(&visitor, 0, sizeof(visitor));

	if(path[0] != '/') {
		fprintf(stderr, "Error: Path does not start with a '/'.\n");
		err = EINVAL;
		goto out;
	}

	err = refs_volume_lookup_by_posix_path(
		/* refs_volume *vol */
		vol,
		/* const char *path */
		path,
		/* size_t path_length */
		strlen(path),
		/* const u64 *start_object_id */
		NULL,
		/* u64 *out_parent_directory_object_id */
		&parent_directory_object_id,
		/* u64 *out_directory_object_id */
		&directory_object_id,
		/* sys_bool *out_is_short_entry */
		&is_short_entry,
		/* u8 *key */
		&key,
		/* size_t key_size */
		&key_size,
		/* u8 **out_record */
		&record,
		/* size_t *out_record_size */
		&record_size);
	if(err) {
		fprintf(stderr, "Encountered error while looking up \"%s\": "
			"%s\n",
			path, strerror(err));
		goto out;
	}

	if(!parent_directory_object_id) {
		fprintf(stderr, "Error: The path \"%s\" was not found in the "
			"filesystem.\n", path);
		err = EINVAL;
		goto out;
	}

	crawl_context = refs_volume_init_node_crawl_context(
		/* refs_volume *vol */
		vol);
	visitor.print_visitor.print_message = print_leaf_by_path_print_message;
	if(!record) {
		/* No record for this entry. Should only happen for the root
		 * directory. */
		fprintf(stdout, "Directory object ID: %" PRIu64 " / "
			"0x%" PRIX64 "\n",
			PRAu64(directory_object_id),
			PRAX64(directory_object_id));
	}
	else if(is_short_entry) {
		err = parse_level3_short_value(
			/* refs_node_crawl_context *crawl_context */
			&crawl_context,
			/* refs_node_walk_visitor *visitor */
			&visitor,
			/* const char *prefix */
			"",
			/* size_t indent */
			1,
			/* const u8 *key */
			key,
			/* u16 key_size */
			key_size,
			/* const u8 *value */
			record,
			/* u16 value_offset */
			0,
			/* u16 value_size */
			record_size,
			/* void *context */
			NULL);
		if(err) {
			sys_log_pwarning(err, "Error while parsing short "
				"value");
			err = 0;
		}
	}
	else {
		err = parse_level3_long_value(
			/* refs_node_crawl_context *crawl_context */
			&crawl_context,
			/* refs_node_walk_visitor *visitor */
			&visitor,
			/* const char *prefix */
			"",
			/* size_t indent */
			1,
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
		if(err) {
			sys_log_pwarning(err, "Error while parsing long value");
			err = 0;
		}
	}

	if(directory_object_id && options.verbose) {
		err = print_object_id_info(
			/* refs_volume *vol */
			vol,
			/* u64 object_id */
			directory_object_id);
		if(err) {
			goto out;
		}
	}
out:
	if(record) {
		sys_free(&record);
	}

	if(key) {
		sys_free(&key);
	}

	return err;
}

typedef struct {
	u64 requested_node_number;
	sys_bool output_enabled;
} print_node_number_info_context;

static int print_node_number_node_header(
		void *_context,
		u64 node_number,
		u64 node_first_cluster,
		u64 object_id,
		const u8 *data,
		size_t header_size)
{
	print_node_number_info_context *const context =
		(print_node_number_info_context*) _context;

	(void) node_first_cluster;
	(void) object_id;
	(void) data;
	(void) header_size;

	if(node_number == context->requested_node_number) {
		context->output_enabled = SYS_TRUE;
	}

	return 0;
}

static int print_node_number_print_message(
		void *context,
		const char *format,
		...)
		__attribute__((format(printf, 2, 3)));

static int print_node_number_print_message(
		void *_context,
		const char *format,
		...)
{
	print_node_number_info_context *const context =
		(print_node_number_info_context*) _context;

	int err = 0;
	va_list ap;

	if(!context->output_enabled) {
		/* We only want to emit information about the selected node
		 * number, so filter out all other output. */
		goto out;
	}


	va_start(ap, format);
	vemitln(format, ap);
	va_end(ap);
out:
	return err;
}

static int print_node_number_info(
		refs_volume *const vol,
		const u64 node_number)
{
	int err = 0;
	print_node_number_info_context context;
	refs_node_walk_visitor visitor;

	memset(&context, 0, sizeof(context));
	memset(&visitor, 0, sizeof(visitor));

	context.requested_node_number = node_number;

	visitor.context = &context;
	visitor.node_header = print_node_number_node_header;
	visitor.print_visitor.context = &context;
	visitor.print_visitor.print_message = print_node_number_print_message;

	err = refs_node_walk(
		/* sys_device *dev */
		vol->dev,
		/* REFS_BOOT_SECTOR *bs */
		vol->bs,
		/* REFS_SUPERBLOCK **bs */
		NULL,
		/* REFS_LEVEL1_NODE **primary_level1_node */
		NULL,
		/* REFS_LEVEL1_NODE **secondary_level1_node */
		NULL,
		/* refs_block_map **block_map */
		NULL,
		/* const u64 *start_node */
		&node_number,
		/* const u64 *object_id */
		NULL,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err) {
		fprintf(stderr, "Encountered error while walking the volume: "
			"%s\n",
			strerror(err));
		goto out;
	}
out:
	return err;
}

typedef struct {
	u64 requested_object_id;
	u64 cur_object_id;
	sys_bool found;
} print_object_id_info_context;

static int print_object_id_node_header(
		void *_context,
		u64 node_number,
		u64 node_first_cluster,
		u64 object_id,
		const u8 *data,
		size_t header_size)
{
	print_object_id_info_context *const context =
		(print_object_id_info_context*) _context;

	(void) node_number;
	(void) node_first_cluster;
	(void) data;
	(void) header_size;

	context->cur_object_id = object_id;
	if(object_id == context->requested_object_id) {
		context->found = SYS_TRUE;
	}

	return 0;
}

static int print_object_id_print_message(
		void *context,
		const char *format,
		...)
		__attribute__((format(printf, 2, 3)));

static int print_object_id_print_message(
		void *_context,
		const char *format,
		...)
{
	print_object_id_info_context *const context =
		(print_object_id_info_context*) _context;

	int err = 0;
	va_list ap;

	if(context->cur_object_id != context->requested_object_id) {
		/* We only want to emit information about the selected object
		 * ID, so filter out all other output. */
		goto out;
	}

	va_start(ap, format);
	vemitln(format, ap);
	va_end(ap);
out:
	return err;
}

static int print_object_id_info(
		refs_volume *const vol,
		const u64 object_id)
{
	int err = 0;
	print_object_id_info_context context;
	refs_node_walk_visitor visitor;

	memset(&context, 0, sizeof(context));
	memset(&visitor, 0, sizeof(visitor));

	context.requested_object_id = object_id;

	visitor.context = &context;
	visitor.node_header = print_object_id_node_header;
	visitor.print_visitor.context = &context;
	visitor.print_visitor.print_message = print_object_id_print_message;

	err = refs_node_walk(
		/* sys_device *dev */
		vol->dev,
		/* REFS_BOOT_SECTOR *bs */
		vol->bs,
		/* REFS_SUPERBLOCK **bs */
		NULL,
		/* REFS_LEVEL1_NODE **primary_level1_node */
		NULL,
		/* REFS_LEVEL1_NODE **secondary_level1_node */
		NULL,
		/* refs_block_map **block_map */
		NULL,
		/* const u64 *start_node */
		NULL,
		/* const u64 *object_id */
		&object_id,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err) {
		fprintf(stderr, "Error while walking the volume: %s\n",
			strerror(err));
		goto out;
	}

	if(!context.found) {
		fprintf(stderr, "Error: The object with ID %" PRIu64 " / "
			"0x%" PRIX64 " could not be found.\n",
			PRAu64(object_id), PRAX64(object_id));
		err = ENOENT;
	}
out:
	return err;
}

static int read_and_print_boot_sector(sys_device *const dev,
		const sys_bool is_backup, REFS_BOOT_SECTOR *out_bs)
{
	int err = 0;
	u64 sector_offset = 0;
	REFS_BOOT_SECTOR *bs = NULL;

	err = sys_calloc(sizeof(*bs), &bs);
	if(err) {
		sys_log_perror(err, "Error while allocating boot sector buffer");
		goto out;
	}

	err = sys_device_pread(dev, sector_offset, sizeof(*bs), bs);
	if(err) {
		fprintf(stderr, "Error while reading %sboot sector from "
			"device: %s\n",
			"", strerror(err));
		goto out;
	}

	if(is_backup) {
		/* The backup boot sector in ReFS is stored in the last sector
		 * of the volume. NOT the last sector of the partition as the
		 * volume ends earlier when the partition is not aligned to 64
		 * MiB (64 MiB is possibly not a constant, but it's what has
		 * been observed). */
		sys_bool boot_sector_valid = SYS_TRUE;
		u32 sector_size = 0;
		u64 device_size = 0;

		if(memcmp(bs->signature, "FSRS", 4)) {
			boot_sector_valid = SYS_FALSE;
		}
		else if(!le32_to_cpu(bs->bytes_per_sector) ||
			!le32_to_cpu(bs->sectors_per_cluster) ||
			!le64_to_cpu(bs->num_sectors))
		{
			boot_sector_valid = SYS_FALSE;
		}

		err = sys_device_get_sector_size(dev, &sector_size);
		if(err) {
			fprintf(stderr, "Error while querying the sector size "
				"(%s).%s\n",
				strerror(err),
				!boot_sector_valid ? "" : " Falling back on "
				"the boot sector value...");
			if(!boot_sector_valid) {
				goto out;
			}

			sector_size = le32_to_cpu(bs->bytes_per_sector);
		}

		err = sys_device_get_size(dev, &device_size);
		if(err) {
			fprintf(stderr, "Error while querying the device size: "
				"%s\n",
				strerror(err));
			goto out;
		}

		//boot_sector_valid = SYS_FALSE;
		if(!boot_sector_valid) {
			fprintf(stderr, "Invalid primary sector "
				"signature. Attempting to locate the "
				"backup boot sector at last 64 MiB "
				"boundary...\n");
			sector_offset =
				device_size -
				(device_size % (64UL * 1024UL * 1024UL)) -
				sector_size;
		}
		else {
			sector_offset =
				(le64_to_cpu(bs->num_sectors) - 1) *
				le32_to_cpu(bs->bytes_per_sector);
		}

		fprintf(stderr, "Reading backup boot sector from byte offset "
			"%" PRIu64 "...\n", PRAu64(sector_offset));

		memset(bs, 0, sizeof(*bs));

		err = sys_device_pread(dev, sector_offset, sizeof(*bs), bs);
		if(err) {
			fprintf(stderr, "Error while reading %sboot sector "
				"from device: %s\n",
				"backup ", strerror(err));
			goto out;
		}

	}

	emitln("%s sector:", is_backup ? "Backup boot" : "Boot");
	print_boot_sector(bs);

	if(out_bs) {
		*out_bs = *bs;
	}
out:
	if(bs) {
		sys_free(&bs);
	}

	return err;
}

int main(int argc, char **argv)
{
	const char *const cmd = argv[0];

	int err = 0;

	const char *conflicting_options_string[2] = { NULL, NULL };
	int conflicting_options = 0;

	refs_info_type info_type = INFO_TYPE_VOLUME;
	sys_device *dev = NULL;
	sys_bool dev_open = SYS_FALSE;
	refs_volume *vol = NULL;

	while(argc > 2) {
		if(!strcmp(argv[1], "-b") ||
			(!strcmp(argv[1], "--boot-sector")))
		{
			options.boot_sector = SYS_TRUE;
			info_type = INFO_TYPE_BOOT_SECTOR;
			argv = &argv[1];
			argc -= 1;
		}
		else if((!strcmp(argv[1], "-a") ||
			(!strcmp(argv[1], "--backup-boot-sector"))))
		{
			options.backup_boot_sector = SYS_TRUE;
			info_type = INFO_TYPE_BACKUP_BOOT_SECTOR;
			argv = &argv[1];
			argc -= 1;
		}
		else if(argc > 3 &&
			(!strcmp(argv[1], "-n") ||
			(!strcmp(argv[1], "--node-number"))))
		{
			options.node_number_defined = SYS_TRUE;
			errno = 0;
			options.node_number = strtoull(argv[2], NULL, 0);
			if(options.node_number == ULLONG_MAX && errno) {
				sys_log_perror(err, "Error while parsing node "
					"number");
				goto out;
			}
			info_type = INFO_TYPE_NODE_NUMBER;
			argv = &argv[2];
			argc -= 2;
		}
		else if(argc > 3 &&
			(!strcmp(argv[1], "-o") ||
			(!strcmp(argv[1], "--object-id"))))
		{
			options.object_id_defined = SYS_TRUE;
			errno = 0;
			options.object_id = strtoull(argv[2], NULL, 0);
			if(options.node_number == ULLONG_MAX && errno) {
				sys_log_perror(err, "Error while parsing "
					"object ID");
				goto out;
			}
			info_type = INFO_TYPE_OBJECT_ID;
			argv = &argv[2];
			argc -= 2;
		}
		else if(argc > 3 &&
			(!strcmp(argv[1], "-p") ||
			(!strcmp(argv[1], "--path"))))
		{
			options.path_defined = SYS_TRUE;
			options.path = argv[2];
			info_type = INFO_TYPE_PATH;
			argv = &argv[2];
			argc -= 2;
		}
		else if((!strcmp(argv[1], "-v") ||
			(!strcmp(argv[1], "--verbose"))))
		{
			options.verbose = SYS_TRUE;
			argv = &argv[1];
			argc -= 1;
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

	if(conflicting_options < 2 && options.boot_sector) {
		conflicting_options_string[conflicting_options++] =
			"'-b'/'--boot-sector'";
	}

	if(conflicting_options < 2 && options.backup_boot_sector) {
		conflicting_options_string[conflicting_options++] =
			"'-a'/'--backup-boot-sector'";
	}

	if(conflicting_options < 2 && options.node_number_defined) {
		conflicting_options_string[conflicting_options++] =
			"'-n'/'--node-number'";
	}

	if(conflicting_options < 2 && options.object_id_defined) {
		conflicting_options_string[conflicting_options++] =
			"'-o'/'--object-id'";
	}
	
	if(conflicting_options < 2 && options.path_defined) {
		conflicting_options_string[conflicting_options++] =
			"'-p'/'--path'";
	}

	if(conflicting_options > 1) {
		fprintf(stderr, "Error: Options %s and %s cannot both be "
			"specified.\n",
			conflicting_options_string[0],
			conflicting_options_string[1]);
		print_help(stderr, cmd);
		goto out;
	}

	options.device_name = argv[1];

	if(options.help) {
		print_help(stdout, cmd);
		goto out;
	}
	else if(options.about) {
		print_about(stdout);
		goto out;
	}

	err = sys_device_open(&dev, options.device_name);
	if(err) {
		fprintf(stderr, "Error while opening device \"%s\": %s\n",
			options.device_name, strerror(err));
		goto out;
	}

	dev_open = SYS_TRUE;

	if(info_type == INFO_TYPE_BOOT_SECTOR) {
		err = read_and_print_boot_sector(
			/* sys_device *dev */
			dev,
			/* sys_bool is_backup */
			SYS_FALSE,
			/* REFS_BOOT_SECTOR *out_bs */
			NULL);
	}
	else if(info_type == INFO_TYPE_BACKUP_BOOT_SECTOR) {
		err = read_and_print_boot_sector(
			/* sys_device *dev */
			dev,
			/* sys_bool is_backup */
			SYS_TRUE,
			/* REFS_BOOT_SECTOR *out_bs */
			NULL);
	}
	else {
		err = refs_volume_create(dev, &vol);
		if(err) {
			fprintf(stderr, "Error: Failed to open volume "
				"\"%s\".\n",
				options.device_name);
			goto out;
		}

		if(info_type == INFO_TYPE_VOLUME) {
			print_volume_info(vol);
		}
		else if(info_type == INFO_TYPE_PATH) {
			err = print_leaf_by_path(vol, options.path);
		}
		else if(info_type == INFO_TYPE_NODE_NUMBER) {
			err = print_node_number_info(vol, options.node_number);
		}
		else if(info_type == INFO_TYPE_OBJECT_ID) {
			err = print_object_id_info(vol, options.object_id);
		}
	}
out:
	if(vol) {
		refs_volume_destroy(&vol);
	}

	if(dev_open) {
		sys_device_close(&dev);
	}

	return err ? (EXIT_FAILURE) : (EXIT_SUCCESS);
}
