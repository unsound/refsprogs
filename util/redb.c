/*-
 * redb.c - Print debug information about a ReFS volume.
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
#include "node.h"
#include "util.h"

/* Headers - ANSI C standard libraries. */
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#include "sys.h"

#define BINARY_NAME "redb"

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

static struct redb_options {
	const char *device_name;

	sys_bool boot_sector;
	sys_bool backup_boot_sector;
	sys_bool scan;
	sys_bool verbose;
	sys_bool about;
	sys_bool help;
} options;


static int generic_print_message(
		void *context,
		const char *format,
		...)
		__attribute__((format(printf, 2, 3)));


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

static void print_help(FILE *out)
{
	fprintf(out, "%s %s\n", BINARY_NAME, VERSION);
	fprintf(out, "usage: " BINARY_NAME " [-s] <device|file>\n");
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

	print_data_with_base(prefix, 1, 64, 512, bs->reserved64,
		sizeof(bs->reserved64));
#if 0
	emitln("%sBoot signature: 0x%" PRI0PAD(4) PRIX16,
		prefix, PRAX16(le16_to_cpu(bs->end_of_sector_signature)));
#endif
}

static int read_and_print_boot_sector(sys_device *const dev,
		REFS_BOOT_SECTOR *out_bs)
{
	int err = 0;
	u64 sector_offset = 0;
	REFS_BOOT_SECTOR bs;

	memset(&bs, 0, sizeof(bs));

	err = sys_device_pread(dev, sector_offset, sizeof(bs), &bs);
	if(err) {
		fprintf(stderr, "Error while reading %sboot sector from "
			"device: %s\n",
			"", strerror(err));
		goto out;
	}

	emitln("%s sector (physical sector %" PRIu64 " / 0x%" PRIX64 "):",
		"Boot", PRAu64(0), PRAX64(0));

	print_boot_sector(&bs);

	if(out_bs) {
		*out_bs = bs;
	}
out:
	return err;
}

static int print_message(
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

int main(int argc, char **argv)
{
	int err = 0;
	sys_device *dev = NULL;
	sys_bool dev_open = SYS_FALSE;

	while(argc > 2) {
		if(!strcmp(argv[1], "-s") ||
			(!strcmp(argv[1], "--scan")))
		{
			options.scan = SYS_TRUE;
			argv = &argv[1];
			argc -= 1;
		}
		else if(!strcmp(argv[1], "-v") ||
			(!strcmp(argv[1], "--verbose")))
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
		print_help(stderr);
		goto out;
	}

	options.device_name = argv[1];

	if(options.help) {
		print_help(stdout);
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

	{
		REFS_BOOT_SECTOR bs;

		memset(&bs, 0, sizeof(bs));

		err = read_and_print_boot_sector(
			/* sys_device *dev */
			dev,
			/* REFS_BOOT_SECTOR *out_bs */
			&bs);
		if(err) {
			goto out;
		}

		if(options.scan) {
			refs_node_scan_visitor visitor;

			memset(&visitor, 0, sizeof(visitor));

			visitor.print_visitor.verbose = options.verbose;
			visitor.print_visitor.print_message = print_message;

			err = refs_node_scan(
				/* sys_device *dev */
				dev,
				/* REFS_BOOT_SECTOR *bs */
				&bs,
				/* refs_node_walk_visitor *visitor */
				&visitor);
			if(err) {
				goto out;
			}
		}
		else {
			refs_node_walk_visitor visitor;

			memset(&visitor, 0, sizeof(visitor));

			visitor.print_visitor.verbose = options.verbose;
			visitor.print_visitor.print_message = print_message;

			err = refs_node_walk(
				/* sys_device *dev */
				dev,
				/* REFS_BOOT_SECTOR *bs */
				&bs,
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
				NULL,
				/* refs_node_walk_visitor *visitor */
				&visitor);
			if(err) {
				goto out;
			}
		}
	}
out:
	if(dev_open) {
		sys_device_close(&dev);
	}

	return err ? (EXIT_FAILURE) : (EXIT_SUCCESS);
}
