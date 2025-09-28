/*-
 * refslabel.c - Print the volume label of a ReFS volume.
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

/* Headers - ANSI C standard libraries. */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#define BINARY_NAME "refslabel"

static struct refslabel_options {
	const char *device_name;
	sys_bool about;
	sys_bool help;
} options;

static void print_help(FILE *out)
{
	fprintf(out, "%s %s\n", BINARY_NAME, VERSION);
	fprintf(out, "usage: " BINARY_NAME " <device|file>\n");
}

static void print_about(FILE *out)
{
	fprintf(out, "%s %s\n", BINARY_NAME, VERSION);
	fprintf(out, "Copyright (c) 2022-2025 Erik Larsson\n");
}

static int refslabel_node_volume_label_entry(
		void *const context,
		const refschar *const volume_label,
		const u16 volume_label_length)
{
	int err = 0;
	char *volume_label_cstr = NULL;
	size_t volume_label_cstr_length = 0;

	(void) context;

	err = sys_unistr_decode(
		volume_label,
		volume_label_length,
		&volume_label_cstr,
		&volume_label_cstr_length);
	if(err) {
		goto out;
	}

	fprintf(stdout, "%" PRIbs "\n",
		PRAbs(volume_label_cstr_length, volume_label_cstr));
	sys_free(&volume_label_cstr);
	err = -1;
out:
	return err;
}

int main(int argc, char **argv)
{
	int err = 0;

	sys_device *dev = NULL;
	sys_bool dev_open = SYS_FALSE;
	refs_volume *vol = NULL;
	refs_node_walk_visitor visitor;
	u64 object_id = 0;

	memset(&visitor, 0, sizeof(visitor));

	while(argc > 2) {
		if((!strcmp(argv[1], "-h") ||
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

	err = refs_volume_create(dev, &vol);
	if(err) {
		fprintf(stderr, "Error: Failed to open volume \"%s\".\n",
			options.device_name);
		goto out;
	}

	visitor.node_volume_label_entry = refslabel_node_volume_label_entry;

	/* Look up node 0x500 where the volume label resides. */
	object_id = 0x500;

	err = refs_node_walk(
		/* sys_device *dev */
		dev,
		/* REFS_BOOT_SECTOR *bs */
		vol->bs,
		/* REFS_SUPERBLOCK_HEADER **sb */
		NULL,
		/* REFS_LEVEL1_NODE **primary_level1_node */
		NULL,
		/* REFS_LEVEL1_NODE **secondary_level1_node */
		NULL,
		/* refs_block_map **block_map */
		NULL,
		/* refs_node_cache **node_cache */
		NULL,
		/* const u64 *start_node */
		NULL,
		/* const u64 *object_id */
		&object_id,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err == -1) {
		/* Manual break. */
		err = 0;
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
