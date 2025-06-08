/*-
 * search_device.c - Search a device for a pattern.
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

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define BINARY_NAME "search_device"

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

static struct search_device_options {
	const char *device_name;
	unsigned long long block_size;
	const char *block_data;

	sys_bool verbose;
	sys_bool about;
	sys_bool help;
} options;


static int generic_print_message(
		void *context,
		const char *format,
		...)
		__attribute__((format(printf, 2, 3)));


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
	fprintf(out, "usage: " BINARY_NAME " <device|file> <block size> "
		"<pattern data file>\n");
}

static void print_about(FILE *out)
{
	fprintf(out, "%s %s\n", BINARY_NAME, VERSION);
	fprintf(out, "Copyright (c) 2022-2025 Erik Larsson\n");
}

int main(int argc, char **argv)
{
	const char *const cmd = argv[0];

	int err = 0;

	const char *conflicting_options_string[2] = { NULL, NULL };
	int conflicting_options = 0;

	sys_device *dev = NULL;
	sys_bool dev_open = SYS_FALSE;
	char *pattern_buffer = NULL;
	u32 read_buffer_size = 0;
	char *read_buffer = NULL;
	u64 device_size = 0;
	u64 cur_offset = 0;

	while(argc > 4) {
		if((!strcmp(argv[1], "-v") ||
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

	if(argc != 4) {
		print_help(stderr, cmd);
		goto out;
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
	errno = 0;
	options.block_size = strtoull(argv[2], NULL, 0);
	if(options.block_size == ULLONG_MAX && errno) {
		err = (err = errno) ? err : EINVAL;
		sys_log_perror(errno, "Error while parsing block size");
		goto out;
	}
	else if(options.block_size > SIZE_MAX) {
		sys_log_error("Invalid block size: %" PRIu64,
			PRAu64(options.block_size));
		err = EINVAL;
		goto out;
	}
	options.block_data = argv[3];

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

	err = sys_malloc((size_t) options.block_size, &pattern_buffer);
	if(err) {
		sys_log_perror(err, "Error while allocating pattern buffer");
		goto out;
	}

	/* Read the data of the pattern file into memory. */
	{
		int pattern_fd;
		s64 read_res;

		pattern_fd = open(options.block_data, O_RDONLY | O_BINARY);
		if(pattern_fd == -1) {
			err = (err = errno) ? err : EIO;
			sys_log_perror(errno, "Error while opening \"%s\"",
				options.block_data);
			goto out;
		}

		read_res = read(pattern_fd, pattern_buffer,
			(size_t) options.block_size);
		if(read_res < 0) {
			err = (err = errno) ? err : EIO;
			sys_log_perror(errno, "Error while reading %" PRId64 " "
				"bytes from pattern file",
				PRAu64(options.block_size));
		}
		else if(read_res < options.block_size) {
			sys_log_error("Partial read while reading pattern "
				"data: %" PRId64 " < %" PRIu64,
				PRAd64(read_res), PRAu64(options.block_size));
		}

		if(close(pattern_fd)) {
			if(!err) {
				err = (err = errno) ? err : EIO;
			}

			sys_log_perror(errno, "Error while closing pattern "
				"file");
		}

		if(err) {
			goto out;
		}
	}

	read_buffer_size = 4U * 1024UL * 1024UL;
	if(read_buffer_size > SIZE_MAX) {
		read_buffer_size = (u32) SIZE_MAX;
	}

	err = sys_malloc((size_t) read_buffer_size, &read_buffer);
	if(err) {
		sys_log_perror(err, "Error while allocating read buffer");
		goto out;
	}

	/* Read from the device in buffer sized chunks looking for the
	 * pattern. */
	err = sys_device_get_size(
		/* sys_device *dev */
		dev,
		/* u64 *out_size */
		&device_size);
	if(err) {
		sys_log_perror(err, "Error while querying device size");
		goto out;
	}

	while(1) {
		const u64 bytes_to_read =
			((cur_offset + read_buffer_size) > device_size) ?
			device_size - cur_offset : read_buffer_size;

		size_t i;

		err = sys_device_pread(
			/* sys_device *dev */
			dev,
			/* u64 offset */
			cur_offset,
			/* size_t nbytes */
			bytes_to_read,
			/* void *buf dev */
			read_buffer);
		if(err) {
			goto out;
		}

		for(i = 0; i < bytes_to_read; i += (size_t) options.block_size)
		{
			if(!memcmp(&read_buffer[i], pattern_buffer,
				(size_t) options.block_size))
			{
				emitln("Found pattern at device offset "
					"%" PRIu64 " / 0x%" PRIX64 ", block "
					"%" PRIu64 " / 0x%" PRIX64 ".",
					PRAu64(cur_offset + i),
					PRAX64(cur_offset + i),
					PRAu64((cur_offset + i) /
					options.block_size),
					PRAX64((cur_offset + i) /
					options.block_size));
			}
		}

		cur_offset += bytes_to_read;
	}
out:
	if(dev_open) {
		sys_device_close(&dev);
	}

	return err ? (EXIT_FAILURE) : (EXIT_SUCCESS);
}
