/*-
 * refsimage.c - Create a filesystem/metadata image of an ReFS volume.
 *
 * Copyright (c) 2025 Erik Larsson
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
#include "volume.h"

/* Headers - ANSI C standard libraries. */
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#include "sys.h"

#define BINARY_NAME "refsimage"

#define get_bit(bitmap, bit) \
	(((bitmap)[(bit) / 8] & (1 << ((bit) % 8))) ? 1 : 0)

#define set_bit(bitmap, bit) \
	(bitmap)[(bit) / 8] |= (1 << ((bit) % 8))

typedef struct {
	refs_volume *vol;
	u8 *bitmap;
	size_t bitmap_size;
	sys_bool metadata;
} refsimage_crawl_context;

static struct refsimage_options {
	const char *device_name;

	sys_bool restore_image;
	sys_bool ntfsclone_image;
	sys_bool metadata;
	const char *output;
	sys_bool about;
	sys_bool help;
} options;


static void print_help(FILE *out)
{
	fprintf(out, "%s %s\n", BINARY_NAME, VERSION);
	fprintf(out, "usage: " BINARY_NAME " [-r] [-n] [-m] [-o <image file>] "
		"<device|file>\n");
}

static void print_about(FILE *out)
{
	fprintf(out, "%s %s\n", BINARY_NAME, VERSION);
	fprintf(out, "Copyright (c) 2022-2025 Erik Larsson\n");
}

static int refsimage_node_header(
		void *const _context,
		const u64 node_number,
		const u64 node_first_cluster,
		const u64 object_id,
		const u8 *const data,
		const size_t data_size,
		const size_t header_offset,
		const size_t header_size)
{
	refsimage_crawl_context *const context =
		(refsimage_crawl_context*) _context;
	const sys_bool is_v3 =
		(context->vol->bs->version_major >= 3) ? SYS_TRUE : SYS_FALSE;
	const REFS_NODE_HEADER *const header = (const REFS_NODE_HEADER*) data;

	(void) header_offset;

	sys_log_debug("Node header. Node number: %" PRIu64 ", node first "
		"cluster: %" PRIu64 ", object ID: %" PRIu64,
		PRAu64(node_number), PRAu64(node_first_cluster),
		PRAu64(object_id));

	if(data_size < (is_v3 ? sizeof(header->v3) : sizeof(header->v1))) {
		sys_log_warning("Size passed to node header callback is too "
			"small for a node header struct: %" PRIuz " < "
			"%" PRIuz " Ignoring node %" PRIu64 " @ cluster "
			"%" PRIu64 " with object ID 0x%" PRIX64 "...",
			PRAuz(header_size),
			PRAuz(is_v3 ? sizeof(header->v3) : sizeof(header->v1)),
			PRAu64(node_number), PRAu64(node_first_cluster),
			PRAX64(object_id));
		goto out;
	}

	if(is_v3) {
		/* If the other cluster numbers are non-0, then add them as well
		 * to the bitmap (node consists of more than one cluster). */
		u8 i;

		if(object_id &&
			node_number != le64_to_cpu(header->v3.block_numbers[0]))
		{
			sys_log_warning("Mismatching first block number for "
				"node %" PRIu64 ": %" PRIu64 " Ignoring "
				"additional numbers...",
				PRAu64(node_number),
				PRAu64(le64_to_cpu(header->v3.
				block_numbers[0])));
			set_bit(context->bitmap, node_number);
			goto out;
		}

		for(i = 0; i < 4; ++i) {
			const u64 cur_block =
				le64_to_cpu(header->v3.block_numbers[i]);
			u64 cur_cluster;

			if(!cur_block) {
				continue;
			}

			cur_cluster =
				(object_id == 0x0) ? cur_block :
				refs_node_logical_to_physical_block_number(
					/* const REFS_BOOT_SECTOR *bs */
					context->vol->bs,
					/* const refs_block_map
					 *     *mapping_table */
					context->vol->block_map,
					/* u64 logical_block_number */
					cur_block);
			if(!cur_cluster) {
				sys_log_warning("Could not resolve the "
					"physical cluster for virtual block "
					"%" PRIu8 "/4 (%" PRIu64 ") in node "
					"starting with virtual block "
					"%" PRIu64 " / physical cluster "
					"%" PRIu64 ". Ignoring...",
					PRAu8(i + 1), PRAu64(cur_block),
					PRAu64(node_number),
					PRAu64(node_first_cluster));
				continue;
			}

			set_bit(context->bitmap, cur_cluster);
		}
	}
	else {
		if(object_id == 0x0) {
			set_bit(context->bitmap, node_number);
		}
		else {
			set_bit(context->bitmap, node_first_cluster);
		}
	}
out:
	return 0;
}

static int refsimage_node_header_entry(
		void *context,
		const u8 *data,
		size_t entry_size)
{
	(void) context;
	(void) data;
	(void) entry_size;

	return 0;
}

static int refsimage_node_allocation_entry(
		void *context,
		const u8 *data,
		size_t entry_size)
{
	(void) context;
	(void) data;
	(void) entry_size;

	return 0;
}

static int refsimage_node_regular_entry(
		void *context,
		const u8 *data,
		size_t entry_size)
{
	(void) context;
	(void) data;
	(void) entry_size;

	return 0;
}

static int refsimage_node_volume_label_entry(
		void *context,
		const le16 *volume_label,
		u16 volume_label_length)
{
	(void) context;
	(void) volume_label;
	(void) volume_label_length;

	return 0;
}

static int refsimage_node_long_entry(
		void *context,
		const le16 *file_name,
		u16 file_name_length,
		u16 child_entry_offset,
		u32 file_flags,
		u64 parent_node_object_id,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size,
		const u8 *key,
		size_t key_size,
		const u8 *record,
		size_t record_size)
{
	(void) context;
	(void) file_name;
	(void) file_name_length;
	(void) child_entry_offset;
	(void) file_flags;
	(void) parent_node_object_id;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) file_size;
	(void) allocated_size;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	return 0;
}

static int refsimage_node_short_entry(
		void *context,
		const le16 *file_name,
		u16 file_name_length,
		u16 child_entry_offset,
		u32 file_flags,
		u64 parent_node_object_id,
		u64 object_id,
		u64 hard_link_id,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		const u64 file_size,
		const u64 allocated_size,
		const u8 *key,
		size_t key_size,
		const u8 *record,
		size_t record_size)
{
	(void) context;
	(void) file_name;
	(void) file_name_length;
	(void) child_entry_offset;
	(void) file_flags;
	(void) parent_node_object_id;
	(void) object_id;
	(void) hard_link_id;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) file_size;
	(void) allocated_size;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	return 0;
}

static int refsimage_node_hardlink_entry(
		void *context,
		u64 hard_link_id,
		u64 parent_id,
		u16 child_entry_offset,
		u32 file_flags,
		u64 create_time,
		u64 last_access_time,
		u64 last_write_time,
		u64 last_mft_change_time,
		u64 file_size,
		u64 allocated_size,
		const u8 *key,
		size_t key_size,
		const u8 *record,
		size_t record_size)
{
	(void) context;
	(void) hard_link_id;
	(void) parent_id;
	(void) child_entry_offset;
	(void) file_flags;
	(void) create_time;
	(void) last_access_time;
	(void) last_write_time;
	(void) last_mft_change_time;
	(void) file_size;
	(void) allocated_size;
	(void) key;
	(void) key_size;
	(void) record;
	(void) record_size;

	return 0;
}

static int refsimage_node_file_extent(
		void *_context,
		u64 first_block,
		u64 block_count,
		u32 block_index_unit)
{
	refsimage_crawl_context *const context =
		(refsimage_crawl_context*) _context;
	const u64 start_cluster =
		(first_block * block_index_unit) / context->vol->cluster_size;
	u64 end_cluster =
		(block_count * block_index_unit + context->vol->cluster_size -
		1) / context->vol->cluster_size;
	u64 i;

	if(context->metadata) {
		/* Don't include file data in the metadata bitmap. */
		goto out;
	}
	else if(start_cluster >= context->vol->cluster_count) {
		sys_log_warning("Inconsistency: %s extent starts at or beyond "
			"the end of the volume. Extent clusters: %" PRIu64 " - "
			"%" PRIu64 " (%" PRIu64 " ) Volume cluster count: "
			"%" PRIu64,
			"File",
			PRAu64(start_cluster), PRAu64(end_cluster - 1),
			PRAu64(end_cluster - start_cluster),
			PRAu64(context->vol->cluster_count));
		goto out;
	}
	else if(end_cluster > context->vol->cluster_count) {
		sys_log_warning("Inconsistency: %s extent extends beyond the "
			"end of the volume. Extent clusters: %" PRIu64 " - "
			"%" PRIu64 " (%" PRIu64 " ) Volume cluster count: "
			"%" PRIu64,
			"File",
			PRAu64(start_cluster), PRAu64(end_cluster - 1),
			PRAu64(end_cluster - start_cluster),
			PRAu64(context->vol->cluster_count));
		end_cluster = context->vol->cluster_count;
	}

	for(i = start_cluster; i < end_cluster; ++i) {
		set_bit(context->bitmap, i);
	}
out:
	return 0;
}

static int refsimage_node_file_data(
		void *context,
		const void *data,
		size_t size)
{
	(void) context;
	(void) data;

	sys_log_debug("Resident file data (size: %" PRIu64 ").",
		PRAu64(size));

	return 0;
}

static int refsimage_node_ea(
		void *context,
		const char *name,
		size_t name_length,
		const void *data,
		size_t data_size)
{
	(void) context;
	(void) data;

	sys_log_debug("EA: \"%" PRIbs "\" (size: %" PRIu64 ")",
		PRAbs(name_length, name), PRAu64(data_size));

	return 0;
}

static int refsimage_node_stream(
		void *context,
		const char *name,
		size_t name_length,
		u64 data_size,
		const refs_node_stream_data *data_reference)
{
	(void) context;

	sys_log_debug("%s stream: \"%" PRIbs "\" (size: %" PRIu64 ")",
		data_reference->resident ? "Resident" : "Non-resident",
		PRAbs(name_length, name), PRAu64(data_size));

	return 0;
}

static int refsimage_node_stream_extent(
		void *_context,
		u64 stream_id,
		u64 first_block,
		u32 block_index_unit,
		u32 cluster_count)
{
		refsimage_crawl_context *const context =
		(refsimage_crawl_context*) _context;
	const u64 start_cluster =
		(first_block * block_index_unit) / context->vol->cluster_size;
	u64 end_cluster =
		(cluster_count * block_index_unit + context->vol->cluster_size -
		1) / context->vol->cluster_size;
	u64 i;

	sys_log_debug("Stream extent with id %" PRIu64 ". First block: "
		"%" PRIu64 " Block index unit: %" PRIu32 " Block count: "
		"%" PRIu32,
		PRAu64(stream_id), PRAu64(first_block),
		PRAu32(block_index_unit), PRAu32(cluster_count));

	if(context->metadata) {
		/* Don't include stream data in the metadata bitmap. TODO: Maybe
		 * we should? */
		goto out;
	}
	else if(start_cluster >= context->vol->cluster_count) {
		sys_log_warning("Inconsistency: %s extent starts at or beyond "
			"the end of the volume. Extent clusters: %" PRIu64 " - "
			"%" PRIu64 " (%" PRIu64 " ) Volume cluster count: "
			"%" PRIu64,
			"Stream",
			PRAu64(start_cluster), PRAu64(end_cluster - 1),
			PRAu64(end_cluster - start_cluster),
			PRAu64(context->vol->cluster_count));
		goto out;
	}
	else if(end_cluster > context->vol->cluster_count) {
		sys_log_warning("Inconsistency: %s extent extends beyond the "
			"end of the volume. Extent clusters: %" PRIu64 " - "
			"%" PRIu64 " (%" PRIu64 " ) Volume cluster count: "
			"%" PRIu64,
			"Stream",
			PRAu64(start_cluster), PRAu64(end_cluster - 1),
			PRAu64(end_cluster - start_cluster),
			PRAu64(context->vol->cluster_count));
		end_cluster = context->vol->cluster_count;
	}

	for(i = start_cluster; i < end_cluster; ++i) {
		set_bit(context->bitmap, i);
	}
out:
	return 0;
}

typedef struct refsimage_output_stream refsimage_output_stream;
struct refsimage_output_stream {
	sys_device *dev;
	u32 block_size;
	void *context;

	int (*process_extent)(
		refsimage_output_stream *stream,
		u64 block_number,
		u64 block_count,
		const char *data);
	int (*process_hole)(
		refsimage_output_stream *stream,
		u64 block_number,
		u64 block_count);
	int (*close)(
		refsimage_output_stream *stream);
};

static int refsimage_fd_stream_process_extent(
		refsimage_output_stream *stream,
		u64 block_number,
		u64 block_count,
		const char *data)
{
	const size_t bytes_to_write =
		(size_t) (block_count * stream->block_size);

	int err = 0;
	ssize_t bytes_written;

	(void) block_number;

	bytes_written = write((int) ((uintptr_t) stream->context), data,
		bytes_to_write);
	if(bytes_written < 0 || (size_t) bytes_written != bytes_to_write) {
		err = (err = errno) ? err : EIO;
		sys_log_perror(errno, "Error writing to file "
			"descriptor");
	}

	return err;
}

static int refsimage_fd_stream_process_hole(
		refsimage_output_stream *stream,
		u64 block_number,
		u64 block_count)
{
	const int fd = (int) ((uintptr_t) stream->context);
	const u64 hole_size = block_count * stream->block_size;
	const size_t buffer_size = sys_min(hole_size, 1024UL * 1024UL);

	int err = 0;
	off_t new_size = 0;
	char *buffer = NULL;
	u64 remaining_bytes = hole_size;

	(void) block_number;

	new_size = lseek(fd, hole_size, SEEK_CUR);
	if(new_size > 0) {
		if(ftruncate(fd, new_size)) {
			err = (err = errno) ? err : EIO;
			sys_log_perror(errno, "Error while truncating file to "
				"end of hole");
		}

		goto out;
	}

	err = sys_calloc(buffer_size, &buffer);
	if(err) {
		goto out;
	}

	while(remaining_bytes) {
		const ssize_t bytes_to_write =
			(ssize_t) sys_min(remaining_bytes, buffer_size);

		if(write(fd, buffer, (size_t) bytes_to_write) != bytes_to_write)
		{
			err = (err = errno) ? err : EIO;
			sys_log_perror(errno, "Error writing to file "
				"descriptor");
			goto out;
		}

		remaining_bytes -= bytes_to_write;
	}
out:
	if(buffer) {
		sys_free(&buffer);
	}

	return err;
}

static refsimage_output_stream refsimage_fd_stream_init(
		sys_device *const dev,
		refs_volume *const vol,
		const int fd)
{
	const refsimage_output_stream stream = {
		/* sys_device *dev */
		dev,
		/* u32 block_size */
		vol->cluster_size,
		/* void *context */
		(void*) ((uintptr_t) fd),
		/* int (*process_extent)(
		 *     refsimage_output_stream *stream,
		 *     u64 block_number,
		 *     u64 block_count,
		 *     const char *data) */
		refsimage_fd_stream_process_extent,
		/* int (*process_hole)(
		 *     refsimage_output_stream *stream,
		 *     u64 block_number,
		 *     u64 block_count) */
		refsimage_fd_stream_process_hole,
		/* int (*close)(
		 *     refsimage_output_stream *stream) */
		NULL
	};

	return stream;
}

typedef struct {
	int fd;
	sys_bool header_written;
	struct {
		u8 signature[16];                       /*  0 */
		struct {
			u8 major;                       /* 16 */
			u8 minor;                       /* 17 */
		} __attribute__((packed)) version;
		/* Note: Misaligned. */
		le32 block_size;                        /* 18 */
		le64 device_size;                       /* 22 */
		le64 total_clusters;                    /* 30 */
		le64 occupied_clusters;                 /* 38 */
		le32 data_offset;                       /* 46 */
		u8 padding[6];                          /* 50 */
		u8 data[0];                             /* 56 */
	} __attribute__((packed)) header;
} refsimage_ntfsclone_stream_context;

static int refsimage_ntfsclone_stream_write_header(
		refsimage_ntfsclone_stream_context *const context)
{
	int err = 0;
	ssize_t bytes_written = 0;

	bytes_written = write(context->fd, &context->header,
		sizeof(context->header));
	if(bytes_written < 0 ||
		(size_t) bytes_written != sizeof(context->header))
	{
		err = (err = errno) ? err : EIO;
		sys_log_perror(errno, "Error writing header to file "
			"descriptor");
		goto out;
	}

	context->header_written = SYS_TRUE;
out:
	return err;
}

static int refsimage_ntfsclone_stream_process_extent(
		refsimage_output_stream *stream,
		u64 block_number,
		u64 block_count,
		const char *data)
{
	refsimage_ntfsclone_stream_context *const context =
		(refsimage_ntfsclone_stream_context*) stream->context;

	int err = 0;
	const char *datap = data;
	size_t remaining_bytes =
		(size_t) (block_count * stream->block_size);

	(void) block_number;

	if(!context->header_written) {
		err = refsimage_ntfsclone_stream_write_header(
			/* refsimage_ntfsclone_stream_context *context */
			context);
		if(err) {
			goto out;
		}
	}

	while(remaining_bytes >= stream->block_size) {
		static const u8 cmd_next = 0x1;
		ssize_t bytes_written;

		/* Write CMD_NEXT (0x1) */
		bytes_written = write(context->fd, &cmd_next, 1);
		if(bytes_written < 0 || (size_t) bytes_written != 1) {
			err = (err = errno) ? err : EIO;
			sys_log_perror(errno, "Error writing CMD_NEXT to file "
				"descriptor");
			goto out;
		}

		/* Write the cluster. */
		bytes_written = write(context->fd, datap, stream->block_size);
		if(bytes_written < 0 ||
			(size_t) bytes_written != stream->block_size)
		{
			err = (err = errno) ? err : EIO;
			sys_log_perror(errno, "Error writing cluster to file "
				"descriptor");
			goto out;
		}

		remaining_bytes -= stream->block_size;
		datap = &datap[stream->block_size];
	}
out:
	return err;
}

static int refsimage_ntfsclone_stream_process_hole(
		refsimage_output_stream *stream,
		u64 block_number,
		u64 block_count)
{
	static const u8 cmd_gap = 0x0;

	refsimage_ntfsclone_stream_context *const context =
		(refsimage_ntfsclone_stream_context*) stream->context;

	int err = 0;
	ssize_t bytes_written = 0;
	le64 count;

	(void) block_number;

	if(!context->header_written) {
		err = refsimage_ntfsclone_stream_write_header(
			/* refsimage_ntfsclone_stream_context *context */
			context);
		if(err) {
			goto out;
		}
	}

	/* Write CMD_GAP (0x0) */
	bytes_written = write(context->fd, &cmd_gap, 1);
	if(bytes_written < 0 || (size_t) bytes_written != 1) {
		err = (err = errno) ? err : EIO;
		sys_log_perror(errno, "Error writing CMD_GAP to file "
			"descriptor");
		goto out;
	}

	/* Write the count. */
	count = cpu_to_le64(block_count);
	bytes_written = write(context->fd, &count, sizeof(count));
	if(bytes_written < 0 || (size_t) bytes_written != sizeof(count)) {
		err = (err = errno) ? err : EIO;
		sys_log_perror(errno, "Error writing gap count to file "
			"descriptor");
		goto out;
	}
out:
	return err;
}

static refsimage_output_stream refsimage_ntfsclone_stream_init(
		sys_device *const dev,
		refs_volume *const vol,
		const int fd,
		refsimage_ntfsclone_stream_context *const context)
{
	const refsimage_output_stream stream = {
		/* sys_device *dev */
		dev,
		/* u32 block_size */
		vol->cluster_size,
		/* void *context */
		context,
		/* int (*process_extent)(
		 *     refsimage_output_stream *stream,
		 *     u64 block_number,
		 *     u64 block_count,
		 *     const char *data) */
		refsimage_ntfsclone_stream_process_extent,
		/* int (*process_hole)(
		 *     refsimage_output_stream *stream,
		 *     u64 block_number,
		 *     u64 block_count) */
		refsimage_ntfsclone_stream_process_hole,
		/* int (*close)(
		 *     refsimage_output_stream *stream) */
		NULL
	};

	int err = 0;
	u64 device_size = 0;
	le32 block_size_le;
	le64 device_size_le;
	le64 total_clusters_le;
	le64 occupied_clusters_le;
	le32 data_offset_le;

	err = sys_device_get_size(dev, &device_size);
	if(err) {
		sys_log_pwarning(err, "Error getting device size (falling back "
			"to cluster count)");
		device_size = vol->cluster_count * vol->cluster_size;
	}

	block_size_le = cpu_to_le32(vol->cluster_size);
	device_size_le = cpu_to_le64(device_size);
	total_clusters_le = cpu_to_le64(vol->cluster_count);
	occupied_clusters_le = total_clusters_le; /* TODO */
	data_offset_le = cpu_to_le32(56);

	memset(context, 0, sizeof(*context));
	context->fd = fd;
	memcpy(&context->header.signature, "\0ntfsclone-image", 16);
	context->header.version.major = 10;
	context->header.version.minor = 0;
	memcpy(&context->header.block_size, &block_size_le,
		sizeof(block_size_le));
	memcpy(&context->header.device_size, &device_size_le,
		sizeof(device_size_le));
	memcpy(&context->header.total_clusters, &total_clusters_le,
		sizeof(total_clusters_le));
	memcpy(&context->header.occupied_clusters, &occupied_clusters_le,
		sizeof(occupied_clusters_le));
	memcpy(&context->header.data_offset, &data_offset_le,
		sizeof(data_offset_le));

	return stream;
}

static int refsimage_restore_ntfsclone_image(
		const char *input_file,
		int out_fd)
{
	int err = 0;
	int in_fd = -1;
	refsimage_ntfsclone_stream_context context;
	ssize_t bytes_transferred = 0;
	le32 block_size_le;
	le64 device_size_le;
	le64 total_clusters_le;
	le64 occupied_clusters_le;
	le32 data_offset_le;
	u32 block_size = 0;
	void *buffer = NULL;
	u64 cmd_index = 0;

	memset(&context, 0, sizeof(context));

	in_fd = open(input_file, O_RDONLY);
	if(in_fd == -1) {
		err = (err = errno) ? err : ENOENT;
		goto out;
	}

	bytes_transferred =
		read(in_fd, &context.header, sizeof(context.header));
	if(bytes_transferred < 0 ||
		(size_t) bytes_transferred != sizeof(context.header))
	{
		err = (err = errno) ? err : EIO;
		fprintf(stderr, "Error while reading header from ntfsclone "
			"image: %s\n", strerror(errno));
		goto out;
	}

	if(memcmp(context.header.signature, "\0ntfsclone-image", 16)) {
		fprintf(stderr, "Invalid ntfsclone header: Invalid signature");
		err = EIO;
		goto out;
	}
	else if(context.header.version.major != 10 ||
		context.header.version.minor != 0)
	{
		fprintf(stderr, "Invalid ntfsclone header: Unsupported version "
			"%u.%u.",
			context.header.version.major,
			context.header.version.minor);
		err = EIO;
		goto out;
	}

	memcpy(&block_size_le, &context.header.block_size,
		sizeof(block_size_le));
	memcpy(&device_size_le, &context.header.device_size,
		sizeof(device_size_le));
	memcpy(&total_clusters_le, &context.header.total_clusters,
		sizeof(total_clusters_le));
	memcpy(&occupied_clusters_le, &context.header.occupied_clusters,
		sizeof(occupied_clusters_le));
	memcpy(&data_offset_le, &context.header.data_offset,
		sizeof(data_offset_le));

	block_size = le32_to_cpu(block_size_le);
	err = sys_malloc(block_size, &buffer);
	if(err) {
		goto out;
	}

	/* Keep it simple... no seeking needed. */
	if(le32_to_cpu(context.header.data_offset) != 56) {
		fprintf(stderr, "Invalid ntfsclone header: Unsupported data "
			"offset %" PRIu32 ".",
			PRAu32(le32_to_cpu(context.header.data_offset)));
		err = EIO;
		goto out;
	}

	if(ftruncate(out_fd, le64_to_cpu(device_size_le))) {
		err = (err = errno) ? err : ENOSPC;
		fprintf(stderr, "Error while truncating output file to "
			"%" PRIu64 " bytes: %s\n",
			PRAu64(le64_to_cpu(device_size_le)), strerror(errno));
		goto out;
	}

	while(1) {
		u8 cmd = 0;

		bytes_transferred = read(in_fd, &cmd, sizeof(cmd));
		if(bytes_transferred == 0) {
			break;
		}
		else if(bytes_transferred < 0 ||
			(size_t) bytes_transferred != sizeof(cmd))
		{
			err = (err = errno) ? err : EIO;
			fprintf(stderr, "Error while reading command from "
				"ntfsclone image: %s\n", strerror(errno));
			goto out;
		}

		if(cmd == 0x0) {
			/* CMD_GAP */
			le64 count = cpu_to_le64(0);
			off_t new_size = 0;

			bytes_transferred = read(in_fd, &count, sizeof(count));
			if(bytes_transferred < 0 ||
				(size_t) bytes_transferred != sizeof(count))
			{
				fprintf(stderr, "Error while gap count from "
					"ntfsclone image: %s\n",
					strerror(errno));
				err = (err = errno) ? err : EIO;
				goto out;
			}

			sys_log_debug("[%" PRIu64 "] CMD_GAP: %" PRIu64 " "
				"clusters",
				PRAu64(cmd_index), PRAu64(le64_to_cpu(count)));

			new_size =
				lseek(out_fd, le64_to_cpu(count) * block_size,
				SEEK_CUR);
			if(new_size < 0) {
				err = (err = errno) ? err : EIO;
				fprintf(stderr, "Error while seeking ahead "
					"%" PRIu64 " bytes in output file: "
					"%s\n",
					PRAu64(le64_to_cpu(count) * block_size),
					strerror(errno));
				goto out;
			}

			if(ftruncate(out_fd, new_size)) {
				err = (err = errno) ? err : EIO;
				fprintf(stderr, "Error while truncating output "
					"file to %" PRIu64 " bytes: %s\n",
					PRAu64(new_size),
					strerror(errno));
				goto out;
			}
		}
		else if(cmd == 0x1) {
			/* CMD_NEXT */
			sys_log_debug("[%" PRIu64 "] CMD_NEXT",
				PRAu64(cmd_index));

			bytes_transferred = read(in_fd, buffer, block_size);
			if(bytes_transferred < 0 ||
				(size_t) bytes_transferred != block_size)
			{
				err = (err = errno) ? err : EIO;
				fprintf(stderr, "Error while reading "
					"%" PRIu64 " bytes of cluster data "
					"from ntfsclone image: %s\n",
					PRAu64(block_size), strerror(errno));
				goto out;
			}

			bytes_transferred = write(out_fd, buffer, block_size);
			if(bytes_transferred < 0 ||
				(size_t) bytes_transferred != block_size)
			{
				err = (err = errno) ? err : EIO;
				fprintf(stderr, "Error while writing "
					"%" PRIu64 " bytes of cluster data to "
					"output file: %s\n",
					PRAu64(block_size), strerror(errno));
				goto out;
			}
		}
		else {
			fprintf(stderr, "Invalid command read from ntfsclone "
				"image: 0x%" PRIX8 "\n",
				PRAX8(cmd));
			err = EIO;
			goto out;
		}

		++cmd_index;
	}
out:
	if(buffer) {
		sys_free(&buffer);
	}

	if(in_fd != -1) {
		close(in_fd);
	}

	return err;
}

int main(int argc, char **argv)
{
	int err = 0;
	sys_device *dev = NULL;
	refs_volume *vol = NULL;
	u64 device_size = 0;
	u64 device_cluster_count = 0;
	u64 bitmap_size = 0;
	u8 *bitmap = NULL;
	int out_fd = -1;
	u64 i;
	refsimage_crawl_context context;
	refs_node_walk_visitor visitor;
	refsimage_ntfsclone_stream_context ntfsclone_context;
	refsimage_output_stream stream;
	size_t buffer_size = 0;
	char *buffer = NULL;
	sys_bool extent_is_hole = SYS_FALSE;
	u64 extent_start = 0;
	u64 extent_length = 0;

	memset(&context, 0, sizeof(context));
	memset(&visitor, 0, sizeof(visitor));
	memset(&ntfsclone_context, 0, sizeof(ntfsclone_context));
	memset(&stream, 0, sizeof(stream));

	while(argc > 2) {
		if(!strcmp(argv[1], "-m") ||
			(!strcmp(argv[1], "--metadata")))
		{
			options.metadata = SYS_TRUE;
			argv = &argv[1];
			argc -= 1;
		}
		else if(!strcmp(argv[1], "-n") ||
			(!strcmp(argv[1], "--ntfsclone-image")))
		{
			options.ntfsclone_image = SYS_TRUE;
			argv = &argv[1];
			argc -= 1;
		}
		else if(argc > 2 && (!strcmp(argv[1], "-o") ||
			(!strcmp(argv[1], "--output"))))
		{
			options.output = argv[2];
			argv = &argv[2];
			argc -= 2;
		}
		else if(!strcmp(argv[1], "-r") ||
			(!strcmp(argv[1], "--restore-image")))
		{
			options.restore_image = SYS_TRUE;
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
	else if(options.help) {
		print_help(stdout);
		goto out;
	}
	else if(options.about) {
		print_about(stdout);
		goto out;
	}

	options.device_name = argv[1];

	if(!options.restore_image) {
		err = sys_device_open(&dev, options.device_name);
		if(err) {
			fprintf(stderr, "Error while opening device \"%s\": "
				"%s\n",
				options.device_name, strerror(err));
			goto out;
		}

		err = refs_volume_create(dev, &vol);
		if(err) {
			fprintf(stderr, "Error: Failed to open ReFS volume "
				"\"%s\".\n",
				options.device_name);
			goto out;
		}

		err = sys_device_get_size(dev, &device_size);
		if(err) {
			sys_log_pwarning(err, "Error getting the device size");
			err = 0;
			device_size = vol->cluster_count * vol->cluster_size;
		}

		device_cluster_count =
			(device_size + vol->cluster_size - 1) /
			vol->cluster_size;
		bitmap_size = (device_cluster_count + 7) / 8;
#if SIZE_MAX < UINT64_MAX
		if(bitmap_size > SIZE_MAX) {
			sys_log_error("Bitmap is too large for this system's "
				"address space.");
			err = ENOMEM;
			goto out;
		}
#endif

		err = sys_calloc((size_t) bitmap_size, &bitmap);
		if(err) {
			sys_log_perror(err, "Error allocating %" PRIuz "-byte "
				"bitmap",
				PRAuz(bitmap_size));
			goto out;
		}
	}

	if(options.output) {
		out_fd = open(options.output, O_WRONLY | O_CREAT | O_EXCL,
			0666);
		if(out_fd == -1) {
			fprintf(stderr, "Error while opening output file "
				"\"%s\": %s\n",
				options.output, strerror(errno));
			goto out;
		}
	}
	else {
		out_fd = fileno(stdout);
	}

#ifdef O_BINARY
	setmode(out_fd, O_BINARY);
#endif

	if(options.restore_image) {
		err = refsimage_restore_ntfsclone_image(
			/* const char *input_file */
			options.device_name,
			/* int out_fd */
			out_fd);
		goto out;
	}

	/* Mark the first 32 clusters. */
	for(i = 0; i < 32; ++i) {
		set_bit(bitmap, i);
	}

	if(device_cluster_count > vol->cluster_count) {
		/* Mark the last X clusters that follow the end of the defined
		 * clusters. */
		sys_log_debug("Marking %" PRIu64 " trailing clusters...",
			PRAu64(device_cluster_count - vol->cluster_count));
		for(i = vol->cluster_count; i < device_cluster_count; ++i) {
			set_bit(bitmap, i);
		}
	}

	context.vol = vol;
	context.bitmap = bitmap;
	context.bitmap_size = (size_t) bitmap_size;
	context.metadata = options.metadata;

	visitor.node_header = refsimage_node_header;
	visitor.node_header_entry = refsimage_node_header_entry;
	visitor.node_allocation_entry = refsimage_node_allocation_entry;
	visitor.node_regular_entry = refsimage_node_regular_entry;
	visitor.node_volume_label_entry = refsimage_node_volume_label_entry;
	visitor.node_long_entry = refsimage_node_long_entry;
	visitor.node_short_entry = refsimage_node_short_entry;
	visitor.node_hardlink_entry = refsimage_node_hardlink_entry;
	visitor.node_file_extent = refsimage_node_file_extent;
	visitor.node_file_data = refsimage_node_file_data;
	visitor.node_ea = refsimage_node_ea;
	visitor.node_stream = refsimage_node_stream;
	visitor.node_stream_extent = refsimage_node_stream_extent;
	visitor.context = &context;

	err = refs_node_walk(
		/* sys_device *dev */
		dev,
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
		NULL,
		/* refs_node_walk_visitor *visitor */
		&visitor);
	if(err) {
		goto out;
	}

	/* We now have the bitmap. Start reading and dumping the blocks. */
	if(options.ntfsclone_image) {
		stream = refsimage_ntfsclone_stream_init(
			/* sys_device *dev */
			dev,
			/* refs_volume *vol */
			vol,
			/* int fd */
			(out_fd == -1) ? fileno(stdout) : out_fd,
			/* refsimage_ntfsclone_stream_context *context */
			&ntfsclone_context);
	}
	else {
		stream = refsimage_fd_stream_init(
			/* sys_device *dev */
			dev,
			/* refs_volume *vol */
			vol,
			/* int fd */
			(out_fd == -1) ? fileno(stdout) : out_fd);
	}

	buffer_size = 1024UL * 1024UL;
	err = sys_malloc(buffer_size, &buffer);
	if(err) {
		sys_log_perror(err, "Error allocating buffer");
		goto out;
	}

	for(i = 0; i < device_cluster_count; ++i) {
		const u8 bit = get_bit(bitmap, i);

#if 0
		sys_log_trace("Bit %" PRIu64 ": %" PRIu8 " (%s %" PRIu64 " - "
			"%" PRIu64 " (%" PRIu64 " clusters))",
			PRAu64(i), PRAu8(bit),
			extent_is_hole ? "hole" : "extent",
			PRAu64(extent_start),
			PRAu64(!extent_length ? extent_start :
				(extent_start + extent_length - 1)),
			PRAu64(extent_length));
#endif

		if(!extent_length) {
			extent_start = i;
			extent_is_hole = !bit;
			extent_length = 1;
			continue;
		}
		else if((!bit) == extent_is_hole) {
			++extent_length;

			if(i + 1 < device_cluster_count) {
				continue;
			}

			/* Last iteration, must process the extent. */
		}

		sys_log_debug("Processing %s %" PRIu64 " - %" PRIu64 " "
			"(%" PRIu64 " clusters)...",
			extent_is_hole ? "hole" : "extent",
			PRAu64(extent_start),
			PRAu64(extent_start + extent_length - 1),
			PRAu64(extent_length));

		if(extent_is_hole) {
			err = stream.process_hole(
				/* refsimage_output_stream *stream */
				&stream,
				/* u64 block_number */
				extent_start,
				/* u64 block_count */
				extent_length);
			if(err) {
				goto out;
			}
		}
		else {
			u64 cur_block = extent_start;
			u64 cur_offset = cur_block * vol->cluster_size;
			u64 remaining_bytes = extent_length * vol->cluster_size;

			while(remaining_bytes) {
				const size_t bytes_to_read =
					sys_min(remaining_bytes, buffer_size);
				const size_t blocks_to_read =
					bytes_to_read / vol->cluster_size;

				err = sys_device_pread(
					/* sys_device *dev */
					dev,
					/* u64 offset */
					cur_offset,
					/* size_t nbytes */
					bytes_to_read,
					/* void *buf */
					buffer);
				if(err) {
					sys_log_perror(err, "Error while "
						"reading %" PRIuz " bytes from "
						"device offset %" PRIu64,
						PRAuz(bytes_to_read),
						PRAu64(cur_offset));
					goto out;
				}

				err = stream.process_extent(
					/* refsimage_output_stream *stream */
					&stream,
					/* u64 block_number */
					cur_block,
					/* u64 block_count */
					blocks_to_read,
					/* const char *data */
					buffer);
				if(err) {
					goto out;
				}

				remaining_bytes -= bytes_to_read;
				cur_offset += bytes_to_read;
				cur_block += blocks_to_read;
			}
		}

		extent_is_hole = !bit;
		extent_start = i;
		extent_length = 1;
	}
out:
	if(stream.context && stream.close) {
		int close_err;

		close_err = stream.close(
			/* refsimage_output_stream *stream */
			&stream);
		if(close_err) {
			err = err ? err : close_err;
		}
	}

	if(out_fd != fileno(stdout)) {
#ifdef _WIN32
		_commit(out_fd);
#else
		fsync(out_fd);
#endif
		close(out_fd);
	}

	if(buffer) {
		sys_free(&buffer);
	}

	if(vol) {
		refs_volume_destroy(&vol);
	}

	if(dev) {
		sys_device_close(&dev);
	}

	return err ? (EXIT_FAILURE) : (EXIT_SUCCESS);
}
