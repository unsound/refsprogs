/*-
 * refs-fuse.c - FUSE driver interface to librefs.
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

/* Headers - Autoconf-generated config.h, if present. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _WIN32
/* Fix for incompatible mode_t typedefs in mingw-w64 and Visual Studio. */
#define _MODE_T_
typedef unsigned int mode_t;
#endif

#if defined(_WIN32) || defined(__NetBSD__) || defined(__OpenBSD__)
#define REFS_FUSE_USE_LOWLEVEL_API 0
#else
#define REFS_FUSE_USE_LOWLEVEL_API 1
#endif

/* Headers - libfuse. */
#define FUSE_USE_VERSION 26
#if defined(__NetBSD__)
/* Work around librefuse compile error due to missing kernel types. */
#define _KERNTYPES 1
#endif
#include <fuse.h>
#if REFS_FUSE_USE_LOWLEVEL_API
#include <fuse_lowlevel.h>
#endif

/* Headers - librefs. */
#include "fsapi.h"
#include "layout.h"

#ifndef FUSE_STAT
/* The FUSE_STAT declaration is Dokan-specific, so for non-Dokan builds we
 * simply define it to 'stat'. */
#define FUSE_STAT stat
#endif

static int refs_fuse_fill_stat(
		struct FUSE_STAT *const stbuf,
		const fsapi_node_attributes *const attributes)
{
	memset(stbuf, 0, sizeof(*stbuf));

	sys_log_trace("%s("
		"stbuf=%p, "
		"attributes=%p (->{ .is_directory=%d, "
		".bsd_flags=0x%" PRIX32 ", "
		".create_time={ .tv_sec=%" PRIu64 ", .tv_nsec=%" PRId32 " }, "
		".last_access_time={ .tv_sec=%" PRIu64 ", "
		".tv_nsec=%" PRId32 " }, "
		".last_write_time={ .tv_sec=%" PRIu64 ", "
		".tv_nsec=%" PRId32 " }, "
		".last_mft_change_time={ .tv_sec=%" PRIu64 ", "
		".tv_nsec=%" PRId32 " }, "
		".file_size=%" PRIu64 ", "
		".allocated_size=%" PRIu64 "}) )",
		__FUNCTION__,
		stbuf,
		attributes,
		attributes->is_directory,
		PRAX32(attributes->bsd_flags),
		PRAu64(attributes->creation_time.tv_sec),
		PRAd32(attributes->creation_time.tv_nsec),
		PRAu64(attributes->last_data_access_time.tv_sec),
		PRAd32(attributes->last_data_access_time.tv_nsec),
		PRAu64(attributes->last_data_change_time.tv_sec),
		PRAd32(attributes->last_data_change_time.tv_nsec),
		PRAu64(attributes->last_status_change_time.tv_sec),
		PRAd32(attributes->last_status_change_time.tv_nsec),
		PRAu64(attributes->size),
		PRAu64(attributes->allocated_size));

	stbuf->st_mode = (attributes->is_directory ? S_IFDIR : S_IFREG) | 0777;
	stbuf->st_nlink = attributes->is_directory ? 2 /* TODO */ : 1;

	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER) {
		stbuf->st_ino = attributes->inode_number;
	}

#ifdef __APPLE__
	stbuf->st_uid = 99;
	stbuf->st_gid = 99;

#define st_atim st_atimespec
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#endif
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME)
	{
		stbuf->st_atim.tv_sec =
			attributes->last_data_access_time.tv_sec;
		stbuf->st_atim.tv_nsec =
			attributes->last_data_access_time.tv_nsec;
	}

	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME)
	{
		stbuf->st_mtim.tv_sec =
			attributes->last_data_change_time.tv_sec;
		stbuf->st_mtim.tv_nsec =
			attributes->last_data_change_time.tv_nsec;
	}

	if(attributes->valid &
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME)
	{
		stbuf->st_ctim.tv_sec =
			attributes->last_status_change_time.tv_sec;
		stbuf->st_ctim.tv_nsec =
			attributes->last_status_change_time.tv_nsec;
	}

#ifdef __APPLE__
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME) {
		stbuf->st_birthtimespec.tv_sec =
			attributes->creation_time.tv_sec;
		stbuf->st_birthtimespec.tv_nsec =
			attributes->creation_time.tv_nsec;
	}
#endif

	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_SIZE) {
		stbuf->st_size = attributes->size;
	}

	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE) {
		stbuf->st_blocks = attributes->allocated_size / 512;
	}

#ifdef __APPLE__
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS) {
		stbuf->st_flags = attributes->bsd_flags;
	}
#endif

	return 0;
}

typedef struct {
	void *dirbuf;
	fuse_fill_dir_t filler;
	off_t index;
} refs_fuse_readdir_context;

static int refs_fuse_filldir(
		refs_fuse_readdir_context *context,
		const char *file_name,
		size_t file_name_length,
		fsapi_node_attributes *attributes)
{
	int err = 0;
	struct FUSE_STAT stbuf;

	err = refs_fuse_fill_stat(
		/* struct FUSE_STAT *stbuf */
		&stbuf,
		/* const fsapi_node_attributes *attributes */
		attributes);
	if(err) {
		goto out;
	}

	/* We assume that file_name is NULL-terminated. This may be a bad choice
	 * for future changes but it simplifies things here. */
	(void) file_name_length;

	if(context->filler(
		/* void *buf */
		context->dirbuf,
		/* const char *name */
		file_name,
		/* const struct FUSE_STAT *stbuf */
		&stbuf,
		/* off_t off */
		0))
	{
		err = -1;
	}
out:

	return err;
}

static int refs_fuse_op_getattr(const char *path, struct FUSE_STAT *stbuf)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_get_context()->private_data;

	int err = 0;
	fsapi_node *node = NULL;
	fsapi_node_attributes attributes;

	memset(&attributes, 0, sizeof(attributes));

	sys_log_debug("%s(path=\"%s\", stbuf=%p)",
		__FUNCTION__, path, stbuf);

	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS;

	err = fsapi_node_lookup(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *parent_node */
		NULL,
		/* const char *path */
		path,
		/* size_t path_length */
		strlen(path),
		/* fsapi_node **out_child_node */
		&node,
		/* fsapi_node_attributes *out_attributes */
		&attributes);
	if(err) {
		goto out;
	}
	else if(!node) {
		err = ENOENT;
		goto out;
	}

	err = refs_fuse_fill_stat(
		/* struct stat *stbuf */
		stbuf,
		/* const fsapi_node_attributes *attributes */
		&attributes);
out:
	if(node) {
		fsapi_node_release(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **node */
			&node,
			/* size_t release_count */
			1);
	}

	sys_log_debug("%s(path=\"%s\", stbuf=%p): %d (%s)",
		__FUNCTION__, path, stbuf, -err, strerror(err));

	return -err;
}

static int refs_fuse_op_open(const char *path, struct fuse_file_info *fi)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_get_context()->private_data;

	int err = 0;
	fsapi_node *node = NULL;
	fsapi_node_attributes attributes;

	sys_log_debug("%s(path=\"%s\", fi=%p)",
		__FUNCTION__, path, fi);

	memset(&attributes, 0, sizeof(attributes));

	err = fsapi_node_lookup(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *parent_node */
		NULL,
		/* const char *path */
		path,
		/* size_t path_length */
		strlen(path),
		/* fsapi_node **out_child_node */
		&node,
		/* fsapi_node_attributes *out_attributes */
		&attributes);
	if(err) {
		goto out;
	}
	else if(!node) {
		err = ENOENT;
		goto out;
	}
	else if(attributes.is_directory) {
		err = EISDIR;
		goto out;
	}
out:
	if(node) {
		fsapi_node_release(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **node */
			&node,
			/* size_t release_count */
			1);
	}

	sys_log_debug("%s(path=\"%s\", fi=%p): %d (%s)",
		__FUNCTION__, path, fi, -err, strerror(err));

	return -err;
}

static int refs_fuse_op_read(const char *path, char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_get_context()->private_data;

	int err = 0;
	fsapi_node *node = NULL;
	fsapi_node_attributes attributes;
	fsapi_iohandler_buffer_context context;
	fsapi_iohandler iohandler;

	memset(&attributes, 0, sizeof(attributes));
	memset(&context, 0, sizeof(context));
	memset(&iohandler, 0, sizeof(iohandler));

	sys_log_debug("%s(path=\"%s\", buf=%p, size=%" PRIuz ", "
		"offset=%" PRId64 ", fi=%p)",
		__FUNCTION__, path, buf, PRAuz(size), PRAd64(offset), fi);

	err = fsapi_node_lookup(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *parent_node */
		NULL,
		/* const char *path */
		path,
		/* size_t path_length */
		strlen(path),
		/* fsapi_node **out_child_node */
		&node,
		/* fsapi_node_attributes *out_attributes */
		&attributes);
	if(err) {
		goto out;
	}
	else if(!node) {
		err = ENOENT;
		goto out;
	}
	else if(attributes.is_directory) {
		err = EISDIR;
		goto out;
	}


	context.buf.rw = buf;
	context.remaining_size = size;
	context.is_read = SYS_TRUE;
	iohandler.context = &context;
	iohandler.handle_io = fsapi_iohandler_buffer_handle_io;
	iohandler.copy_data = fsapi_iohandler_buffer_copy_data;

	err = fsapi_node_read(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* u64 offset */
		offset,
		/* size_t size */
		size,
		/* fsapi_iohandler *iohandler */
		&iohandler);
out:
	if(node) {
		fsapi_node_release(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **node */
			&node,
			/* size_t release_count */
			1);
	}

	sys_log_debug("%s(path=\"%s\", buf=%p, size=%" PRIuz ", "
		"offset=%" PRId64 ", fi=%p): %" PRIdz " (%s)",
		__FUNCTION__, path, buf, PRAuz(size), PRAd64(offset), fi,
		PRAdz(err ? -err : (size - context.remaining_size)),
		strerror(err));

	return err ? -err : (size - context.remaining_size);
}

static int refs_fuse_op_statfs(const char *path, struct statvfs *stvbuf)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_get_context()->private_data;

	int err = 0;
	fsapi_volume_attributes attributes;

	memset(&attributes, 0, sizeof(attributes));

	sys_log_debug("%s(path=\"%s\", stvbuf=%p)",
		__FUNCTION__, path, stvbuf);

	attributes.requested =
		FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_SIZE |
		FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_COUNT |
		FSAPI_VOLUME_ATTRIBUTE_TYPE_FREE_BLOCKS;

	err = fsapi_volume_get_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_volume_attributes *out_attrs */
		&attributes);
	if(err) {
		goto out;
	}

	memset(stvbuf, 0, sizeof(*stvbuf));
	if(attributes.valid & FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_SIZE) {
		stvbuf->f_bsize = attributes.block_size;
	}

	if(attributes.valid & FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_COUNT) {
		stvbuf->f_blocks = attributes.block_count;
	}

	if(attributes.valid & FSAPI_VOLUME_ATTRIBUTE_TYPE_FREE_BLOCKS) {
		stvbuf->f_bfree = attributes.free_blocks;
	}
out:
	sys_log_debug("%s(path=\"%s\", stvbuf=%p): %d (%s)",
		__FUNCTION__, path, stvbuf, -err, strerror(err));

	return -err;
}

static int refs_fuse_op_release(const char *path, struct fuse_file_info *fi)
{
	int err = 0;

	sys_log_debug("%s(path=\"%s\", fi=%p)",
		__FUNCTION__, path, fi);

	sys_log_debug("%s(path=\"%s\", fi=%p): %d (%s)",
		__FUNCTION__, path, fi, -err, strerror(err));

	return -err;
}

static int refs_fuse_op_readdir_handle_dirent(
		void *context,
		const char *name,
		size_t name_length,
		fsapi_node_attributes *attributes)
{
	int err = 0;

	err = refs_fuse_filldir(
		/* refs_fuse_readdir_context *context */
		(refs_fuse_readdir_context*) context,
		/* const char *file_name */
		name,
		/* size_t file_name_length */
		name_length,
		/* fsapi_node_attributes *attributes */
		attributes);

	return err;
}

static int refs_fuse_op_readdir(const char *path, void *dirbuf,
		fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_get_context()->private_data;

	int err = 0;
	fsapi_node *node = NULL;
	refs_fuse_readdir_context context;
	fsapi_node_attributes attributes;

	memset(&context, 0, sizeof(context));
	memset(&attributes, 0, sizeof(attributes));

	sys_log_debug("%s(path=\"%s\", dirbuf=%p, filler=%p, "
		"offset=%" PRId64 ", fi=%p)",
		__FUNCTION__, path, dirbuf, filler, PRAd64(offset), fi);

	err = fsapi_node_lookup(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *parent_node */
		NULL,
		/* const char *path */
		path,
		/* size_t path_length */
		strlen(path),
		/* fsapi_node **out_child_node */
		&node,
		/* fsapi_node_attributes *out_attributes */
		NULL);
	if(err) {
		goto out;
	}
	else if(!node) {
		err = ENOENT;
		goto out;
	}

	if(offset < 1 && filler(dirbuf, ".", NULL, 1)) {
		goto out;
	}

	if(offset < 2 && filler(dirbuf, "..", NULL, 2)) {
		goto out;
	}

	context.dirbuf = dirbuf;
	context.filler = filler;
	context.index = 2;
	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS;

	err = fsapi_node_list(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *directory_node */
		node,
		/* fsapi_node_attributes *attributes */
		&attributes,
		/* void *context */
		&context,
		/* int (*handle_dirent)(
		 *     void *context,
		 *     const char *name,
		 *     size_t name_length,
		 *     fsapi_node_attributes *attributes) */
		refs_fuse_op_readdir_handle_dirent);
	if(err == -1) {
		/* No more space in buffer. */
		err = 0;
	}
	else if(err) {
		sys_log_perror(err, "Error while listing directory");
		goto out;
	}
out:
	if(node) {
		fsapi_node_release(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **node */
			&node,
			/* size_t release_count */
			1);
	}

	sys_log_debug("%s(path=\"%s\", dirbuf=%p, filler=%p, "
		"offset=%" PRId64 ", fi=%p): %d (%s)",
		__FUNCTION__, path, dirbuf, filler, PRAd64(offset), fi, -err,
		strerror(err));

	return -err;
}

typedef struct {
	const char *name;
	size_t name_length;
	size_t size;
} refs_fuse_getxattr_context;

static int refs_fuse_op_getxattr_xattr_handler(
		void *const _context,
		const char *const name,
		const size_t name_length,
		const size_t size)
{
	refs_fuse_getxattr_context *const context =
		(refs_fuse_getxattr_context*) _context;

	int err = 0;

	if(name_length != context->name_length ||
		memcmp(name, context->name, name_length))
	{
		/* Not the xattr that we are looking for. Move on to the
		 * next one. */
		goto out;
	}

	context->size = size;
	err = -1;
out:
	return err;
}

#ifdef __APPLE__
static int refs_fuse_op_getxattr(const char *path, const char *name, char *buf,
		size_t size, uint32_t position)
#else
static int refs_fuse_op_getxattr(const char *path, const char *name, char *buf,
		size_t size)
#endif
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_get_context()->private_data;
#ifndef __APPLE__
	const uint32_t position = 0;
#endif

	int err = 0;
	fsapi_node *node = NULL;
	refs_fuse_getxattr_context context;
	fsapi_iohandler_buffer_context buffer_context;

	memset(&context, 0, sizeof(context));
	memset(&buffer_context, 0, sizeof(buffer_context));

	sys_log_debug("%s(path=\"%s\", name=\"%s\", buf=%p, "
		"size=%" PRIuz ", position=%" PRIu32 ")",
		__FUNCTION__, path, name, buf, PRAuz(size), PRAu32(position));

	err = fsapi_node_lookup(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *parent_node */
		NULL,
		/* const char *path */
		path,
		/* size_t path_length */
		strlen(path),
		/* fsapi_node **out_child_node */
		&node,
		/* fsapi_node_attributes *out_attributes */
		NULL);
	if(err) {
		goto out;
	}
	else if(!node) {
		err = ENOENT;
		goto out;
	}

	if(!buf) {
		context.name = name;
		context.name_length = strlen(name);

		err = fsapi_node_list_extended_attributes(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			node,
			/* void *context */
			&context,
			/* int (*xattr_handler)(
			 *     void *context,
			 *     const char *name,
			 *     size_t name_length,
			 *     size_t size) */
			refs_fuse_op_getxattr_xattr_handler);
		if(err == -1) {
			err = 0;
		}
		else if(err) {
			goto out;
		}
		else {
			err = ENOENT;
		}
	}
	else {
		fsapi_iohandler iohandler;

		memset(&iohandler, 0, sizeof(iohandler));

		buffer_context.buf.rw = buf;
		buffer_context.remaining_size = size;
		buffer_context.is_read = SYS_TRUE;

		iohandler.context = &buffer_context;
		iohandler.handle_io = fsapi_iohandler_buffer_handle_io;
		iohandler.copy_data = fsapi_iohandler_buffer_copy_data;

		err = fsapi_node_read_extended_attribute(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			node,
			/* const char *xattr_name */
			name,
			/* size_t xattr_name_length */
			strlen(name),
			/* u64 offset */
			position,
			/* size_t size */
			size,
			/* fsapi_iohandler *iohandler */
			&iohandler);
	}
	if(err == ENOENT) {
		/* Transform to ENOATTR (macOS/BSD) / ENODATA (Linux,
		 * ...?). */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
defined(__OpenBSD__) || defined(__DragonFly__)
		err = ENOATTR;
#else
		err = ENODATA;
#endif
	}
out:
	if(node) {
		fsapi_node_release(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **node */
			&node,
			/* size_t release_count */
			1);
	}

	return err ? -err :
		(buf ? size - buffer_context.remaining_size : context.size);
}

typedef struct {
	char *buf;
	size_t size;
} refs_fuse_listxattr_context;

static int refs_fuse_op_listxattr_xattr_handler(
		void *const _context,
		const char *const name,
		const size_t name_length,
		const size_t size)
{
	refs_fuse_listxattr_context *const context =
		(refs_fuse_listxattr_context*) _context;

	int err = 0;

	(void) size;

	if(!context->buf) {
		if(context->size > SIZE_MAX - (name_length + 1)) {
			/* Prevent overflow of size_t field. */
			goto out;
		}

		context->size += name_length + 1;
	}
	else if(name_length + 1 > context->size) {
		err = ERANGE;
		goto out;
	}
	else {
		memcpy(context->buf, name, name_length);
		context->buf[name_length] = '\0';
		context->buf = &context->buf[name_length + 1];
		context->size -= name_length + 1;
	}
out:
	return err;
}

static int refs_fuse_op_listxattr(const char *path, char *buf, size_t size)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_get_context()->private_data;

	int err = 0;
	fsapi_node *node = NULL;
	refs_fuse_listxattr_context context;

	memset(&context, 0, sizeof(context));

	sys_log_debug("%s(path=\"%s\", buf=%p, size=%" PRIuz ")",
		__FUNCTION__, path, buf, PRAuz(size));

	err = fsapi_node_lookup(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *parent_node */
		NULL,
		/* const char *path */
		path,
		/* size_t path_length */
		strlen(path),
		/* fsapi_node **out_child_node */
		&node,
		/* fsapi_node_attributes *out_attributes */
		NULL);
	if(err) {
		goto out;
	}
	else if(!node) {
		err = ENOENT;
		goto out;
	}

	if(buf) {
		context.buf = buf;
		context.size = size;
	}

	err = fsapi_node_list_extended_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* void *context */
		&context,
		/* int (*xattr_handler)(
		 *     void *context,
		 *     const char *name,
		 *     size_t name_length,
		 *     size_t size) */
		refs_fuse_op_listxattr_xattr_handler);
out:
	if(node) {
		fsapi_node_release(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **node */
			&node,
			/* size_t release_count */
			1);
	}

	return err ? -err : (buf ? size - context.size : context.size);
}

#if defined(_WIN32)
static uint32_t refs_fuse_op_win_get_attributes(const char *path)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_get_context()->private_data;
	int err = 0;
	fsapi_node *node = NULL;
	fsapi_node_attributes attributes;
	uint32_t ret = 0;

	memset(&attributes, 0, sizeof(attributes));

	sys_log_debug("%s(path=\"%s\")", __FUNCTION__, path);

	attributes.requested = FSAPI_NODE_ATTRIBUTE_TYPE_WINDOWS_FLAGS;
	err = fsapi_node_lookup(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *parent_node */
		NULL,
		/* const char *path */
		path,
		/* size_t path_length */
		strlen(path),
		/* fsapi_node **out_child_node */
		&node,
		/* fsapi_node_attributes *out_attributes */
		&attributes);
	if(err) {
		sys_log_perror(err, "Error while looking up entry by path");
		goto out;
	}
	else if(!node) {
		err = ENOENT;
		goto out;
	}

	ret = (attributes.valid & FSAPI_NODE_ATTRIBUTE_TYPE_WINDOWS_FLAGS) ?
		attributes.windows_flags :
		(attributes.is_directory ? REFS_FILE_ATTRIBUTE_DIRECTORY :
		REFS_FILE_ATTRIBUTE_NORMAL);
out:
	if(node) {
		fsapi_node_release(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **node */
			&node,
			/* size_t release_count */
			1);
	}

	sys_log_debug("%s(path=\"%s\"): 0x%" PRIX32 " (%s)",
		__FUNCTION__, path,
		PRAX32(ret), strerror(0));

	return ret;
}
#endif /* defined(_WIN32) */

struct fuse_operations refs_fuse_operations = {
	/* int (*getattr) (const char *, struct FUSE_STAT *) */
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
#ifdef __APPLE__
	/* int (*getxattr) (const char *, const char *, char *, size_t,
	 *     uint32_t); */
#else
	/* int (*getxattr) (const char *, const char *, char *, size_t); */
#endif
	.getxattr = refs_fuse_op_getxattr,
	/* int (*listxattr) (const char *, char *, size_t); */
	.listxattr = refs_fuse_op_listxattr,
#ifdef _WIN32
	/* uint32_t (*win_get_attributes) (const char *fn) */
	.win_get_attributes = refs_fuse_op_win_get_attributes,
#endif
};

#if REFS_FUSE_USE_LOWLEVEL_API
static fsapi_node* refs_fuse_ll_fuse_ino_to_node(
		fuse_ino_t ino,
		fsapi_volume *vol)
{
	if(ino == FUSE_ROOT_ID) {
		fsapi_node *root_node = NULL;

		fsapi_volume_get_root_node(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *out_root_node */
			&root_node);

		return root_node;
	}

	return (fsapi_node*) (uintptr_t) ino;
}

static void refs_fuse_ll_op_lookup(
		fuse_req_t req,
		fuse_ino_t parent,
		const char *name)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_req_userdata(req);
	fsapi_node *const parent_node =
		refs_fuse_ll_fuse_ino_to_node(
			/* fuse_ino_t ino */
			parent,
			/* fsapi_volume *vol */
			vol);

	int err = 0;
	fsapi_node_attributes attributes;
	fsapi_node *node = NULL;
	struct fuse_entry_param entry_param;

	memset(&attributes, 0, sizeof(attributes));
	memset(&entry_param, 0, sizeof(entry_param));

	sys_log_debug("%s(req=%p, parent=0x%lX, name=\"%s\")",
		__FUNCTION__, req, parent, name);

	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS;

	err = fsapi_node_lookup(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *parent_node */
		parent_node,
		/* const char *path */
		name,
		/* size_t path_length */
		strlen(name),
		/* fsapi_node **out_child_node */
		&node,
		/* fsapi_node_attributes *out_attributes */
		&attributes);
	if(err) {
		goto out;
	}
	else if(!node) {
		err = ENOENT;
		goto out;
	}

	entry_param.ino = (fuse_ino_t) (uintptr_t) node;
	entry_param.generation = 1;
	entry_param.attr_timeout = 3600;
	entry_param.entry_timeout= 3600;

	err = refs_fuse_fill_stat(
		/* struct stat *stbuf */
		&entry_param.attr,
		/* const fsapi_node_attributes *attributes */
		&attributes);
out:
	sys_log_debug("%s(req=%p, parent=0x%lX, name=\"%s\"): %d (%s)",
		__FUNCTION__, req, parent, name, err, strerror(err));

	if(err) {
		fuse_reply_err(req, err);
	}
	else {
		fuse_reply_entry(req, &entry_param);
	}
}

static void refs_fuse_ll_op_forget(
		fuse_req_t req,
		fuse_ino_t ino,
		unsigned long nlookup)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_req_userdata(req);

	int err = 0;
	fsapi_node *node =
		refs_fuse_ll_fuse_ino_to_node(
			/* fuse_ino_t ino */
			ino,
			/* fsapi_volume *vol */
			vol);

	sys_log_debug("%s(req=%p, ino=0x%lX, nlookup=%lu)",
		__FUNCTION__, req, ino, nlookup);

	err = fsapi_node_release(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node **node */
		&node,
		/* size_t release_count */
		nlookup);
	if(err) {
		sys_log_perror(err, "Error while releasing node (ignored)");
	}

	sys_log_debug("%s(req=%p, ino=0x%lX, nlookup=%lu): %d (%s)",
		__FUNCTION__, req, ino, nlookup, 0, strerror(0));

	fuse_reply_none(req);
}

static void refs_fuse_ll_op_getattr(
		fuse_req_t req,
		fuse_ino_t ino,
		struct fuse_file_info *fi)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_req_userdata(req);
	fsapi_node *const node =
		refs_fuse_ll_fuse_ino_to_node(
			/* fuse_ino_t ino */
			ino,
			/* fsapi_volume *vol */
			vol);

	int err = 0;
	fsapi_node_attributes attributes;
	struct FUSE_STAT stbuf;

	memset(&attributes, 0, sizeof(attributes));

	sys_log_debug("%s(req=%p, ino=0x%lX, fi=%p)",
		__FUNCTION__, req, ino, fi);

	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS;

	err = fsapi_node_get_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* fsapi_node_attributes *out_attributes */
		&attributes);
	if(err) {
		goto out;
	}

	err = refs_fuse_fill_stat(
		/* struct stat *stbuf */
		&stbuf,
		/* const fsapi_node_attributes *attributes */
		&attributes);
out:
	sys_log_debug("%s(req=%p, ino=0x%lX, fi=%p): %d (%s)",
		__FUNCTION__, req, ino, fi, err, strerror(err));

	if(err) {
		fuse_reply_err(req, err);
	}
	else {
		fuse_reply_attr(req, &stbuf, 3600);
	}
}

static void refs_fuse_ll_op_open(
		fuse_req_t req,
		fuse_ino_t ino,
		struct fuse_file_info *fi)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_req_userdata(req);
	fsapi_node *const node =
		refs_fuse_ll_fuse_ino_to_node(
			/* fuse_ino_t ino */
			ino,
			/* fsapi_volume *vol */
			vol);

	int err = 0;
	fsapi_node_attributes attributes;

	sys_log_debug("%s(req=%p, ino=0x%lX, fi=%p)",
		__FUNCTION__, req, ino, fi);

	memset(&attributes, 0, sizeof(attributes));

	err = fsapi_node_get_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* fsapi_node_attributes *out_attributes */
		&attributes);
	if(err) {
		goto out;
	}
	else if(attributes.is_directory) {
		err = EISDIR;
		goto out;
	}

	/* No need to invalidate caches. This is read-only data. */
	fi->keep_cache = 1;
out:
	sys_log_debug("%s(req=%p, ino=0x%lX, fi=%p): %d (%s)",
		__FUNCTION__, req, ino, fi, -err, strerror(err));

	if(err) {
		fuse_reply_err(req, err);
	}
	else {
		fuse_reply_open(req, fi);
	}
}

static void refs_fuse_ll_op_read(
		fuse_req_t req,
		fuse_ino_t ino,
		size_t size,
		off_t off,
		struct fuse_file_info *fi)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_req_userdata(req);
	fsapi_node *const node =
		refs_fuse_ll_fuse_ino_to_node(
			/* fuse_ino_t ino */
			ino,
			/* fsapi_volume *vol */
			vol);

	int err = 0;
	void *buf = NULL;
	fsapi_iohandler_buffer_context iohandler_context;
	fsapi_iohandler iohandler;

	memset(&iohandler_context, 0, sizeof(iohandler_context));
	memset(&iohandler, 0, sizeof(iohandler));

	sys_log_debug("%s(req=%p, ino=0x%lX, size=%" PRIuz ", off=%" PRId64 ", "
		"fi=%p)",
		__FUNCTION__, req, ino, PRAuz(size), PRAd64(off), fi);

	err = sys_malloc(size, &buf);
	if(err) {
		goto out;
	}

	iohandler_context.buf.rw = buf;
	iohandler_context.remaining_size = size;
	iohandler_context.is_read = SYS_TRUE;
	iohandler.context = &iohandler_context;
	iohandler.handle_io = fsapi_iohandler_buffer_handle_io;
	iohandler.copy_data = fsapi_iohandler_buffer_copy_data;

	err = fsapi_node_read(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* u64 offset */
		off,
		/* size_t size */
		size,
		/* fsapi_iohandler *iohandler */
		&iohandler);
out:
	sys_log_debug("%s(req=%p, ino=0x%lX, size=%" PRIuz ", off=%" PRId64 ", "
		"fi=%p): %" PRIdz " (%s)",
		__FUNCTION__, req, ino, PRAuz(size), PRAd64(off), fi,
		PRAdz(err), strerror(err));

	if(err) {
		fuse_reply_err(req, err);
	}
	else {
		fuse_reply_buf(req, buf,
			size - iohandler_context.remaining_size);
	}

	if(buf) {
		sys_free(&buf);
	}
}

static void refs_fuse_ll_op_statfs(
		fuse_req_t req,
		fuse_ino_t ino)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_req_userdata(req);

	int err = 0;
	fsapi_volume_attributes attributes;
	struct statvfs stvbuf;

	memset(&attributes, 0, sizeof(attributes));

	sys_log_debug("%s(req=%p, ino=0x%lX)",
		__FUNCTION__, req, ino);

	attributes.requested =
		FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_SIZE |
		FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_COUNT |
		FSAPI_VOLUME_ATTRIBUTE_TYPE_FREE_BLOCKS;

	err = fsapi_volume_get_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_volume_attributes *out_attrs */
		&attributes);
	if(err) {
		goto out;
	}

	memset(&stvbuf, 0, sizeof(stvbuf));
	if(attributes.valid & FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_SIZE) {
		stvbuf.f_bsize = attributes.block_size;
	}

	if(attributes.valid & FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_COUNT) {
		stvbuf.f_blocks = attributes.block_count;
	}

	if(attributes.valid & FSAPI_VOLUME_ATTRIBUTE_TYPE_FREE_BLOCKS) {
		stvbuf.f_bfree = attributes.free_blocks;
	}
out:
	sys_log_debug("%s(req=%p, ino=0x%lX): %d (%s)",
		__FUNCTION__, req, ino, err, strerror(err));

	if(err) {
		fuse_reply_err(req, err);
	}
	else {
		fuse_reply_statfs(req, &stvbuf);
	}
}

static void refs_fuse_ll_op_release(
		fuse_req_t req,
		fuse_ino_t ino,
		struct fuse_file_info *fi)
{
	int err = 0;

	sys_log_debug("%s(req=%p, ino=0x%lX, fi=%p)",
		__FUNCTION__, req, ino, fi);

	sys_log_debug("%s(req=%p, ino=0x%lX, fi=%p): %d (%s)",
		__FUNCTION__, req, ino, fi, err, strerror(err));

	fuse_reply_err(req, err);
}

typedef struct {
	fuse_req_t req;
	char *dirbuf;
	size_t size;
	off_t offset;
	off_t current_offset;
} refs_fuse_ll_readdir_context;

static int refs_fuse_ll_filldir(
		refs_fuse_ll_readdir_context *context,
		const char *file_name,
		size_t file_name_length,
		fsapi_node_attributes *attributes)
{
	int err = 0;
	struct FUSE_STAT stbuf;
	size_t bytes_written;

	if(context->current_offset < context->offset) {
		++context->current_offset;
		goto out;
	}

	err = refs_fuse_fill_stat(
		/* struct FUSE_STAT *stbuf */
		&stbuf,
		/* const fsapi_node_attributes *attributes */
		attributes);
	if(err) {
		goto out;
	}

	/* We assume that file_name is NULL-terminated. This may be a bad choice
	 * for future changes but it simplifies things here. */
	(void) file_name_length;

	++context->current_offset;

	sys_log_debug("Adding direntry \"%s\" to buffer with size "
		"%" PRIuz "...",
		file_name, PRAuz(context->size));
	bytes_written = fuse_add_direntry(
		/* fuse_req_t req */
		context->req,
		/* char *buf */
		context->dirbuf,
		/* size_t bufsize */
		context->size,
		/* const char *name */
		file_name,
		/* const struct stat *stbuf */
		&stbuf,
		/* off_t off */
		context->current_offset);
	sys_log_debug("Finished adding direntry \"%s\" to buffer with size "
		"%" PRIuz ".",
		file_name, PRAuz(context->size));
	if(bytes_written > context->size) {
		/* No more space in buffer. */
		err = -1;
		goto out;
	}

	context->size -= bytes_written;
	context->dirbuf = &context->dirbuf[bytes_written];
out:
	return err;
}

static int refs_fuse_ll_op_readdir_handle_dirent(
		void *context,
		const char *name,
		size_t name_length,
		fsapi_node_attributes *attributes)
{
	int err = 0;

	err = refs_fuse_ll_filldir(
		/* refs_fuse_ll_readdir_context *context */
		(refs_fuse_ll_readdir_context*) context,
		/* const char *file_name */
		name,
		/* size_t file_name_length */
		name_length,
		/* fsapi_node_attributes *attributes */
		attributes);

	return err;
}

static void refs_fuse_ll_op_readdir(
		fuse_req_t req,
		fuse_ino_t ino,
		size_t size,
		off_t off,
		struct fuse_file_info *fi)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_req_userdata(req);
	fsapi_node *const node =
		refs_fuse_ll_fuse_ino_to_node(
			/* fuse_ino_t ino */
			ino,
			/* fsapi_volume *vol */
			vol);

	int err = 0;
	char *dirbuf = NULL;
	refs_fuse_ll_readdir_context context;
	fsapi_node_attributes attributes;

	memset(&context, 0, sizeof(context));
	memset(&attributes, 0, sizeof(attributes));

	sys_log_debug("%s(req=%p, ino=0x%lX, size=%" PRIuz ", off=%" PRId64 ", "
		"fi=%p)",
		__FUNCTION__, req, ino, PRAuz(size), PRAd64(off), fi);

	err = sys_malloc(size, &dirbuf);
	if(err) {
		goto out;
	}

	context.req = req;
	context.dirbuf = dirbuf;
	context.size = size;

	if(off < 1) {
		struct stat stbuf;
		size_t bytes_written;

		memset(&stbuf, 0, sizeof(stbuf));
		stbuf.st_mode = S_IFDIR;

		sys_log_debug("Adding direntry \"%s\" to buffer with size "
			"%" PRIuz "...",
			".", PRAuz(context.size));
		bytes_written = fuse_add_direntry(
			/* fuse_req_t req */
			req,
			/* char *buf */
			context.dirbuf,
			/* size_t bufsize */
			context.size,
			/* const char *name */
			".",
			/* const struct stat *stbuf */
			&stbuf,
			/* off_t off */
			1);
		sys_log_debug("Finished adding direntry \"%s\" to buffer with "
			"size %" PRIuz "...",
			".", PRAuz(context.size));
		if(bytes_written > context.size) {
			/* No more space in buffer. */
			goto out;
		}

		context.size -= bytes_written;
		context.dirbuf = &context.dirbuf[bytes_written];
	}

	if(off < 2) {
		struct stat stbuf;
		size_t bytes_written;

		memset(&stbuf, 0, sizeof(stbuf));
		stbuf.st_mode = S_IFDIR;

		sys_log_debug("Adding direntry \"%s\" to buffer with size "
			"%" PRIuz "...",
			"..", PRAuz(context.size));
		bytes_written = fuse_add_direntry(
			/* fuse_req_t req */
			req,
			/* char *buf */
			context.dirbuf,
			/* size_t bufsize */
			context.size,
			/* const char *name */
			"..",
			/* const struct stat *stbuf */
			&stbuf,
			/* off_t off */
			2);
		sys_log_debug("Finished adding direntry \"%s\" to buffer with "
			"size %" PRIuz "...",
			"..", PRAuz(context.size));
		if(bytes_written > context.size) {
			/* No more space in buffer. */
			goto out;
		}

		context.size -= bytes_written;
		context.dirbuf = &context.dirbuf[bytes_written];
	}

	context.offset = off;
	context.current_offset = 2;

	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS;

	err = fsapi_node_list(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *directory_node */
		node,
		/* fsapi_node_attributes *attributes */
		&attributes,
		/* void *context */
		&context,
		/* int (*handle_dirent)(
		 *     void *context,
		 *     const char *name,
		 *     size_t name_length,
		 *     fsapi_node_attributes *attributes) */
		refs_fuse_ll_op_readdir_handle_dirent);
	if(err == -1) {
		/* No more space in buffer. */
		err = 0;
	}
	else if(err) {
		sys_log_perror(err, "Error while listing directory");
		goto out;
	}
out:
	sys_log_debug("%s(req=%p, ino=0x%lX, size=%" PRIuz ", off=%" PRId64 ", "
		"fi=%p): %d (%s)",
		__FUNCTION__, req, ino, PRAuz(size), PRAd64(off), fi, err,
		strerror(err));

	if(err) {
		fuse_reply_err(req, err);
	}
	else {
		fuse_reply_buf(req, dirbuf, size - context.size);
	}

	if(dirbuf) {
		sys_free(&dirbuf);
	}
}

#ifdef __APPLE__
static void refs_fuse_ll_op_getxattr(
		fuse_req_t req,
		fuse_ino_t ino,
		const char *name,
		size_t size,
		uint32_t position)
#else
static void refs_fuse_ll_op_getxattr(
		fuse_req_t req,
		fuse_ino_t ino,
		const char *name,
		size_t size)
#endif
{
#ifndef __APPLE__
	static const uint32_t position = 0;
#endif

	fsapi_volume *const vol =
		(fsapi_volume*) fuse_req_userdata(req);
	fsapi_node *const node =
		refs_fuse_ll_fuse_ino_to_node(
			/* fuse_ino_t ino */
			ino,
			/* fsapi_volume *vol */
			vol);

	int err = 0;
	void *buf = NULL;
	refs_fuse_getxattr_context context;
	fsapi_iohandler_buffer_context buffer_context;

	memset(&context, 0, sizeof(context));
	memset(&buffer_context, 0, sizeof(buffer_context));

	sys_log_debug("%s(req=%p, ino=0x%lX, name=\"%s\", size=%" PRIuz ", "
		"position=%" PRIu32 ")",
		__FUNCTION__, req, ino, name, PRAuz(size), PRAu32(position));

	if(!size) {
		context.name = name;
		context.name_length = strlen(name);

		err = fsapi_node_list_extended_attributes(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			node,
			/* void *context */
			&context,
			/* int (*xattr_handler)(
			 *     void *context,
			 *     const char *name,
			 *     size_t name_length,
			 *     size_t size) */
			refs_fuse_op_getxattr_xattr_handler);
		if(err == -1) {
			err = 0;
		}
		else if(err) {
			goto out;
		}
		else {
			err = ENOENT;
		}
	}
	else {
		fsapi_iohandler iohandler;

		memset(&iohandler, 0, sizeof(iohandler));

		buffer_context.buf.rw = buf;
		buffer_context.remaining_size = size;
		buffer_context.is_read = SYS_TRUE;

		iohandler.context = &buffer_context;
		iohandler.handle_io = fsapi_iohandler_buffer_handle_io;
		iohandler.copy_data = fsapi_iohandler_buffer_copy_data;

		err = fsapi_node_read_extended_attribute(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			node,
			/* const char *xattr_name */
			name,
			/* size_t xattr_name_length */
			strlen(name),
			/* u64 offset */
			position,
			/* size_t size */
			size,
			/* fsapi_iohandler *iohandler */
			&iohandler);
	}
	if(err == ENOENT) {
		/* Transform to ENOATTR (macOS/BSD) / ENODATA (Linux,
		 * ...?). */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
defined(__OpenBSD__) || defined(__DragonFly__)
		err = ENOATTR;
#else
		err = ENODATA;
#endif
	}
out:
	if(err) {
		fuse_reply_err(req, err);
	}
	else if(buf) {
		fuse_reply_buf(req, buf, size - buffer_context.remaining_size);
	}
	else {
		fuse_reply_xattr(req, context.size);
	}

	if(buf) {
		sys_free(&buf);
	}
}

static void refs_fuse_ll_op_listxattr(
		fuse_req_t req,
		fuse_ino_t ino,
		size_t size)
{
	fsapi_volume *const vol =
		(fsapi_volume*) fuse_req_userdata(req);
	fsapi_node *const node =
		refs_fuse_ll_fuse_ino_to_node(
			/* fuse_ino_t ino */
			ino,
			/* fsapi_volume *vol */
			vol);

	int err = 0;
	void *buf = NULL;
	refs_fuse_listxattr_context context;

	memset(&context, 0, sizeof(context));

	sys_log_debug("%s(req=%p, ino=0x%lX, size=%" PRIuz ")",
		__FUNCTION__, req, ino, PRAuz(size));

	if(size) {
		err = sys_malloc(size, &buf);
		if(err) {
			goto out;
		}

		context.buf = buf;
		context.size = size;
	}

	err = fsapi_node_list_extended_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* void *context */
		&context,
		/* int (*xattr_handler)(
		 *     void *context,
		 *     const char *name,
		 *     size_t name_length,
		 *     size_t size) */
		refs_fuse_op_listxattr_xattr_handler);
out:
	if(err) {
		fuse_reply_err(req, err);
	}
	else if(buf) {
		fuse_reply_buf(req, buf, size - context.size);
	}
	else {
		fuse_reply_xattr(req, context.size);
	}

	if(buf) {
		sys_free(&buf);
	}
}

static struct fuse_lowlevel_ops refs_fuse_ll_operations = {
	/* void (*lookup) (fuse_req_t req, fuse_ino_t parent,
	 *         const char *name); */
	.lookup = refs_fuse_ll_op_lookup,
	/* void (*forget) (fuse_req_t req, fuse_ino_t ino,
	 *         unsigned long nlookup); */
	.forget = refs_fuse_ll_op_forget,
	/* void (*getattr) (fuse_req_t req, fuse_ino_t ino,
	 *         struct fuse_file_info *fi); */
	.getattr = refs_fuse_ll_op_getattr,
	/* void (*open) (fuse_req_t req, fuse_ino_t ino,
	 *         struct fuse_file_info *fi); */
	.open = refs_fuse_ll_op_open,
	/* void (*read) (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
	 *         struct fuse_file_info *fi); */
	.read = refs_fuse_ll_op_read,
	/* void (*statfs) (fuse_req_t req, fuse_ino_t ino); */
	.statfs = refs_fuse_ll_op_statfs,
	/* void (*release) (fuse_req_t req, fuse_ino_t ino,
	 *         struct fuse_file_info *fi); */
	.release = refs_fuse_ll_op_release,
	/* void (*readdir) (fuse_req_t req, fuse_ino_t ino, size_t size,
	 *         off_t off, struct fuse_file_info *fi); */
	.readdir = refs_fuse_ll_op_readdir,
#ifdef __APPLE__
	/* void (*getxattr) (fuse_req_t req, fuse_ino_t ino, const char *name,
	 *         size_t size, uint32_t position); */
#else
	/* void (*getxattr) (fuse_req_t req, fuse_ino_t ino, const char *name,
	 *         size_t size); */
#endif
	.getxattr = refs_fuse_ll_op_getxattr,
	/* void (*listxattr) (fuse_req_t req, fuse_ino_t ino, size_t size); */
	.listxattr = refs_fuse_ll_op_listxattr,
};
#endif /* REFS_FUSE_USE_LOWLEVEL_API */

int main(int argc, char **argv)
{
	int err = 0;
	const char *device_name = NULL;
	const char *mount_point = NULL;
	sys_device *dev = NULL;
	fsapi_volume *vol = NULL;
#if REFS_FUSE_USE_LOWLEVEL_API
	int i;
	sys_bool foreground = SYS_FALSE;
	struct fuse_args args;
	struct fuse_chan *chan = NULL;
	struct fuse_session *ses = NULL;
	sys_bool signal_handlers_set = SYS_FALSE;
#endif /* REFS_FUSE_USE_LOWLEVEL_API */

	if(argc < 3) {
		fprintf(stderr, "usage: refs-fuse <device> <mountpoint> [fuse "
			"options...]\n");
		err = EINVAL;
		goto out;
	}

	device_name = argv[1];
	mount_point = argv[2];

	err = sys_device_open(&dev, device_name);
	if(err) {
		sys_log_perror(err, "Error while opening device \"%s\"",
			device_name);
		goto out;
	}

	err = fsapi_volume_mount(
		/* sys_device *dev */
		dev,
		/* sys_bool read_only */
		SYS_TRUE,
		/* const void *custom_mount_options */
		NULL,
		/* fsapi_volume **out_vol */
		&vol,
		/* fsapi_node **out_root_node */
		NULL,
		/* fsapi_volume_attributes *out_attrs */
		NULL);
	if(err) {
		sys_log_perror(err, "Error while mounting ReFS volume \"%s\"",
			argv[1]);
		goto out;
	}

#if REFS_FUSE_USE_LOWLEVEL_API
	/* Remove the device and mount point argument from FUSE options. */
	if(argc > 3) {
		memmove(&argv[1], &argv[3], (argc - 3) * sizeof(argv[0]));
	}
	argc -= 2;

	sys_log_debug("Args after trimming device/mount point:");
	for(i = 0; i < argc; ++i) {
		sys_log_debug("    [%d]: %s", i, argv[i]);
	}

	for(i = 1; i < argc; ++i) {
		sys_bool parsed = SYS_FALSE;

		if(!strcmp(argv[i], "-f")) {
			foreground = SYS_TRUE;
			parsed = SYS_TRUE;
		}

		if(parsed) {
			memmove(&argv[i], &argv[i + 1],
				(argc - (i + 1)) * sizeof(argv[0]));
			--argc;
		}
	}

	args.allocated = 0;
	args.argv = argv;
	args.argc = argc;

	sys_log_debug("FUSE args:");
	for(i = 0; i < args.argc; ++i) {
		sys_log_debug("    [%d]: %s", i, args.argv[i]);
	}

	chan = fuse_mount(
		/* const char *mountpoint */
		mount_point,
		/* struct fuse_args *args */
		&args);
	if(!chan) {
		err = EINVAL;
		goto out;
	}

	ses = fuse_lowlevel_new(
		/* struct fuse_args *args */
		&args,
		/* const struct fuse_lowlevel_ops *op */
		&refs_fuse_ll_operations,
		/* size_t op_size */
		sizeof(refs_fuse_ll_operations),
		/* void *userdata */
		vol);
	if(!ses) {
		err = EINVAL;
		goto out;
	}

	if(fuse_set_signal_handlers(
		/* struct fuse_session *se */
		ses) == -1)
	{
		err = EINVAL;
		goto out;
	}

	signal_handlers_set = SYS_TRUE;

	fuse_session_add_chan(
		/* struct fuse_session *se */
		ses,
		/* struct fuse_chan *ch */
		chan);

	if(!foreground) {
		fuse_daemonize(0);
	}

	err = fuse_session_loop(
		/* struct fuse_session *se */
		ses);

	fuse_session_remove_chan(
		/* struct fuse_chan *ch */
		chan);
#else
	/* Shuffle arguments around for 'fuse_main'. The mountpoint should be
	 * the first non-option argument and the device should not be passed on,
	 * but we add the '-s' switch to enforce single-threaded operation. */
	argv[1] = argv[2];
	argv[2] = "-s";

	if(fuse_main(argc, argv, &refs_fuse_operations, vol)) {
		err = EIO;
	}
#endif /* REFS_FUSE_USE_LOWLEVEL_API ... */
out:
#if REFS_FUSE_USE_LOWLEVEL_API
	if(signal_handlers_set) {
		fuse_remove_signal_handlers(
			/* struct fuse_session *se */
			ses);
	}

	if(ses) {
		fuse_session_destroy(
			/* struct fuse_session *se */
			ses);
	}

	if(chan) {
		fuse_unmount(
			/* const char *mountpoint */
			mount_point,
			/* struct fuse_chan *ch */
			chan);
	}
#endif /* REFS_FUSE_USE_LOWLEVEL_API */

	if(vol) {
		int unmount_err;

		unmount_err = fsapi_volume_unmount(
			/* fsapi_volume **vol */
			&vol);
		if(unmount_err) {
			sys_log_perror(unmount_err, "Error while unmounting "
				"volume");
			err = err ? err : unmount_err;
		}
	}

	if(dev) {
		sys_device_close(&dev);
	}

	return err ? (EXIT_FAILURE) : (EXIT_SUCCESS);
}
