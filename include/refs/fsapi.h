/*-
 * fsapi.h - ReFS public file system API (declarations).
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

#ifndef _REFS_FSAPI_H
#define _REFS_FSAPI_H

#include "sys.h"

typedef struct fsapi_volume fsapi_volume;

typedef enum {
	FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_SIZE = 0x1,
	FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_COUNT = 0x2,
	FSAPI_VOLUME_ATTRIBUTE_TYPE_FREE_BLOCKS = 0x4,
	FSAPI_VOLUME_ATTRIBUTE_TYPE_VOLUME_NAME = 0x10,
} fsapi_volume_attribute_types;

typedef struct {
	/**
	 * A bitmask of the attributes that are requested by the caller.
	 */
	fsapi_volume_attribute_types requested;

	/**
	 * The attributes that are filled in by the fsapi function. If an
	 * attribute is requested but not valid after a successful call to the
	 * fsapi function then it is not supported by the filesystem or the
	 * node.
	 *
	 * Note: An unsupported attribute does not result in an error thrown by
	 * the function.
	 */
	fsapi_volume_attribute_types valid;

	/**
	 * The allocation block size of the volume, in bytes.
	 *
	 * This should be the smallest unit that can be allocated independently
	 * on the volume (e.g. non-resident data).
	 */
	u32 block_size;

	/**
	 * The total number of allocation blocks that the volume covers.
	 */
	u64 block_count;

	/**
	 * The number of allocation blocks that are free on the volume.
	 */
	u64 free_blocks;

	/**
	 * The name of the volume, as defined by the volume label.
	 */
	const char *volume_name;

	/**
	 * The length (in @p chars) of @p volume_name.
	 */
	size_t volume_name_length;
} fsapi_volume_attributes;

typedef struct fsapi_node fsapi_node;

typedef enum {
	FSAPI_NODE_ATTRIBUTE_TYPE_SIZE                          = 0x0001,
	FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE                = 0x0002,
	FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT                    = 0x0004,
	FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER                  = 0x0008,
	FSAPI_NODE_ATTRIBUTE_TYPE_MODE                          = 0x0010,
	FSAPI_NODE_ATTRIBUTE_TYPE_UID                           = 0x0020,
	FSAPI_NODE_ATTRIBUTE_TYPE_GID                           = 0x0040,
	FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME                 = 0x0080,
	FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME       = 0x0100,
	FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME         = 0x0200,
	FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME         = 0x0400,
	FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS                     = 0x0400,
	FSAPI_NODE_ATTRIBUTE_TYPE_WINDOWS_FLAGS                 = 0x0800,
	FSAPI_NODE_ATTRIBUTE_TYPE_SYMLINK_TARGET                = 0x1000,
	FSAPI_NODE_ATTRIBUTE_TYPE_ALL                           = 0x1FFF
} fsapi_node_attribute_types;

typedef struct {
	/**
	 * A bitmask of the attributes that are requested by the caller.
	 */
	fsapi_node_attribute_types requested;

	/**
	 * The attributes that are filled in by the fsapi function. If an
	 * attribute is requested but not valid after a successful invocation
	 * then it is not supported by the filesystem or the node.
	 *
	 * Note: An unsupported attribute does not result in an error thrown by
	 * the function.
	 */
	fsapi_node_attribute_types valid;

	/**
	 * @ref SYS_TRUE if this is directory, @ref SYS_FALSE if this is a file,
	 * symlink, device or other non-directory entry.
	 *
	 * This field is always filled in and doesn't have any bit reserved in
	 * @ref fsapi_node_attributes::requested or
	 * @ref fsapi_node_attributes::valid.
	 */
	sys_bool is_directory;

	/**
	 * The size of the node, in bytes.
	 */
	u64 size;

	/**
	 * The allocated size on disk, in bytes.
	 */
	u64 allocated_size;

	/**
	 * The number of links of the node.
	 */
	u64 link_count;

	/**
	 * The UNIX inode number of the node.
	 */
	u64 inode_number;

	/**
	 * The UNIX mode of the node.
	 */
	u32 mode;

	/**
	 * The UNIX owner user ID of the node.
	 */
	u32 uid;

	/**
	 * The UNIX owner group ID of the node.
	 */
	u32 gid;

	/**
	 * The time when this node was created, expressed as UNIX time (number
	 * of seconds and nanoseconds since 00:00:00, January 1, 1970 UTC).
	 */
	sys_timespec creation_time;

	/**
	 * The time when this node's metadata was last changed, expressed as
	 * UNIX time (number of seconds and nanoseconds since 00:00:00, January
	 * 1, 1970 UTC).
	 */
	sys_timespec last_status_change_time;

	/**
	 * The time when this node's data was last changed, expressed as UNIX
	 * time (number of seconds and nanoseconds since 00:00:00, January 1,
	 * 1970 UTC).
	 */
	sys_timespec last_data_change_time;

	/**
	 * The time when this node's data was last accessed, expressed as UNIX
	 * time (number of seconds and nanoseconds since 00:00:00, January 1,
	 * 1970 UTC).
	 */
	sys_timespec last_data_access_time;

	/**
	 * The BSD file flags of the node.
	 */
	u32 bsd_flags;

	/**
	 * The Windows file flags of the node.
	 */
	u32 windows_flags;

	/**
	 * The target of a symlink, as a string.
	 *
	 * If returned, and @p symlink_target is @ NULL then the target is
	 * returned as a @p NULL terminated string with the length matching
	 * @p size (excludes the @p NULL terminator).
	 *
	 * The returned string must be freed by the caller using @ref sys_free
	 * when the caller is done using it.
	 */
	char *symlink_target;

	/**
	 * The length of @p symlink_target, in bytes (excluding the @p NULL
	 * terminator).
	 *
	 * In the case of an fsapi-allocated buffer, the string will always have
	 * a @p NULL terminator.
	 *
	 * In the case of a preallocated buffer, set this to the buffer size
	 * before calling @ref fsapi_node_get_attributes. A @p NULLterminator
	 * will be inserted if there is room in the buffer, but in the case of a
	 * preallocated buffer it is not guaranteed.
	 * If the caller needs to guarantee a @p NULL terminated buffer, pass
	 * the buffer size minus one and set the final byte to @p NULL manually.
	 */
	size_t symlink_target_length;
} fsapi_node_attributes;

/**
 * The handler of an I/O operation, implementing a method to process it.
 */
typedef struct {
	/** The context that is passed to @ref fsapi_iohandler::handle_io. */
	void *context;

	/**
	 * The I/O handler callback function.
	 *
	 * Accepts a device, offset and size and processes I/O as implemented by
	 * the handler.
	 */
	int (*handle_io)(
		void *context,
		sys_device *dev,
		u64 offset,
		size_t size);

	/**
	 * Copies data from a memory buffer into the I/O handler's backend.
	 */
	int (*copy_data)(
		void *context,
		const void *data,
		size_t size);
} fsapi_iohandler;

typedef enum {
	FSAPI_RENAME_FLAG_EXCHANGE = 0x1,
	FSAPI_RENAME_FLAG_NOREPLACE = 0x2,
	FSAPI_RENAME_FLAG_WHITEOUT = 0x4
} fsapi_rename_flags;

typedef enum {
	FSAPI_NODE_EXTENDED_ATTRIBUTE_FLAG_CREATE = 0x1,
	FSAPI_NODE_EXTENDED_ATTRIBUTE_FLAG_REPLACE = 0x2,
	FSAPI_NODE_EXTENDED_ATTRIBUTE_FLAG_TRUNCATE = 0x4
} fsapi_node_extended_attribute_flags;

/**
 * Context for the buffer I/O handler.
 */
typedef struct {
	union {
		char *rw;
		const char *ro;
	} buf;
	size_t remaining_size;
	sys_bool is_read;
} fsapi_iohandler_buffer_context;

/**
 * I/O handler for the buffer I/O handler.
 *
 * @param context
 *      (in) The context for the I/O target handler (for this handler this is an
 *      @ref fsapi_iohandler_buffer_context).
 * @param dev
 *      (in) The @ref sys_device for which this I/O operation is to be peformed.
 * @param offset
 *      (in) The byte offset in @p dev where the I/O should start.
 * @param size
 *      (in) The number of bytes to process.
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_iohandler_buffer_handle_io(
		void *context,
		sys_device *dev,
		u64 offset,
		size_t size);

/**
 * Handler for copying data into the buffer (e.g. a read operation).
 *
 * @param context
 *      (in) The context for the I/O target handler (for this handler this is an
 *      @ref fsapi_iohandler_buffer_context).
 * @param buffer
 *      (in) The buffer from which the data should be copied.
 * @param size
 *      (in) The number of bytes to copy.
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_iohandler_buffer_copy_data(
		void *context,
		const void *buffer,
		size_t size);

/**
 * Handler for getting data from the buffer (e.g. a write operation).
 *
 * @param context
 *      (in) The context for the I/O target handler (for this handler this is an
 *      @ref fsapi_iohandler_buffer_context).
 * @param buffer
 *      (in) The buffer to which the data should be copied.
 * @param size
 *      (in) The number of bytes to copy.
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_iohandler_buffer_get_data(
		void *_context,
		void *buffer,
		size_t size);

/**
 * Mount device @p dev and return a @ref fsapi_volume reference along with the
 * root node of the volume (@p out_root_node) and optionally some or all of its
 * volume attributes.
 *
 * @param dev
 *      (in) The device that we are mounting.
 * @param read_only
 *      (in) Whether to mount the device read only or read/write (currently only
 *      read-only operation is supported).
 * @param custom_mount_options
 *      (in) Filesystem-specific mount options. The type and layout of these
 *      options is specified in a file-system specific header.
 * @param out_vol
 *      (out) Pointer to a field that will receive the @ref fsapi_volume of the
 *      mount, if successful.
 * @param out_root_node
 *      (out) Pointer to a field that will receive a pointer to the
 *      @ref fsapi_node of the root directory of the volume.
 * @param out_attrs
 *      (out) (optional) Pointer to a @ref fsapi_volume_attributes struct which
 *      will receive the volume attributes requested in the
 *      @ref fsapi_volume_attributes::requested bitmask, if supported (the
 *      bitmask @ref fsapi_volume_attributes::valid indicates whether the
 *      requested attribute is supported).
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_volume_mount(
		sys_device *dev,
		sys_bool read_only,
		const void *custom_mount_options,
		fsapi_volume **out_vol,
		fsapi_node **out_root_node,
		fsapi_volume_attributes *out_attrs);

/**
 * Get the root node of the volume.
 *
 * @param vol
 *      (in) The @ref fsapi_volume whose root node we want to retrieve.
 * @param out_root_node
 *      (out) Pointer to a field that will receive a pointer to the
 *      @ref fsapi_node of the root directory of the volume.
 */
void fsapi_volume_get_root_node(
		fsapi_volume *vol,
		fsapi_node **out_root_node);

/**
 * Get attributes of the volume.
 *
 * @param vol
 *      (in) The @ref fsapi_volume to query.
 * @param out_attrs
 *      (out) Pointer to a @ref fsapi_volume_attributes struct which will
 *      receive the volume attributes requested in the
 *      @ref fsapi_volume_attributes::requested bitmask, if supported (the
 *      bitmask @ref fsapi_volume_attributes::valid indicates whether the
 *      requested attribute is supported).
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_volume_get_attributes(
		fsapi_volume *vol,
		fsapi_volume_attributes *out_attrs);

int fsapi_volume_sync(
		fsapi_volume *vol);

/**
 * Unmount a volume.
 *
 * @param vol
 *      (in/out) Pointer to a field containing a @ref fsapi_volume pointer
 *      retrieved from calling @ref fsapi_volume_mount.
 *      The field containing the pointer will be set to @p NULL after a
 *      successful unmount.
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_volume_unmount(
		fsapi_volume **vol);

#if 0 /* Unnecessary if mount returns the root node. */
int fsapi_root(
		fsapi_volume *vol,
		fsapi_node **out_node);
#endif

/**
 * Look up a node on the volume.
 *
 * @param vol
 *      (in) The @p fsapi_volume of the mount.
 * @param parent_node
 *      (in) (optional) The node from which the lookup should start. If this is
 *      a lookup relative to the root directory, then @p NULL can be passed as
 *      parent node.
 * @param path
 *      (in) The name or path that should be looked up starting at
 *      @p parent_node. Pathname components are separated by '/'.
 * @param path_length
 *      (in) The length of @p path in @p chars.
 * @param out_child_node
 *      (out) Pointer to a field that will receive the child node.
 * @param out_attributes
 *      (out) (optional) Pointer to a @ref fsapi_node_attributes struct which
 *      will receive the volume attributes requested in the
 *      @ref fsapi_node_attributes::requested bitmask, if supported (the
 *      bitmask @ref fsapi_node_attributes::valid indicates whether the
 *      requested attribute is supported).
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_node_lookup(
		fsapi_volume *vol,
		fsapi_node *parent_node,
		const char *path,
		size_t path_length,
		fsapi_node **out_child_node,
		fsapi_node_attributes *out_attributes);

/**
 * Release the resources of a node acquired using @ref fsapi_node_lookup.
 *
 * @param vol
 *      (in) The @p fsapi_volume of the mount.
 * @param node
 *      (in/out) Pointer to a field referencing the @ref fsapi_node pointer. The
 *      field will be zeroed after releasing the node.
 * @param release_count
 *      (in) The number of references to release (usually 1).
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_node_release(
		fsapi_volume *vol,
		fsapi_node **node,
		size_t release_count);

/**
 * List a directory node and optionally return attributes for each entry.
 *
 * The @p handle_dirent callback will be called for each entry in the directory
 * with the supplied context passed to the first argument.
 *
 * If @p attributes is non-@p NULL then the attributes specified in the
 * @ref fsapi_node_attributes::requested bitmask will be returned with every
 * entry. The attribute buffer passed to the function will be reused to return
 * attributes to the callback.
 *
 * If @p attributes is @p NULL then no attempt at querying the node's attributes
 * will be done. The @p attributes pointer passed to @p handle_dirent will also
 * be @p NULL in this case.
 *
 * @param vol
 *      (in) The @p fsapi_volume of the mount.
 * @param directory_node
 *      (in) The directory node that we are listing.
 * @param attributes
 *      (in/out) (optional) A @ref fsapi_node_attributes buffer with the
 *      @ref fsapi_node_attributes::requested member filled in with the
 *      attributes to retrieve for each entry in the listing. If no attributes
 *      are needed then pass @p NULL here (or leave the
 *      @ref fsapi_node_attributes::requested member zeroed).
 * @param context
 *      (in) (optional) Caller provided context to pass to the @p handle_dirent
 *      callback.
 * @param handle_dirent
 *      (in) Callback to invoke for every entry in the directory.
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_node_list(
		fsapi_volume *vol,
		fsapi_node *directory_node,
		fsapi_node_attributes *attributes,
		void *context,
		int (*handle_dirent)(
			void *context,
			const char *name,
			size_t name_length,
			fsapi_node_attributes *attributes));

/**
 * Get attributes for a node.
 *
 * @param vol
 *      (in) The @p fsapi_volume of the mount.
 * @param node
 *      (in) The node whose attributes we are querying.
 * @param out_attributes
 *      (out) A pointer to a @ref fsapi_node_attributes struct with the
 *      @ref fsapi_node_attributes::requested bitmask filled in with the
 *      requested attributes.
 *      This function will populate @p attributes with the attributes that the
 *      filesystem supports and that are requested and indicate their presence
 *      in the @ref fsapi_node_attributes::valid bitmask.
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_node_get_attributes(
		fsapi_volume *vol,
		fsapi_node *node,
		fsapi_node_attributes *out_attributes);

/**
 * Set attributes for a node.
 *
 * @param vol
 *      (in) The @p fsapi_volume of the mount.
 * @param node
 *      (in) The node whose attributes we are querying.
 * @param attributes
 *      (in/out) A pointer to a @ref fsapi_node_attributes struct with the
 *      @ref fsapi_node_attributes::valid bitmask filled in with the attributes
 *      to set.
 *      After successfully setting attributes, this function will populate
 *      @p attributes with the attributes that the filesystem supports and that
 *      are requested and indicate their presence in the
 *      @ref fsapi_node_attributes::requested bitmask.
 *      The returned values may differ from the values initially passed to the
 *      function if the filesystem cannot store them in the requested precision.
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_node_set_attributes(
		fsapi_volume *vol,
		fsapi_node *node,
		fsapi_node_attributes *attributes);

/**
 * Get data for @p node in a filesystem-specific format that has to be
 * interpreted in a filesystem-specific way.
 *
 * @param vol
 *      (in) The @p fsapi_volume of the mount.
 * @param node
 *      (in) The node that we are querying.
 * @param out_raw_data
 *      (out) A pointer to a @p void* field that will receive the pointer to the
 *      raw data. The data should be freed by the caller using @ref sys_free.
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_node_get_raw_data(
		fsapi_volume *vol,
		fsapi_node *node,
		void **out_raw_data);

/**
 * Read from a file node.
 *
 * @param vol
 *      (in) The @p fsapi_volume of the mount.
 * @param node
 *      (in) The file node that we are reading from.
 * @param offset
 *      (in) The byte offset in the file where reading should start.
 * @param size
 *      (in) The number of bytes to read.
 * @param iohandler
 *      (in) The @ref fsapi_iohandler that will process the read parameters and
 *      perform the I/O.
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_node_read(
		fsapi_volume *vol,
		fsapi_node *node,
		u64 offset,
		size_t size,
		fsapi_iohandler *iohandler);

int fsapi_node_write(
		fsapi_volume *vol,
		fsapi_node *node,
		u64 offset,
		size_t size,
		fsapi_iohandler *iohandler);

int fsapi_node_sync(
		fsapi_volume *vol,
		fsapi_node *node,
		sys_bool data_only);

int fsapi_node_create(
		fsapi_volume *vol,
		fsapi_node *node,
		const char *name,
		size_t name_length,
		fsapi_node_attributes *attributes,
		fsapi_node **out_node);

int fsapi_node_hardlink(
		fsapi_volume *vol,
		fsapi_node *node,
		fsapi_node *link_parent,
		const char *link_name,
		size_t link_name_length,
		fsapi_node_attributes *out_attributes);

int fsapi_node_rename(
		fsapi_volume *vol,
		fsapi_node *source_dir_node,
		const char *source_name,
		size_t source_name_length,
		fsapi_node *target_dir_node,
		const char *target_name,
		size_t target_name_length,
		fsapi_rename_flags flags);

int fsapi_node_remove(
		fsapi_volume *vol,
		fsapi_node *parent_node,
		sys_bool is_directory,
		const char *name,
		size_t name_length,
		fsapi_node **out_removed_node);

/**
 * List the extended attributes of a node.
 *
 * @param vol
 *      (in) The @p fsapi_volume of the mount.
 * @param node
 *      (in) The node whose extended attributes we are listing.
 * @param context
 *      (in) Caller-provided context that will be passed to @p xattr_handler.
 * @param xattr_handler
 *      (in) Callback that will be invoked for each extended attribute found.
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_node_list_extended_attributes(
		fsapi_volume *vol,
		fsapi_node *node,
		void *context,
		int (*xattr_handler)(
			void *context,
			const char *name,
			size_t name_length,
			size_t size));

/**
 * Read from an extended attribute of a node.
 *
 * @param vol
 *      (in) The @p fsapi_volume of the mount.
 * @param node
 *      (in) The node containing the extended attribute that we are reading
 *      from.
 * @param xattr_name
 *      (in) The name of the extended attribute to read from.
 * @param xattr_name_length
 *      (in) The length of @p xattr_name, in @p chars.
 * @param offset
 *      (in) The byte offset in the file where reading should start.
 * @param size
 *      (in) The number of bytes to read.
 * @param iohandler
 *      (in) The @ref fsapi_iohandler that will process the read parameters and
 *      perform the extended attribute I/O.
 *
 * @return 0 on success and a non-0 @p errno value on failure.
 */
int fsapi_node_read_extended_attribute(
		fsapi_volume *vol,
		fsapi_node *node,
		const char *xattr_name,
		size_t xattr_name_length,
		u64 offset,
		size_t size,
		fsapi_iohandler *iohandler);

int fsapi_node_write_extended_attribute(
		fsapi_volume *vol,
		fsapi_node *node,
		const char *xattr_name,
		size_t xattr_name_length,
		fsapi_node_extended_attribute_flags flags,
		u64 offset,
		size_t size,
		fsapi_iohandler *iohandler);

int fsapi_node_remove_extended_attribute(
		fsapi_volume *vol,
		fsapi_node *node,
		const char *xattr_name,
		size_t xattr_name_length);

#endif /* _REFS_FSAPI_H */
