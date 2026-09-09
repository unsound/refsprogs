#ifndef _REFS_FSAPI_REFS_H
#define _REFS_FSAPI_REFS_H

typedef enum {
	FSAPI_REFS_XATTR_MODE_NONE = 0,
	FSAPI_REFS_XATTR_MODE_STREAMS,
	FSAPI_REFS_XATTR_MODE_EAS,
	FSAPI_REFS_XATTR_MODE_BOTH,
} fsapi_refs_xattr_mode;

typedef enum {
	FSAPI_REFS_SYMLINK_MODE_RAW = 0,
	FSAPI_REFS_SYMLINK_MODE_POSIX
} fsapi_refs_symlink_mode;

typedef struct {
	char letter;
	size_t path_length;
	char *path;
} fsapi_refs_drive_mapping;

typedef struct {
	struct {
		sys_bool uid;
		sys_bool gid;
		sys_bool xattr_mode;
		sys_bool symlink_mode;
	} valid;

	u64 uid;
	u64 gid;
	fsapi_refs_xattr_mode xattr_mode;
	fsapi_refs_symlink_mode symlink_mode;

	size_t drive_mappings_length;
	fsapi_refs_drive_mapping *drive_mappings;
} fsapi_refs_custom_mount_options;

#endif /* _REFS_FSAPI_REFS_H */
