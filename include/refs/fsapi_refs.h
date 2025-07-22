#ifndef _REFS_FSAPI_REFS_H
#define _REFS_FSAPI_REFS_H

typedef enum {
	FSAPI_REFS_XATTR_MODE_NONE = 0,
	FSAPI_REFS_XATTR_MODE_STREAMS,
	FSAPI_REFS_XATTR_MODE_EAS,
	FSAPI_REFS_XATTR_MODE_BOTH,
} fsapi_refs_xattr_mode;

typedef struct {
	fsapi_refs_xattr_mode xattr_mode;
} fsapi_refs_custom_mount_options;

#endif /* _REFS_FSAPI_REFS_H */
