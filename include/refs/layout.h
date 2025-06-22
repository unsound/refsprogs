/*-
 * layout.h - ReFS on-disk layout struct definitions.
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

#ifndef _REFS_LAYOUT_H
#define _REFS_LAYOUT_H

#include "sys.h"

#define REFS_FILE_ATTRIBUTE_READONLY                              (0x00000001UL)
#define REFS_FILE_ATTRIBUTE_HIDDEN                                (0x00000002UL)
#define REFS_FILE_ATTRIBUTE_SYSTEM                                (0x00000004UL)
#define REFS_FILE_ATTRIBUTE_DIRECTORY                             (0x00000010UL)
#define REFS_FILE_ATTRIBUTE_ARCHIVE                               (0x00000020UL)
#define REFS_FILE_ATTRIBUTE_DEVICE                                (0x00000040UL)
#define REFS_FILE_ATTRIBUTE_NORMAL                                (0x00000080UL)
#define REFS_FILE_ATTRIBUTE_TEMPORARY                             (0x00000100UL)
#define REFS_FILE_ATTRIBUTE_SPARSE_FILE                           (0x00000200UL)
#define REFS_FILE_ATTRIBUTE_REPARSE_POINT                         (0x00000400UL)
#define REFS_FILE_ATTRIBUTE_COMPRESSED                            (0x00000800UL)
#define REFS_FILE_ATTRIBUTE_OFFLINE                               (0x00001000UL)
#define REFS_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED                   (0x00002000UL)
#define REFS_FILE_ATTRIBUTE_ENCRYPTED                             (0x00004000UL)
#define REFS_FILE_ATTRIBUTE_INTEGRITY_STREAM                      (0x00008000UL)
#define REFS_FILE_ATTRIBUTE_VIRTUAL                               (0x00010000UL)
#define REFS_FILE_ATTRIBUTE_NO_SCRUB_DATA                         (0x00020000UL)
#define REFS_FILE_ATTRIBUTE_EA                                    (0x00040000UL)
#define REFS_FILE_ATTRIBUTE_PINNED                                (0x00080000UL)
#define REFS_FILE_ATTRIBUTE_UNPINNED                              (0x00100000UL)
#define REFS_FILE_ATTRIBUTE_RECALL_ON_OPEN                        (0x00040000UL)
#define REFS_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS                 (0x00400000UL)

typedef struct {
	le32 data1;
	le16 data2;
	le16 data3;
	unsigned char data4[8];
} REFS_GUID;

/**
 * The boot sector of a ReFS volume.
 */
typedef struct {
	u8 jump[3];                                   /* offset = 0x0       0 */
	u8 oem_id[4];                                 /* offset = 0x3       3 */
	u8 reserved7[9];                              /* offset = 0x7       7 */
	u8 signature[4];                              /* offset = 0x10     16 */
	u8 reserved20[4];                             /* offset = 0x14     20 */
	le64 num_sectors;                             /* offset = 0x18     24 */
	le32 bytes_per_sector;                        /* offset = 0x20     32 */
	le32 sectors_per_cluster;                     /* offset = 0x24     36 */
	u8 version_major;                             /* offset = 0x28     40 */
	u8 version_minor;                             /* offset = 0x29     41 */
	le16 reserved42;                              /* offset = 0x2A     42 */
	le32 reserved44;                              /* offset = 0x2C     44 */
	le64 reserved48;                              /* offset = 0x30     48 */
	le64 serial_number;                           /* offset = 0x38     56 */
	u8 reserved64[448];                           /* offset = 0x40     64 */
	                                              /* size   = 0x200   512 */
} __attribute__ ((__packed__)) REFS_BOOT_SECTOR;


typedef struct {
	le64 block_number;                            /* offset = 0x0       0 */
	le64 unknown_0x8;                             /* offset = 0x8       8 */
	le64 unknown_0x10;                            /* offset = 0x10     16 */
	le64 object_id;                               /* offset = 0x18     24 */
	le64 unknown_0x20;                            /* offset = 0x20     32 */
	le64 unknown_0x28;                            /* offset = 0x28     40 */
	                                              /* size   = 0x30     48 */
} __attribute__((__packed__)) REFS_V1_BLOCK_HEADER;

typedef struct {
	u8 signature[4];                              /* offset = 0x0       0 */
	le32 unknown_0x4;                             /* offset = 0x4       4 */
	le32 unknown_0x8;                             /* offset = 0x8       8 */
	le32 unknown_0xC;                             /* offset = 0xC      12 */
	le64 unknown_0x10;                            /* offset = 0x10     16 */
	le64 unknown_0x18;                            /* offset = 0x18     24 */
	le64 block_number;                            /* offset = 0x20     32 */
	le64 unknown_0x28;                            /* offset = 0x28     40 */
	le64 unknown_0x30;                            /* offset = 0x30     48 */
	le64 unknown_0x38;                            /* offset = 0x38     56 */
	le64 unknown_0x40;                            /* offset = 0x40     64 */
	le64 object_id;                               /* offset = 0x48     72 */
	                                              /* size   = 0x50     80 */
} __attribute__((__packed__)) REFS_V3_BLOCK_HEADER;

typedef struct {
	le64 self_block_index;                        /* offset = 0x0       0 */
	le64 reserved8;                               /* offset = 0x8       8 */
	le64 reserved16;                              /* offset = 0x10     16 */
	le64 reserved24;                              /* offset = 0x18     24 */
	le64 reserved32;                              /* offset = 0x20     32 */
	le64 reserved40;                              /* offset = 0x28     40 */
	REFS_GUID block_guid;                         /* offset = 0x30     48 */
	le64 reserved64;                              /* offset = 0x40     64 */
	le64 reserved72;                              /* offset = 0x48     72 */
	le32 level1_blocks_offset;                    /* offset = 0x50     80 */
	le32 level1_blocks_count;                     /* offset = 0x54     84 */
	le32 self_extents_offset;                     /* offset = 0x58     88 */
	le32 self_extents_size;                       /* offset = 0x5C     92 */
	                                              /* size   = 0x60     96 */
} __attribute__((__packed__)) REFS_V1_SUPERBLOCK_HEADER;

typedef struct {
	/**
	 * The signature of the superblock. Should be "SUPB".
	 */
	u8 signature[4];                              /* offset = 0x0       0 */

	/**
	 * Unknown field. Observed values: 2 / 0x00000002
	 *
	 * This field is 2 for all metadata blocks. May be a struct version
	 * number or a metadata counter for COW trees or something.
	 */
	le32 reserved4;                               /* offset = 0x4       4 */

	/**
	 * Unknown field. Observed values: 0
	 *
	 * This field is 0 for all descendant blocks. Could be part of the above
	 * block in which case it's a 64-bit field.
	 */
	le32 reserved8;                               /* offset = 0x8       8 */

	/**
	 * Unknown field. Observed values: 0xbebdd167
	 *
	 * The same value occurs all over the metadata table at offset 12 in
	 * metadata blocks. It's possible that it's some sort of version number
	 * to identify the tree. Or just an identifier that links the descendant
	 * metadata blocks to the superblock as a volume id.
	 *
	 */
	le32 reserved12;                              /* offset = 0xC      12 */

	/**
	 * Unknown range. Observed to be zeroed.
	 */
	u8 reserved16[16];                            /* offset = 0x10     16 */

	/**
	 * Self-referencing cluster/block number. Observed to be equal to the
	 * cluster number of the block.
	 */
	le64 self_block_index;                        /* offset = 0x20     32 */

	/**
	 * Unknown range. Observed to be zeroed.
	 */
	u8 reserved40[40];                            /* offset = 0x28     40 */

	/**
	 * 128-bit stream of bytes that seem random. Looks like a GUID.
	 */
	REFS_GUID block_guid;                         /* offset = 0x50     80 */

	/**
	 * Unknown field. Observed values: 0
	 */
	le64 reserved96;                              /* offset = 0x60     96 */

	/**
	 * Unknown field. Observed values: 1
	 * Possibly the start of a new struct.
	 */
	le64 reserved104;                             /* offset = 0x68    104 */

	/**
	 * Unknown field. Observed values: 12 / 0x0000000C
	 */
	le32 reserved112;                             /* offset = 0x70    112 */

	/**
	 * Unknown field. Observed values: 2 / 0x00000002
	 */
	le32 reserved116;                             /* offset = 0x74    116 */

	/**
	 * Unknown field. Observed values: 13 / 0x0000000D
	 */
	le32 reserved120;                             /* offset = 0x78    120 */

	/**
	 * Unknown field. Observed values: 104 / 0x00000068
	 * Byte offset of the header relative to the start of the block?
	 */
	le32 reserved124;                             /* offset = 0x7C    124 */

	/**
	 * Unknown range. Observed to be zeroed.
	 */
	u8 reserved128[64];                           /* offset = 0x80    128 */

	/**
	 * Unknown field. Observed values: 121440 / 0x1DA60
	 */
	le64 reserved192;                             /* offset = 0xC0    192 */

	/**
	 * Unknown field. Observed values: 1456896 / 0x163B00
	 */
	le64 reserved200;                             /* offset = 0xC8    200 */

	/**
	 * Unknown field. Observed values: 30 / 0x1E
	 * Another self cluster reference to the start of the metadata block?
	 */
	le64 reserved208;                             /* offset = 0xD0    208 */

	/**
	 * Unknown field. Observed values: 0
	 */
	le64 reserved216;                             /* offset = 0xD8    216 */

	/**
	 * Unknown field. Observed values: 0
	 */
	le64 reserved224;                             /* offset = 0xE0    224 */

	/**
	 * Unknown field. Observed values: 0
	 */
	le64 reserved232;                             /* offset = 0xE8    232 */

	/**
	 * Unknown field. Observed values: 0x08010000
	 * The fact that bits are set in random places makes me think this is a
	 * 32-bit flags field.
	 */
	le32 reserved240;                             /* offset = 0xF0    240 */

	/**
	 * Unknown field. Observed values: 4
	 * May be part of the previous field, in which case it could be a 64-bit
	 * flags field with observed value 0x408010000.
	 */
	le32 reserved244;                             /* offset = 0xF4    244 */

	/**
	 * Unknown field. Observed values: 231767958 / 0x000000000DD07F96
	 */
	le64 reserved248;                             /* offset = 0xF8    248 */
	                                              /* size   = 0x100   256 */
} __attribute__ ((__packed__)) REFS_V3_SUPERBLOCK_HEADER;

typedef union {
	REFS_V1_SUPERBLOCK_HEADER v1;
	REFS_V3_SUPERBLOCK_HEADER v3;
} __attribute__ ((__packed__)) REFS_SUPERBLOCK_HEADER;

typedef struct {
	le64 block_number;                            /* offset = 0x0       0 */
	le64 reserved40;                              /* offset = 0x8       8 */
	le64 reserved48;                              /* offset = 0x10     16 */
	le64 reserved56;                              /* offset = 0x18     24 */
	le64 reserved64;                              /* offset = 0x20     32 */
	le64 object_id;                               /* offset = 0x28     40 */
	                                              /* size   = 0x30     48 */
} __attribute__ ((__packed__)) REFS_V1_NODE_HEADER;

typedef struct {
	u8 signature[4];                              /* offset = 0x0       0 */
	le32 reserved4;                               /* offset = 0x4       4 */
	le32 reserved8;                               /* offset = 0x8       8 */
	le32 checksum;                                /* offset = 0xC      12 */
	le64 reserved16;                              /* offset = 0x10     16 */
	le64 reserved24;                              /* offset = 0x18     24 */
	le64 block_numbers[4];                        /* offset = 0x20     32 */
	le64 reserved64;                              /* offset = 0x40     64 */
	le64 object_id;                               /* offset = 0x48     72 */
	                                              /* size   = 0x50     80 */
} __attribute__ ((__packed__)) REFS_V3_NODE_HEADER;

typedef struct {
	REFS_V1_NODE_HEADER header;                   /* offset = 0x0       0 */
	le32 unknown48;                               /* offset = 0x30     48 */
	le16 unknown52;                               /* offset = 0x34     52 */
	le16 unknown54;                               /* offset = 0x36     54 */
	le32 unknown56;                               /* offset = 0x38     56 */

} __attribute__ ((__packed__)) REFS_V1_LEVEL1_NODE;

typedef struct {
	REFS_V3_NODE_HEADER header;                   /* offset = 0x0       0 */
	le32 unknown48;                               /* offset = 0x50     80 */
	le16 unknown52;                               /* offset = 0x54     84 */
	le16 unknown54;                               /* offset = 0x56     86 */
	le32 offset_of_self_reference;                /* offset = 0x58     88 */
	le32 size_of_self_reference;                  /* offset = 0x5C     92 */
	le64 unknown96;                               /* offset = 0x60     96 */
	le64 unknown104;                              /* offset = 0x68    104 */
	le64 unknown112;                              /* offset = 0x70    112 */
	le32 unknown120;                              /* offset = 0x78    120 */
	le32 unknown124;                              /* offset = 0x7C    124 */
	le32 unknown128;                              /* offset = 0x80    128 */
	le32 unknown132;                              /* offset = 0x84    132 */
	le32 unknown136;                              /* offset = 0x88    136 */
	le32 unknown140;                              /* offset = 0x8C    140 */
	le32 level2_blocks_count;                     /* offset = 0x90    144 */
	le32 level2_blocks[];                         /* offset = 0x90    144 */
} __attribute__ ((__packed__)) REFS_V3_LEVEL1_NODE;

typedef union {
	REFS_V1_LEVEL1_NODE v1;
	REFS_V3_LEVEL1_NODE v3;
} __attribute__ ((__packed__)) REFS_LEVEL1_NODE;

/**
 * Tests if the version number is at least @p major.minor and returns
 * @ref SYS_TRUE if it is (@ref SYS_FALSE otherwise).
 */
#define REFS_VERSION_MIN(actual_major, actual_minor, min_major, min_minor) \
	(((actual_major) > (min_major) || \
	((actual_major) == (min_major) && (actual_minor) >= (min_minor))) ? \
	SYS_TRUE : SYS_FALSE)

#endif /* _REFS_LAYOUT_H */
