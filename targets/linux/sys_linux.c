/*-
 * sys_linux.c - Lightweight abstractions for system functionality (Linux).
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

#include "sys.h"

#include <linux/version.h>

#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/nls.h>

const char* sys_strerror(int err)
{
	switch(err) {
	case EPERM: return "EPERM";
	case ENOENT: return "ENOENT";
	case ESRCH: return "ESRCH";
	case EINTR: return "EINTR";
	case EIO: return "EIO";
	case ENXIO: return "ENXIO";
	case E2BIG: return "E2BIG";
	case ENOEXEC: return "ENOEXEC";
	case EBADF: return "EBADF";
	case ECHILD: return "ECHILD";
	case EAGAIN: return "EAGAIN";
	case ENOMEM: return "ENOMEM";
	case EACCES: return "EACCES";
	case EFAULT: return "EFAULT";
	case ENOTBLK: return "ENOTBLK";
	case EBUSY: return "EBUSY";
	case EEXIST: return "EEXIST";
	case EXDEV: return "EXDEV";
	case ENODEV: return "ENODEV";
	case ENOTDIR: return "ENOTDIR";
	case EISDIR: return "EISDIR";
	case EINVAL: return "EINVAL";
	case ENFILE: return "ENFILE";
	case EMFILE: return "EMFILE";
	case ENOTTY: return "ENOTTY";
	case ETXTBSY: return "ETXTBSY";
	case EFBIG: return "EFBIG";
	case ENOSPC: return "ENOSPC";
	case ESPIPE: return "ESPIPE";
	case EROFS: return "EROFS";
	case EMLINK: return "EMLINK";
	case EPIPE: return "EPIPE";
	case EDOM: return "EDOM";
	case ERANGE: return "ERANGE";
	default: return "<unknown>";
	}
}

int sys_unistr_decode(const refschar *ins, const size_t ins_len,
		char **const outs, size_t *const outs_len)
{
	int err = 0;
	size_t buf_capacity;
	char *buf = NULL;
	int len;

	if(!*outs) {
		/* Allocate a worst-case string, which is 3 times the number of
		 * characters of the UTF-16LE string times 4 to account for
		 * possible NFD decomposition (+1 for the NULL terminator). */
		buf_capacity = ins_len * (3 * 4) + 1;
		err = sys_malloc(buf_capacity, &buf);
		if(err) {
			goto out;
		}
	}
	else {
		buf_capacity = *outs_len;
		buf = *outs;
	}

	len = utf16s_to_utf8s(
		/* const wchar_t *pwcs */
		(const wchar_t*) ins,
		/* int inlen */
		ins_len,
		/* enum utf16_endian endian */
		UTF16_LITTLE_ENDIAN,
		/* u8 *s */
		buf,
		/* int maxout */
		buf_capacity - 1);
	if(len < 0) {
		err = -len;
		goto out;
	}

	if(*outs);
	else if(len < buf_capacity) {
		char *shrunk_buf = NULL;

		buf_capacity = (size_t) len + 1;
		err = sys_realloc(buf, buf_capacity, &shrunk_buf);
		if(err) {
			/* Shrinking an allocation should never fail? */
			goto out;
		}

		*outs = shrunk_buf;
	}
	else {
		--len;
		*outs = buf;
	}

	buf = NULL;

	(*outs)[len] = '\0';
	*outs_len = (size_t) len;
out:
	if(buf) {
		sys_free(&buf);
	}

	return err;
}

int sys_unistr_encode(const char *const ins, const size_t ins_len,
		refschar **outs, size_t *outs_len)
{
	int err = 0;
	size_t buf_capacity;
	refschar *buf = NULL;
	int len;

	if(!*outs) {
		/* The number of UTF-16 characters can at worst be equal to the
		 * number of UTF-8 characters, but sometimes less if e.g. the
		 * UTF-8 sequence encodes non-ASCII codepoints. If composition
		 * is applied it might be even fewer. */
		buf_capacity = (ins_len + 1) * sizeof(refschar);
		err = sys_malloc(buf_capacity, &buf);
		if(err) {
			goto out;
		}
	}
	else {
		buf_capacity = *outs_len;
		buf = *outs;
	}

	len = utf8s_to_utf16s(
		/* const u8 *s */
		ins,
		/* int len */
		ins_len,
		/* enum utf16_endian endian */
		UTF16_LITTLE_ENDIAN,
		/* wchar_t *pwcs */
		(wchar_t*) buf,
		/* int maxlen */
		buf_capacity / sizeof(refschar) - 1);
	if(len < 0) {
		err = -len;
		goto out;
	}

	if(*outs);
	else if(len < buf_capacity / sizeof(refschar)) {
		wchar_t *shrunk_buf = NULL;

		buf_capacity = ((size_t) len + 1) * sizeof(refschar);
		err = sys_realloc(buf, buf_capacity, &shrunk_buf);
		if(err) {
			/* Shrinking an allocation should never fail? */
			goto out;
		}

		*outs = shrunk_buf;
	}
	else {
		--len;
		*outs = buf;
	}

	buf = NULL;

	(*outs)[len] = cpu_to_le16(0);
	*outs_len = (size_t) len;
out:
	if(buf) {
		sys_free(&buf);
	}

	return err;
}

static int sys_device_pread_common(sys_device *const dev, const u64 offset,
		const size_t nbytes, void *const buf,
		sys_iohandler *const iohandler)
{
	struct super_block *const sb = (struct super_block*) dev;

	int err = 0;
	size_t bufp = 0;
	u64 block_index = 0;
	unsigned long offset_in_block = 0;
	size_t remaining = nbytes;
	struct buffer_head *bh = NULL;
	size_t bytes_read = 0;

	sys_log_debug("pread: offset=%" PRIu64 " nbytes=%" PRIuz,
		PRAu64(offset), PRAuz(nbytes));

	block_index = offset >> sb->s_blocksize_bits;
	offset_in_block =
		(unsigned long) (offset & (sb->s_blocksize - 1));
	while(remaining) {
		const size_t remaining_in_block =
			(remaining > sb->s_blocksize) ? sb->s_blocksize :
			remaining;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,7,0))
		const gfp_t gfp =
			__GFP_NOFAIL |
			mapping_gfp_constraint(
				/* struct address_space *mapping */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,10,0))
				sb->s_bdev->bd_mapping,
#else
				sb->s_bdev->bd_inode->i_mapping,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,10,0)) ... */
				/* gfp_t gfp_mask */
				~__GFP_FS);

		bh = bdev_getblk(
			/* struct block_device *bdev */
			sb->s_bdev,
			/* sector_t block */
			block_index,
			/* unsigned size */
			sb->s_blocksize,
			/* gfp_t gfp */
			gfp | __GFP_MOVABLE);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
		bh = __getblk_gfp(
			/* struct block_device *bdev */
			sb->s_bdev,
			/* sector_t block */
			block_index,
			/* unsigned size */
			sb->s_blocksize,
			/* gfp_t gfp */
			__GFP_MOVABLE);
#else
		bh = __getblk(
			/* struct block_device *bdev */
			sb->s_bdev,
			/* sector_t block */
			block_index,
			/* unsigned size */
			sb->s_blocksize);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,7,0)) ... */

		if(likely(bh) && !buffer_uptodate(
			/* const struct buffer_head *bh */
			bh))
		{
			lock_buffer(
				/* struct buffer_head *bh */
				bh);

			if(buffer_uptodate(
				/* const struct buffer_head *bh */
				bh))
			{
				unlock_buffer(
					/* struct buffer_head *bh */
					bh);
			}
			else {
				const int bh_flags =
					/* TODO: REQ_PRIO for metadata? */ 0;

				get_bh(
					/* struct buffer_head *bh */
					bh);

				bh->b_end_io = end_buffer_read_sync;

				submit_bh(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0))
					/* blk_opf_t opf */
					REQ_OP_READ | bh_flags,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0))
					/* enum req_op op */
					REQ_OP_READ,
					/* blk_opf_t op_flags */
					bh_flags,
#else
					/* int rw */
					READ | bh_flags,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)) ... */
					/* struct buffer_head *bh */
					bh);

				wait_on_buffer(
					/* struct buffer_head *bh */
					bh);

				if(!buffer_uptodate(
					/* const struct buffer_head *bh */
					bh))
				{
					sys_log_error("Buffer for block "
						"%" PRIu64 " still not up to "
						"date after waiting on it.",
						PRAu64(block_index));
					err = EIO;
					goto out;
				}
			}
		}

		if(buf) {
			memcpy(&((u8*) buf)[bufp], &bh->b_data[offset_in_block],
				remaining_in_block);
		}
		else {
			err = iohandler->copy_data(
				/* void *context */
				iohandler->context,
				/* const void *data */
				&bh->b_data[offset_in_block],
				/* size_t size */
				remaining_in_block);
			if(err) {
				goto out;
			}
		}

		brelse(
			/* struct buffer_head *bh */
			bh);
		bh = NULL;

		bufp += sb->s_blocksize - offset_in_block;
		offset_in_block = 0;
		++block_index;
		remaining -= remaining_in_block;
		bytes_read += remaining_in_block;
	}

	if(bytes_read != nbytes) {
		err = EIO;
	}
out:
	if(bh) {
		brelse(
			/* struct buffer_head *bh */
			bh);
	}

	return err;
}

int sys_device_pread(sys_device *const dev, const u64 offset,
		const size_t nbytes, void *const buf)
{
	return sys_device_pread_common(
		/* sys_device *dev */
		dev,
		/* u64 offset */
		offset,
		/* size_t nbytes */
		nbytes,
		/* void *buf */
		buf,
		/* sys_iohandler *iohandler */
		NULL);
}

int sys_device_pread_iohandler(sys_device *const dev, const u64 offset,
		const size_t nbytes, sys_iohandler *const iohandler)
{
	return sys_device_pread_common(
		/* sys_device *dev */
		dev,
		/* u64 offset */
		offset,
		/* size_t nbytes */
		nbytes,
		/* void *buf */
		NULL,
		/* sys_iohandler *iohandler */
		iohandler);
}

int sys_device_get_sector_size(sys_device *const dev,
		u32 *const out_sector_size)
{
	struct super_block *const sb = (struct super_block*) dev;

	*out_sector_size = bdev_logical_block_size(sb->s_bdev);

	return 0;
}

int sys_device_get_size(sys_device *const dev,
		u64 *const out_size)
{
	struct super_block *const sb = (struct super_block*) dev;

	*out_size =
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0))
		bdev_nr_bytes(sb->s_bdev);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,16,0)) */
		i_size_read(sb->s_bdev->bd_inode) &
		~((1ULL << SECTOR_SHIFT) - 1);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)) ... */

	return 0;
}
