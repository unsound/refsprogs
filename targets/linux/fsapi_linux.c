/*-
 * fsapi_linux.c - Linux kernel backend for fsapi operations.
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

#include "fsapi_linux.h"

#include "sys.h"
#include "fsapi.h"

#include <linux/version.h>

#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/falloc.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0))
#include <linux/fileattr.h>
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)) */
#include <linux/iversion.h>
#include <linux/fs.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0))
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0)) */
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/xattr.h>

#ifndef FSAPI_LINUX_SLOW_SYNCHRONOUS_READ_PATH
#define FSAPI_LINUX_SLOW_SYNCHRONOUS_READ_PATH 0
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))
#define FSAPI_IF_LINUX_4_9(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_4_9(...)
#define FSAPI_IFELSE_LINUX_4_9(a, b) a
#else
#define FSAPI_IF_LINUX_4_9(...)
#define FSAPI_NOT_LINUX_4_9(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_4_9(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
#define FSAPI_IF_LINUX_4_11(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_4_11(...)
#define FSAPI_IFELSE_LINUX_4_11(a, b) a
#else
#define FSAPI_IF_LINUX_4_11(...)
#define FSAPI_NOT_LINUX_4_11(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_4_11(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
#define FSAPI_IF_LINUX_5_12(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_5_12(...)
#define FSAPI_IFELSE_LINUX_5_12(a, b) a
#else
#define FSAPI_IF_LINUX_5_12(...)
#define FSAPI_NOT_LINUX_5_12(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_5_12(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0))
#define FSAPI_IF_LINUX_5_13(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_5_13(...)
#define FSAPI_IFELSE_LINUX_5_13(a, b) a
#else
#define FSAPI_IF_LINUX_5_13(...)
#define FSAPI_NOT_LINUX_5_13(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_5_13(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0))
#define FSAPI_IF_LINUX_5_14(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_5_14(...)
#define FSAPI_IFELSE_LINUX_5_14(a, b) a
#else
#define FSAPI_IF_LINUX_5_14(...)
#define FSAPI_NOT_LINUX_5_14(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_5_14(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0))
#define FSAPI_IF_LINUX_5_15(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_5_15(...)
#define FSAPI_IFELSE_LINUX_5_15(a, b) a
#else
#define FSAPI_IF_LINUX_5_15(...)
#define FSAPI_NOT_LINUX_5_15(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_5_15(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0))
#define FSAPI_IF_LINUX_5_16(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_5_16(...)
#define FSAPI_IFELSE_LINUX_5_16(a, b) a
#else
#define FSAPI_IF_LINUX_5_16(...)
#define FSAPI_NOT_LINUX_5_16(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_5_16(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
#define FSAPI_IF_LINUX_5_17(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_5_17(...)
#define FSAPI_IFELSE_LINUX_5_17(a, b) a
#else
#define FSAPI_IF_LINUX_5_17(...)
#define FSAPI_NOT_LINUX_5_17(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_5_17(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
#define FSAPI_IF_LINUX_5_18(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_5_18(...)
#define FSAPI_IFELSE_LINUX_5_18(a, b) a
#else
#define FSAPI_IF_LINUX_5_18(...)
#define FSAPI_NOT_LINUX_5_18(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_5_18(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0))
#define FSAPI_IF_LINUX_5_19(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_5_19(...)
#define FSAPI_IFELSE_LINUX_5_19(a, b) a
#else
#define FSAPI_IF_LINUX_5_19(...)
#define FSAPI_NOT_LINUX_5_19(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_5_19(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0))
#define FSAPI_IF_LINUX_6_1(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_1(...)
#define FSAPI_IFELSE_LINUX_6_1(a, b) a
#else
#define FSAPI_IF_LINUX_6_1(...)
#define FSAPI_NOT_LINUX_6_1(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_1(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0))
#define FSAPI_IF_LINUX_6_5(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_5(...)
#define FSAPI_IFELSE_LINUX_6_5(a, b) a
#else
#define FSAPI_IF_LINUX_6_5(...)
#define FSAPI_NOT_LINUX_6_5(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_5(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0))
#define FSAPI_IF_LINUX_6_6(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_6(...)
#define FSAPI_IFELSE_LINUX_6_6(a, b) a
#else
#define FSAPI_IF_LINUX_6_6(...)
#define FSAPI_NOT_LINUX_6_6(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_6(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
#define FSAPI_IF_LINUX_6_8(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_8(...)
#define FSAPI_IFELSE_LINUX_6_8(a, b) a
#else
#define FSAPI_IF_LINUX_6_8(...)
#define FSAPI_NOT_LINUX_6_8(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_8(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0))
#define FSAPI_IF_LINUX_6_9(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_9(...)
#define FSAPI_IFELSE_LINUX_6_9(a, b) a
#else
#define FSAPI_IF_LINUX_6_9(...)
#define FSAPI_NOT_LINUX_6_9(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_9(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,10,0))
#define FSAPI_IF_LINUX_6_10(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_10(...)
#define FSAPI_IFELSE_LINUX_6_10(a, b) a
#else
#define FSAPI_IF_LINUX_6_10(...)
#define FSAPI_NOT_LINUX_6_10(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_10(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,11,0))
#define FSAPI_IF_LINUX_6_11(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_11(...)
#define FSAPI_IFELSE_LINUX_6_11(a, b) a
#else
#define FSAPI_IF_LINUX_6_11(...)
#define FSAPI_NOT_LINUX_6_11(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_11(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0))
#define FSAPI_IF_LINUX_6_12(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_12(...)
#define FSAPI_IFELSE_LINUX_6_12(a, b) a
#else
#define FSAPI_IF_LINUX_6_12(...)
#define FSAPI_NOT_LINUX_6_12(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_12(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0))
#define FSAPI_IF_LINUX_6_13(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_13(...)
#define FSAPI_IFELSE_LINUX_6_13(a, b) a
#else
#define FSAPI_IF_LINUX_6_13(...)
#define FSAPI_NOT_LINUX_6_13(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_13(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,14,0))
#define FSAPI_IF_LINUX_6_14(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_14(...)
#define FSAPI_IFELSE_LINUX_6_14(a, b) a
#else
#define FSAPI_IF_LINUX_6_14(...)
#define FSAPI_NOT_LINUX_6_14(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_14(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,15,0))
#define FSAPI_IF_LINUX_6_15(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_15(...)
#define FSAPI_IFELSE_LINUX_6_15(a, b) a
#else
#define FSAPI_IF_LINUX_6_15(...)
#define FSAPI_NOT_LINUX_6_15(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_15(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,16,0))
#define FSAPI_IF_LINUX_6_16(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_16(...)
#define FSAPI_IFELSE_LINUX_6_16(a, b) a
#else
#define FSAPI_IF_LINUX_6_16(...)
#define FSAPI_NOT_LINUX_6_16(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_16(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
#define FSAPI_IF_LINUX_6_17(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_17(...)
#define FSAPI_IFELSE_LINUX_6_17(a, b) a
#else
#define FSAPI_IF_LINUX_6_17(...)
#define FSAPI_NOT_LINUX_6_17(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_17(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0))
#define FSAPI_IF_LINUX_6_18(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_18(...)
#define FSAPI_IFELSE_LINUX_6_18(a, b) a
#else
#define FSAPI_IF_LINUX_6_18(...)
#define FSAPI_NOT_LINUX_6_18(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_18(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,19,0))
#define FSAPI_IF_LINUX_6_19(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_6_19(...)
#define FSAPI_IFELSE_LINUX_6_19(a, b) a
#else
#define FSAPI_IF_LINUX_6_19(...)
#define FSAPI_NOT_LINUX_6_19(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_6_19(a, b) b
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0))
#define FSAPI_IF_LINUX_7_0(...) __VA_ARGS__
#define FSAPI_NOT_LINUX_7_0(...)
#define FSAPI_IFELSE_LINUX_7_0(a, b) a
#else
#define FSAPI_IF_LINUX_7_0(...)
#define FSAPI_NOT_LINUX_7_0(...) __VA_ARGS__
#define FSAPI_IFELSE_LINUX_7_0(a, b) b
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0))
#define SSIZE_MAX LONG_MAX
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)) */

/* Enabling the following block of defines causes a monotonically increasing
 * operation number to be included in enter/leave messages which can be helpful
 * when debugging to match enter/leave messages in a huge volume of output. */
#if 0
static atomic_t opnum = ATOMIC_INIT(1);
#define OPNUM_DECL const int opnr = atomic_fetch_add(1, &opnum)
#define OPNUM_PREFIX "<op %d> "
#define OPNUM_ARGUMENT , opnr
#else
#define OPNUM_DECL do {} while(0)
#define OPNUM_PREFIX ""
#define OPNUM_ARGUMENT
#endif

#define fsapi_linux_op_log_enter(fmt, ...) \
	OPNUM_DECL; \
	sys_log_trace("Entering %s(" OPNUM_PREFIX fmt ")...", \
		__FUNCTION__ OPNUM_ARGUMENT, ##__VA_ARGS__)

#define fsapi_linux_op_log_leave(ret, fmt, ...) \
	sys_log_trace("Leaving %s(" OPNUM_PREFIX fmt "): %s%s%" PRId64 "%s", \
		__FUNCTION__ OPNUM_ARGUMENT, ##__VA_ARGS__, \
		(ret) < 0 ? sys_strerror(-(ret)) : "", \
		(ret) < 0 ? " (" : "", PRAd64(ret), (ret) < 0 ? ")" : "")

#define PRIdentry "p (inode: %p, name: %.*s)"
#define PRAdentry(dentry) \
	(dentry), (dentry)->d_inode, \
	(dentry) ? (int) sizeof((dentry)->d_iname) : 0, \
	(dentry) ? (char*) (dentry)->d_iname : ""

typedef struct {
	struct super_block *sb;
	struct inode *root_inode;

	sys_device *dev;
	fsapi_volume *vol;
	fsapi_node *root_node;
} fsapi_linux_context;

static struct kmem_cache *fsapi_inode_cache = NULL;

static struct inode* fsapi_linux_super_op_alloc_inode(
		struct super_block *sb);

static void fsapi_linux_super_op_free_inode(
		struct inode *);

#if 0
static void fsapi_linux_super_op_dirty_inode(
		struct inode *,
		int flags);
#endif

static int fsapi_linux_super_op_write_inode(
		struct inode *,
		struct writeback_control *wbc);

static int fsapi_linux_super_op_drop_inode(
		struct inode *);

static void fsapi_linux_super_op_evict_inode(
		struct inode *);

static void fsapi_linux_super_op_put_super(
		struct super_block *);

static int fsapi_linux_super_op_sync_fs(
		struct super_block *sb,
		int wait);

#if 0
static int fsapi_linux_super_op_freeze_super(
		struct super_block *);

static int fsapi_linux_super_op_freeze_fs(
		struct super_block *);

static int fsapi_linux_super_op_thaw_super(
		struct super_block *);

static int fsapi_linux_super_op_unfreeze_fs(
		struct super_block *);
#endif

static int fsapi_linux_super_op_statfs(
		struct dentry *,
		struct kstatfs *);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(7,0,0))
static int fsapi_linux_super_op_remount_fs(
		struct super_block *,
		int *,
		char *);
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(7,0,0)) */

#if 0
static void fsapi_linux_super_op_umount_begin(
		struct super_block *);
#endif

static int fsapi_linux_super_op_show_options(
		struct seq_file *,
		struct dentry *);

#if 0
static int fsapi_linux_super_op_show_devname(
		struct seq_file *,
		struct dentry *);

static int fsapi_linux_super_op_show_path(
		struct seq_file *,
		struct dentry *);

static int fsapi_linux_super_op_show_stats(
		struct seq_file *,
		struct dentry *);

#ifdef CONFIG_QUOTA
static ssize_t fsapi_linux_super_op_quota_read(
		struct super_block *,
		int,
		char *,
		size_t,
		loff_t);

static ssize_t fsapi_linux_super_op_quota_write(
		struct super_block *,
		int,
		const char *,
		size_t,
		loff_t);

static struct dquot** fsapi_linux_super_op_get_dquots(
		struct inode *);
#endif /* defined(CONFIG_QUOTA) */

static long fsapi_linux_super_op_nr_cached_objects(
		struct super_block *,
		struct shrink_control *);

static long fsapi_linux_super_op_free_cached_objects(
		struct super_block *,
		struct shrink_control *);
#endif

static const struct super_operations fsapi_linux_super_operations = {
	/* struct inode* (*alloc_inode)(
	 *     struct super_block *sb) */
	.alloc_inode = fsapi_linux_super_op_alloc_inode,
	/* void (*destroy_inode)(
	 *     struct inode *) */
	.destroy_inode = NULL,
	/* void (*free_inode)(
	 *     struct inode *) */
	.free_inode = fsapi_linux_super_op_free_inode,
	/* void (*dirty_inode)(
	 *     struct inode *,
	 *     int flags) */
	.dirty_inode = NULL /* fsapi_linux_super_op_dirty_inode */,
	/* int (*write_inode)(
	 *     struct inode *,
	 *     struct writeback_control *wbc) */
	.write_inode = fsapi_linux_super_op_write_inode,
	/* int (*drop_inode)(
	 *     struct inode *) */
	.drop_inode = fsapi_linux_super_op_drop_inode,
	/* void (*evict_inode)(
	 *     struct inode *) */
	.evict_inode = fsapi_linux_super_op_evict_inode,
	/* void (*put_super)(
	 *     struct super_block *) */
	.put_super = fsapi_linux_super_op_put_super,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0))
	/* int (*sync_fs)(
	 *     struct super_block *sb,
	 *     int wait) */
	.sync_fs = fsapi_linux_super_op_sync_fs,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)) */
	/* int (*freeze_super)(
	 *     struct super_block *) */
	.freeze_super = NULL /* fsapi_linux_super_op_freeze_super */,
	/* int (*freeze_fs)(
	 *     struct super_block *) */
	.freeze_fs = NULL /* fsapi_linux_super_op_freeze_fs */,
	/* int (*thaw_super)(
	 *     struct super_block *) */
	.thaw_super = NULL /* fsapi_linux_super_op_thaw_super */,
	/* int (*unfreeze_fs)(
	 *     struct super_block *) */
	.unfreeze_fs = NULL /* fsapi_linux_super_op_unfreeze_fs */,
	/* int (*statfs)(
	 *     struct dentry *,
	 *     struct kstatfs *) */
	.statfs = fsapi_linux_super_op_statfs,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(7,0,0))
	/* int (*remount_fs)(
	 *     struct super_block *,
	 *     int *,
	 *     char *) */
	.remount_fs = fsapi_linux_super_op_remount_fs,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(7,0,0)) */
	/* void (*umount_begin)(
	 *     struct super_block *) */
	.umount_begin = NULL /* fsapi_linux_super_op_umount_begin */,
	/* int (*show_options)(
	 *     struct seq_file *,
	 *     struct dentry *) */
	.show_options = fsapi_linux_super_op_show_options,
	/* int (*show_devname)(
	 *     struct seq_file *,
	 *     struct dentry *) */
	.show_devname = NULL /* fsapi_linux_super_op_show_devname */,
	/* int (*show_path)(
	 *     struct seq_file *,
	 *     struct dentry *) */
	.show_path = NULL /* fsapi_linux_super_op_show_path */,
	/* int (*show_stats)(
	 *     struct seq_file *,
	 *     struct dentry *) */
	.show_stats = NULL /* fsapi_linux_super_op_show_stats */,
#ifdef CONFIG_QUOTA
	/* ssize_t (*quota_read)(
	 *     struct super_block *,
	 *     int,
	 *     char *,
	 *     size_t,
	 *     loff_t) */
	.quota_read = NULL /* fsapi_linux_super_op_quota_read */,
	/* ssize_t (*quota_write)(
	 *     struct super_block *,
	 *     int,
	 *     const char *,
	 *     size_t,
	 *     loff_t) */
	.quota_write = NULL /* fsapi_linux_super_op_quota_write */,
	/* struct dquot** (*get_dquots)(
	 *     struct inode *) */
	.get_dquots = NULL /* fsapi_linux_super_op_get_dquots */,
#endif /* defined(CONFIG_QUOTA) */
	/* long (*nr_cached_objects)(
	 *     struct super_block *,
	 *     struct shrink_control *) */
	.nr_cached_objects = NULL /* fsapi_linux_super_op_nr_cached_objects */,
	/* long (*free_cached_objects)(
	 *     struct super_block *,
	 *     struct shrink_control *) */
	.free_cached_objects =
		NULL /* fsapi_linux_super_op_free_cached_objects */,
};

static struct file_operations fsapi_linux_null_file_operations = {
	/* struct module *owner */
	.owner = THIS_MODULE,
	/* loff_t (*llseek)(
	 *     struct file *,
	 *     loff_t,
	 *     int) */
	.llseek = NULL,
	/* ssize_t (*read)(
	 *     struct file *,
	 *     char __user *,
	 *     size_t,
	 *     loff_t *) */
	.read = NULL,
	/* ssize_t (*write)(
	 *     struct file *,
	 *     const char __user *,
	 *     size_t,
	 *     loff_t *) */
	.write = NULL,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
	/* ssize_t (*read_iter)(
	 *     struct kiocb *,
	 *     struct iov_iter *) */
	.read_iter = NULL,
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
	/* ssize_t (*aio_read)(
	 *     struct kiocb *,
	 *     const struct iovec *,
	 *     unsigned long,
	 *     loff_t) */
	.aio_read = NULL,
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
	/* ssize_t (*write_iter)(
	 *     struct kiocb *,
	 *     struct iov_iter *) */
	.write_iter = NULL,
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
	/* ssize_t (*aio_write)(
	 *     struct kiocb *,
	 *     const struct iovec *,
	 *     unsigned long,
	 *     loff_t) */
	.aio_write = NULL,
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) ... */
	/* int (*iopoll)(
	 *     struct kiocb *kiocb,
	 *     struct io_comp_batch *,
			unsigned int flags) */
	.iopoll = NULL,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0))
	/* int (*iterate)(
	 *     struct file *,
	 *     struct dir_context *) */
	.iterate = NULL,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)) */
	/* int (*iterate_shared)(
	 *     struct file *,
	 *     struct dir_context *) */
	.iterate_shared = NULL,
	/* __poll_t (*poll)(
	 *     struct file *,
	 *     struct poll_table_struct *) */
	.poll = NULL,
	/* long (*unlocked_ioctl)(
	 *     struct file *,
	 *     unsigned int,
	 *     unsigned long) */
	.unlocked_ioctl = NULL,
	/* long (*compat_ioctl)(
	 *     struct file *,
	 *     unsigned int,
	 *     unsigned long) */
	.compat_ioctl = NULL,
	/* int (*mmap)(
	 *     struct file *,
	 *     struct vm_area_struct *) */
	.mmap = NULL,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,10,0))
	/* unsigned long mmap_supported_flags */
	.mmap_supported_flags = 0,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,10,0)) */
	/* int (*open)(
	 *     struct inode *,
	 *     struct file *) */
	.open = NULL,
	/* int (*flush)(
	 *     struct file *,
	 *     fl_owner_t id) */
	.flush = NULL,
	/* int (*release)(
	 *     struct inode *,
	 *     struct file *) */
	.release = NULL,
	/* int (*fsync)(
	 *     struct file *,
	 *     loff_t,
	 *     loff_t,
	 *     int datasync) */
	.fsync = NULL,
	/* int (*fasync)(
	 *     int,
	 *     struct file *,
	 *     int) */
	.fasync = NULL,
	/* int (*lock)(
	 *     struct file *,
	 *     int,
	 *     struct file_lock *) */
	.lock = NULL,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0))
	/* ssize_t (*sendpage)(
	 *     struct file *,
	 *     struct page *,
	 *     int,
	 *     size_t,
	 *     loff_t *,
	 *     int) */
	.sendpage = NULL,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)) */
	/* unsigned long (*get_unmapped_area)(
	 *     struct file *,
	 *     unsigned long,
	 *     unsigned long,
	 *     unsigned long,
	 *     unsigned long) */
	.get_unmapped_area = NULL,
	/* int (*check_flags)(
	 *     int) */
	.check_flags = NULL,
	/* int (*flock)(
	 *     struct file *,
	 *     int,
	 *     struct file_lock *) */
	.flock = NULL,
	/* ssize_t (*splice_write)(
	 *     struct pipe_inode_info *,
	 *     struct file *,
	 *     loff_t *,
	 *     size_t,
	 *     unsigned int) */
	.splice_write = NULL,
	/* ssize_t (*splice_read)(
	 *     struct file *,
	 *     loff_t *,
	 *     struct pipe_inode_info *,
	 *     size_t,
	 *     unsigned int) */
	.splice_read = NULL,
	/* int (*setlease)(
	 *     struct file *,
	 *     long,
	 *     struct file_lock **,
	 *     void **) */
	.setlease = NULL,
	/* long (*fallocate)(
	 *     struct file *file,
	 *     int mode,
	 *     loff_t offset,
	 *     loff_t len) */
	.fallocate = NULL,
	/* void (*show_fdinfo)(
	 *     struct seq_file *m,
	 *     struct file *f) */
	.show_fdinfo = NULL,
#ifndef CONFIG_MMU
	/* unsigned (*mmap_capabilities)(
	 *     struct file *) */
	.mmap_capabilities = NULL,
#endif /* !defined(CONFIG_MMU) */
	/* ssize_t (*copy_file_range)(
	 *     struct file *,
	 *     loff_t,
	 *     struct file *,
	 *     loff_t,
	 *     size_t,
	 *     unsigned int) */
	.copy_file_range = NULL,
	/* loff_t (*remap_file_range)(
	 *     struct file *file_in,
	 *     loff_t pos_in,
	 *     struct file *file_out,
	 *     loff_t pos_out,
	 *     loff_t len,
	 *     unsigned int remap_flags) */
	.remap_file_range = NULL,
	/* int (*fadvise)(
	 *     struct file *,
	 *     loff_t,
	 *     loff_t,
	 *     int) */
	.fadvise = NULL,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0))
	/* int (*uring_cmd)(
	 *     struct io_uring_cmd *ioucmd,
	 *     unsigned int issue_flags) */
	.uring_cmd = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)) */
};

const struct inode_operations fsapi_linux_null_inode_operations =
{
	/* struct dentry* (*lookup)(
	 *     struct inode *,
	 *     struct dentry *,
	 *     unsigned int) */
	.lookup = NULL,
	/* const char* (*get_link)(
	 *     struct dentry *,
	 *     struct inode *,
	 *     struct delayed_call *) */
	.get_link = NULL,
	/* int (*permission)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     int) */
	.permission = NULL,
	/* struct posix_acl* (*get_acl)(
	 *     struct inode *,
	 *     int,
	 *     bool) */
	.get_acl = NULL,
	/* int (*readlink)(
	 *     struct dentry *,
	 *     char __user *,
	 *     int) */
	.readlink = NULL,
	/* int (*create)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t,
	 *     bool) */
	.create = NULL,
	/* int (*link)(
	 *     struct dentry *,
	 *     struct inode *,
	 *     struct dentry *) */
	.link = NULL,
	/* int (*unlink)(
	 *     struct inode *,
	 *     struct dentry *) */
	.unlink = NULL,
	/* int (*symlink)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     const char *) */
	.symlink = NULL,
	/* int (*mkdir)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t) */
	.mkdir = NULL,
	/* int (*rmdir)(
	 *     struct inode *,
	 *     struct dentry *) */
	.rmdir = NULL,
	/* int (*mknod)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t,
	 *     dev_t) */
	.mknod = NULL,
	/* int (*rename)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     unsigned int) */
	.rename = NULL,
	/* int (*setattr)(
	 *     struct user_namespace *,
	 *     struct dentry *,
	 *     struct iattr *) */
	.setattr = NULL,
	/* int (*getattr)(
	 *     struct user_namespace *,
	 *     const struct path *,
	 *     struct kstat *,
	 *     u32,
	 *     unsigned int) */
	.getattr = NULL,
	/* ssize_t (*listxattr)(
	 *     struct dentry *,
	 *     char *,
	 *     size_t) */
	.listxattr = NULL,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
	.setxattr = NULL,
	.getxattr = NULL,
	.removexattr = NULL,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)) */
	/* int (*fiemap)(
	 *     struct inode *,
	 *     struct fiemap_extent_info *,
	 *     u64 start,
	 *     u64 len) */
	.fiemap = NULL,
	/* int (*update_time)(
	 *     struct inode *,
	 *     struct timespec *,(<=4.17)
	 *     struct timespec64 *,(>=4.18, <=6.5)
	 *     int) */
	.update_time = NULL,
	/* int (*atomic_open)(
	 *     struct inode *,
	 *     struct dentry *,
	 *     struct file *,
	 *     unsigned open_flag,
	 *     umode_t create_mode) */
	.atomic_open = NULL,
	/* int (*tmpfile)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t) */
	.tmpfile = NULL,
	/* int (*set_acl)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct posix_acl *,
	 *     int) */
	.set_acl = NULL,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0))
	/* int (*fileattr_set)(
	 *     struct user_namespace *mnt_userns,(<=6.2-ish)
	 *     struct mnt_idmap *mnt_userns, (>=6.5-ish),
	 *     struct dentry *dentry,
	 *     struct fileattr *fa) */
	.fileattr_set = NULL,
	/* int (*fileattr_get)(
	 *     struct dentry *dentry,
	 *     struct fileattr *fa) */
	.fileattr_get = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)) */
};

#if FSAPI_LINUX_SLOW_SYNCHRONOUS_READ_PATH
static ssize_t fsapi_linux_file_op_read(
		struct file *,
		char __user *,
		size_t,
		loff_t *);
#endif /* FSAPI_LINUX_SLOW_SYNCHRONOUS_READ_PATH */

static ssize_t fsapi_linux_file_op_write(
		struct file *,
		const char __user *,
		size_t,
		loff_t *);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
static ssize_t fsapi_linux_file_op_read_iter(
		struct kiocb *const iocb,
		struct iov_iter *const iter);
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
static ssize_t fsapi_linux_file_op_aio_read(
		struct kiocb *const iocb,
		const struct iovec *const iov,
		const unsigned long nr_segs,
		const loff_t pos);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) ... */

#if 0
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
static ssize_t fsapi_linux_file_op_write_iter(
static ssize_t fsapi_linux_file_op_write_iter(
		struct kiocb *const iocb,
		struct iov_iter *const from);
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
static ssize_t fsapi_linux_file_op_aio_write(
		struct kiocb *iocb,
		const struct iovec *iov,
		unsigned long nr_segs,
		loff_t pos);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) ... */
#endif

static long fsapi_linux_file_op_unlocked_ioctl(
		struct file *file,
		unsigned int cmd,
		unsigned long arg);

#ifdef CONFIG_COMPAT
static long fsapi_linux_file_op_compat_ioctl(
		struct file *file,
		unsigned int cmd,
		unsigned long arg);
#endif /* defined(CONFIG_COMPAT) */

static int fsapi_linux_file_op_mmap(
		struct file *,
		struct vm_area_struct *);

static int fsapi_linux_file_op_open(
		struct inode *,
		struct file *);

static int fsapi_linux_file_op_release(
		struct inode *,
		struct file *);

static int fsapi_linux_file_op_fsync(
		struct file *,
		loff_t,
		loff_t,
		int datasync);

#if 0
static ssize_t fsapi_linux_file_op_splice_write(
		struct pipe_inode_info *,
		struct file *,
		loff_t *,
		size_t,
		unsigned int);

static ssize_t fsapi_linux_file_op_splice_read(
		struct file *,
		loff_t *,
		struct pipe_inode_info *,
		size_t,
		unsigned int);
#endif

static long fsapi_linux_file_op_fallocate(
		struct file *file,
		int mode,
		loff_t offset,
		loff_t len);

static struct file_operations fsapi_linux_file_operations = {
	/* struct module *owner */
	.owner = THIS_MODULE,
	/* loff_t (*llseek)(
	 *     struct file *,
	 *     loff_t,
	 *     int) */
	.llseek = generic_file_llseek,
	/* ssize_t (*read)(
	 *     struct file *,
	 *     char __user *,
	 *     size_t,
	 *     loff_t *) */
#if !FSAPI_LINUX_SLOW_SYNCHRONOUS_READ_PATH
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0))
	.read = new_sync_read,
#else /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)) */
	.read = NULL,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)) ... */
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
	.read = do_sync_read,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)) ... */
#else
	.read = fsapi_linux_file_op_read,
#endif /* !FSAPI_LINUX_SLOW_SYNCHRONOUS_READ_PATH ... */
	/* ssize_t (*write)(
	 *     struct file *,
	 *     const char __user *,
	 *     size_t,
	 *     loff_t *) */
#if 1 /* Temporary write path. */
	.write = fsapi_linux_file_op_write,
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0))
	.write = new_sync_write,
#else /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)) */
	.write = NULL,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)) ... */
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
	.write = do_sync_write,
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
	/* ssize_t (*read_iter)(
	 *     struct kiocb *,
	 *     struct iov_iter *) */
	.read_iter = fsapi_linux_file_op_read_iter,
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
	/* ssize_t (*aio_read)(
	 *     struct kiocb *,
	 *     const struct iovec *,
	 *     unsigned long,
	 *     loff_t) */
	.aio_read = fsapi_linux_file_op_aio_read,
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
	/* ssize_t (*write_iter)(
	 *     struct kiocb *,
	 *     struct iov_iter *) */
#if 1 /* Temporary write path. */
	.write_iter = NULL,
#else
	.write_iter = fsapi_linux_file_op_write_iter,
#endif
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
	/* ssize_t (*aio_write)(
	 *     struct kiocb *,
	 *     const struct iovec *,
	 *     unsigned long,
	 *     loff_t) */
#if 1 /* Temporary write path. */
	.aio_write = NULL,
#else
	.aio_write = fsapi_linux_file_op_aio_write,
#endif
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) ... */
	/* int (*iopoll)(
	 *     struct kiocb *kiocb,
	 *     struct io_comp_batch *,
	 *     unsigned int flags) */
	.iopoll = NULL,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,2,0))
	/* int (*iterate)(
	 *     struct file *,
	 *     struct dir_context *) */
	.iterate = NULL,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,2,0)) */
	/* int (*iterate_shared)(
	 *     struct file *,
	 *     struct dir_context *) */
	.iterate_shared = NULL,
	/* __poll_t (*poll)(
	 *     struct file *,
	 *     struct poll_table_struct *) */
	.poll = NULL,
	/* long (*unlocked_ioctl)(
	 *     struct file *,
	 *     unsigned int,
	 *     unsigned long) */
	.unlocked_ioctl = fsapi_linux_file_op_unlocked_ioctl,
	/* long (*compat_ioctl)(
	 *     struct file *,
	 *     unsigned int,
	 *     unsigned long) */
#ifdef CONFIG_COMPAT
	.compat_ioctl = fsapi_linux_file_op_compat_ioctl,
#else /* !defined(CONFIG_COMPAT) */
	.compat_ioctl = NULL,
#endif /* defined(CONFIG_COMPAT) ... */
	/* int (*mmap)(
	 *     struct file *,
	 *     struct vm_area_struct *) */
	.mmap = fsapi_linux_file_op_mmap,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,10,0))
	/* unsigned long mmap_supported_flags */
	.mmap_supported_flags = 0,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,10,0)) */
	/* int (*open)(
	 *     struct inode *,
	 *     struct file *) */
	.open = fsapi_linux_file_op_open,
	/* int (*flush)(
	 *     struct file *,
	 *     fl_owner_t id) */
	.flush = NULL,
	/* int (*release)(
	 *     struct inode *,
	 *     struct file *) */
	.release = fsapi_linux_file_op_release,
	/* int (*fsync)(
	 *     struct file *,
	 *     loff_t,
	 *     loff_t,
	 *     int datasync) */
	.fsync = fsapi_linux_file_op_fsync,
	/* int (*fasync)(
	 *     int,
	 *     struct file *,
	 *     int) */
	.fasync = NULL,
	/* int (*lock)(
	 *     struct file *,
	 *     int,
	 *     struct file_lock *) */
	.lock = NULL,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0))
	/* ssize_t (*sendpage)(
	 *     struct file *,
	 *     struct page *,
	 *     int,
	 *     size_t,
	 *     loff_t *,
	 *     int) */
	.sendpage = NULL,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)) */
	/* unsigned long (*get_unmapped_area)(
	 *     struct file *,
	 *     unsigned long,
	 *     unsigned long,
	 *     unsigned long,
	 *     unsigned long) */
	.get_unmapped_area = NULL,
	/* int (*check_flags)(
	 *     int) */
	.check_flags = NULL,
	/* int (*flock)(
	 *     struct file *,
	 *     int,
	 *     struct file_lock *) */
	.flock = NULL,
	/* ssize_t (*splice_write)(
	 *     struct pipe_inode_info *,
	 *     struct file *,
	 *     loff_t *,
	 *     size_t,
	 *     unsigned int) */
#if 1
	.splice_write = NULL,
#else
	.splice_write = fsapi_linux_file_op_splice_write,
#endif
	/* ssize_t (*splice_read)(
	 *     struct file *,
	 *     loff_t *,
	 *     struct pipe_inode_info *,
	 *     size_t,
	 *     unsigned int) */
#if 1
	.splice_read = NULL,
#else
	.splice_read = fsapi_linux_file_op_splice_read,
#endif
	/* int (*setlease)(
	 *     struct file *,
	 *     long,
	 *     struct file_lock **,
	 *     void **) */
	.setlease = NULL,
	/* long (*fallocate)(
	 *     struct file *file,
	 *     int mode,
	 *     loff_t offset,
	 *     loff_t len) */
	.fallocate = fsapi_linux_file_op_fallocate,
	/* void (*show_fdinfo)(
	 *     struct seq_file *m,
	 *     struct file *f) */
	.show_fdinfo = NULL,
#ifndef CONFIG_MMU
	/* unsigned (*mmap_capabilities)(
	 *     struct file *) */
	.mmap_capabilities = NULL,
#endif /* !defined(CONFIG_MMU) */
	/* ssize_t (*copy_file_range)(
	 *     struct file *,
	 *     loff_t,
	 *     struct file *,
	 *     loff_t,
	 *     size_t,
	 *     unsigned int) */
	.copy_file_range = NULL,
	/* loff_t (*remap_file_range)(
	 *     struct file *file_in,
	 *     loff_t pos_in,
	 *     struct file *file_out,
	 *     loff_t pos_out,
	 *     loff_t len,
	 *     unsigned int remap_flags) */
	.remap_file_range = NULL,
	/* int (*fadvise)(
	 *     struct file *,
	 *     loff_t,
	 *     loff_t,
	 *     int) */
	.fadvise = NULL,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0))
	/* int (*uring_cmd)(
	 *     struct io_uring_cmd *ioucmd,
	 *     unsigned int issue_flags) */
	.uring_cmd = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)) */
};

static int fsapi_linux_file_inode_op_setattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *entry,
		struct iattr *attr);

static int fsapi_linux_file_inode_op_getattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
		const struct path *path,
		struct kstat *stat,
		u32 request_mask,
		unsigned int query_flags
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)) */
		struct vfsmount *mnt,
		struct dentry *dentry,
		struct kstat *stat
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)) ... */
		);

static ssize_t fsapi_linux_file_inode_op_listxattr(
		struct dentry *,
		char *,
		size_t);

static int fsapi_linux_file_inode_op_fiemap(
		struct inode *inode,
		struct fiemap_extent_info *fieinfo,
		u64 start,
		u64 len);

static int fsapi_linux_file_inode_op_update_time(
		struct inode *,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0))
		enum fs_update_time type,
		unsigned
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0)) */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0))
		struct timespec64 *,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)) */
		struct timespec *,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) ... */
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) ... */
		int);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0))
static int fsapi_linux_file_inode_op_fileattr_set(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *mnt_userns,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0)) */
		struct user_namespace *mnt_userns,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *dentry,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		struct file_kattr *fa);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)) */
		struct fileattr *fa);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */

static int fsapi_linux_file_inode_op_fileattr_get(
		struct dentry *dentry,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		struct file_kattr *fa);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)) */
		struct fileattr *fa);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)) */

static struct inode_operations fsapi_linux_file_inode_operations = {
	/* struct dentry* (*lookup)(
	 *     struct inode *,
	 *     struct dentry *,
	 *     unsigned int) */
	.lookup = NULL,
	/* const char* (*get_link)(
	 *     struct dentry *,
	 *     struct inode *,
	 *     struct delayed_call *) */
	.get_link = NULL,
	/* int (*permission)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     int) */
	.permission = NULL,
	/* struct posix_acl* (*get_acl)(
	 *     struct inode *,
	 *     int,
	 *     bool) */
	.get_acl = NULL,
	/* int (*readlink)(
	 *     struct dentry *,
	 *     char __user *,
	 *     int) */
	.readlink = NULL,
	/* int (*create)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t,
	 *     bool) */
	.create = NULL,
	/* int (*link)(
	 *     struct dentry *,
	 *     struct inode *,
	 *     struct dentry *) */
	.link = NULL,
	/* int (*unlink)(
	 *     struct inode *,
	 *     struct dentry *) */
	.unlink = NULL,
	/* int (*symlink)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     const char *) */
	.symlink = NULL,
	/* int (*mkdir)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t) */
	.mkdir = NULL,
	/* int (*rmdir)(
	 *     struct inode *,
	 *     struct dentry *) */
	.rmdir = NULL,
	/* int (*mknod)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t,
	 *     dev_t) */
	.mknod = NULL,
	/* int (*rename)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     unsigned int) */
	.rename = NULL,
	/* int (*setattr)(
	 *     struct user_namespace *,
	 *     struct dentry *,
	 *     struct iattr *) */
	.setattr = fsapi_linux_file_inode_op_setattr,
	/* int (*getattr)(
	 *     struct user_namespace *,
	 *     const struct path *,
	 *     struct kstat *,
	 *     u32,
	 *     unsigned int) */
	.getattr = fsapi_linux_file_inode_op_getattr,
	/* ssize_t (*listxattr)(
	 *     struct dentry *,
	 *     char *,
	 *     size_t) */
	.listxattr = fsapi_linux_file_inode_op_listxattr,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
	.setxattr = fsapi_linux_file_inode_op_setxattr,
	.getxattr = fsapi_linux_file_inode_op_getxattr,
	.removexattr = fsapi_linux_file_inode_op_removexattr,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)) */
	/* int (*fiemap)(
	 *     struct inode *,
	 *     struct fiemap_extent_info *,
	 *     u64 start,
	 *     u64 len) */
	.fiemap = fsapi_linux_file_inode_op_fiemap,
	/* int (*update_time)(
	 *     struct inode *,
	 *     enum fs_update_time type,(>=7.0)
	 *     struct timespec *,(<=4.17)
	 *     struct timespec64 *,(>=4.18, <=6.5)
	 *     unsigned (>=7.0) int) */
	.update_time = fsapi_linux_file_inode_op_update_time,
	/* int (*atomic_open)(
	 *     struct inode *,
	 *     struct dentry *,
	 *     struct file *,
	 *     unsigned open_flag,
	 *     umode_t create_mode) */
	.atomic_open = NULL,
	/* int (*tmpfile)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t) */
	.tmpfile = NULL,
	/* int (*set_acl)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct posix_acl *,
	 *     int) */
	.set_acl = NULL,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0))
	/* int (*fileattr_set)(
	 *     struct user_namespace *mnt_userns,(<=6.2-ish)
	 *     struct mnt_idmap *mnt_userns, (>=6.5-ish),
	 *     struct dentry *dentry,
	 *     struct fileattr *fa) */
	.fileattr_set = fsapi_linux_file_inode_op_fileattr_set,
	/* int (*fileattr_get)(
	 *     struct dentry *dentry,
	 *     struct fileattr *fa) */
	.fileattr_get = fsapi_linux_file_inode_op_fileattr_get,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)) */
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0))
static int fsapi_linux_dir_op_iterate_shared(
		struct file *filp,
		struct dir_context *actor);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0))
static int fsapi_linux_dir_op_iterate(
		struct file *,
		struct dir_context *);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)) ... */

static long fsapi_linux_dir_op_unlocked_ioctl(
		struct file *file,
		unsigned int cmd,
		unsigned long arg);

#ifdef CONFIG_COMPAT
static long fsapi_linux_dir_op_compat_ioctl(
		struct file *file,
		unsigned int cmd,
		unsigned long arg);
#endif /* defined(CONFIG_COMPAT) */

static int fsapi_linux_dir_op_open(
		struct inode *,
		struct file *);

static int fsapi_linux_dir_op_release(
		struct inode *,
		struct file *);

static int fsapi_linux_dir_op_fsync(
		struct file *,
		loff_t,
		loff_t,
		int datasync);

static struct file_operations fsapi_linux_dir_operations = {
	/* struct module *owner */
	.owner = THIS_MODULE,
	/* loff_t (*llseek)(
	 *     struct file *,
	 *     loff_t,
	 *     int) */
	.llseek = generic_file_llseek,
	/* ssize_t (*read)(
	 *     struct file *,
	 *     char __user *,
	 *     size_t,
	 *     loff_t *) */
	.read = generic_read_dir,
	/* ssize_t (*write)(
	 *     struct file *,
	 *     const char __user *,
	 *     size_t,
	 *     loff_t *) */
	.write = NULL,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
	/* ssize_t (*read_iter)(
	 *     struct kiocb *,
	 *     struct iov_iter *) */
	.read_iter = NULL,
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
	/* ssize_t (*aio_read)(
	 *     struct kiocb *,
	 *     const struct iovec *,
	 *     unsigned long,
	 *     loff_t) */
	.aio_read = NULL,
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
	/* ssize_t (*write_iter)(
	 *     struct kiocb *,
	 *     struct iov_iter *) */
	.write_iter = NULL,
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
	/* ssize_t (*aio_write)(
	 *     struct kiocb *,
	 *     const struct iovec *,
	 *     unsigned long,
	 *     loff_t) */
	.aio_write = NULL,
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) */
	/* int (*iopoll)(
	 *     struct kiocb *kiocb,
	 *     struct io_comp_batch *,
	 *     unsigned int flags) */
	.iopoll = NULL,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0))
	/* No 'iterate' callback exists in Linux 6.5+. */
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0))
	/* int (*iterate)(
	 *     struct file *,
	 *     struct dir_context *) */
	.iterate = fsapi_linux_dir_op_iterate,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0) */
	.readdir = fsapi_linux_dir_op_readdir,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)) ... */
	/* int (*iterate_shared)(
	 *     struct file *,
	 *     struct dir_context *) */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0))
	.iterate_shared = fsapi_linux_dir_op_iterate_shared,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)) */
	.iterate_shared = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)) ... */
	/* __poll_t (*poll)(
	 *     struct file *,
	 *     struct poll_table_struct *) */
	.poll = NULL,
	/* long (*unlocked_ioctl)(
	 *     struct file *,
	 *     unsigned int,
	 *     unsigned long) */
	.unlocked_ioctl = fsapi_linux_dir_op_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	/* long (*compat_ioctl)(
	 *     struct file *,
	 *     unsigned int,
	 *     unsigned long) */
	.compat_ioctl = fsapi_linux_dir_op_compat_ioctl,
#endif /* defined(CONFIG_COMPAT) */
	/* int (*mmap)(
	 *     struct file *,
	 *     struct vm_area_struct *) */
	.mmap = NULL,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,10,0))
	/* unsigned long mmap_supported_flags */
	.mmap_supported_flags = 0,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,10,0)) */
	/* int (*open)(
	 *     struct inode *,
	 *     struct file *) */
	.open = fsapi_linux_dir_op_open,
	/* int (*flush)(
	 *     struct file *,
	 *     fl_owner_t id) */
	.flush = NULL,
	/* int (*release)(
	 *     struct inode *,
	 *     struct file *) */
	.release = fsapi_linux_dir_op_release,
	/* int (*fsync)(
	 *     struct file *,
	 *     loff_t,
	 *     loff_t,
	 *     int datasync) */
	.fsync = fsapi_linux_dir_op_fsync,
	/* int (*fasync)(
	 *     int,
	 *     struct file *,
	 *     int) */
	.fasync = NULL,
	/* int (*lock)(
	 *     struct file *,
	 *     int,
	 *     struct file_lock *) */
	.lock = NULL,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0))
	/* ssize_t (*sendpage)(
	 *     struct file *,
	 *     struct page *,
	 *     int,
	 *     size_t,
	 *     loff_t *,
	 *     int) */
	.sendpage = NULL,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)) */
	/* unsigned long (*get_unmapped_area)(
	 *     struct file *,
	 *     unsigned long,
	 *     unsigned long,
	 *     unsigned long,
	 *     unsigned long) */
	.get_unmapped_area = NULL,
	/* int (*check_flags)(
	 *     int) */
	.check_flags = NULL,
	/* int (*flock)(
	 *     struct file *,
	 *     int,
	 *     struct file_lock *) */
	.flock = NULL,
	/* ssize_t (*splice_write)(
	 *     struct pipe_inode_info *,
	 *     struct file *,
	 *     loff_t *,
	 *     size_t,
	 *     unsigned int) */
	.splice_write = NULL,
	/* ssize_t (*splice_read)(
	 *     struct file *,
	 *     loff_t *,
	 *     struct pipe_inode_info *,
	 *     size_t,
	 *     unsigned int) */
	.splice_read = NULL,
	/* int (*setlease)(
	 *     struct file *,
	 *     long,
	 *     struct file_lock **,
	 *     void **) */
	.setlease = NULL,
	/* long (*fallocate)(
	 *     struct file *file,
	 *     int mode,
	 *     loff_t offset,
	 *     loff_t len) */
	.fallocate = NULL,
	/* void (*show_fdinfo)(
	 *     struct seq_file *m,
	 *     struct file *f) */
	.show_fdinfo = NULL,
#ifndef CONFIG_MMU
	/* unsigned (*mmap_capabilities)(
	 *     struct file *) */
	.mmap_capabilities = NULL,
#endif /* !defined(CONFIG_MMU) */
	/* ssize_t (*copy_file_range)(
	 *     struct file *,
	 *     loff_t,
	 *     struct file *,
	 *     loff_t,
	 *     size_t,
	 *     unsigned int) */
	.copy_file_range = NULL,
	/* loff_t (*remap_file_range)(
	 *     struct file *file_in,
	 *     loff_t pos_in,
	 *     struct file *file_out,
	 *     loff_t pos_out,
	 *     loff_t len,
	 *     unsigned int remap_flags) */
	.remap_file_range = NULL,
	/* int (*fadvise)(
	 *     struct file *,
	 *     loff_t,
	 *     loff_t,
	 *     int) */
	.fadvise = NULL,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0))
	/* int (*uring_cmd)(
	 *     struct io_uring_cmd *ioucmd,
	 *     unsigned int issue_flags) */
	.uring_cmd = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)) */
};

static struct dentry* fsapi_linux_dir_inode_op_lookup(
		struct inode *,
		struct dentry *,
		unsigned int);

static int fsapi_linux_dir_inode_op_create(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct inode *,
		struct dentry *,
		umode_t,
		bool);

static int fsapi_linux_dir_inode_op_link(
		struct dentry *,
		struct inode *,
		struct dentry *);

static int fsapi_linux_dir_inode_op_unlink(
		struct inode *,
		struct dentry *);

static int fsapi_linux_dir_inode_op_symlink(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct inode *,
		struct dentry *,
		const char *);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,15,0))
static struct dentry* fsapi_linux_dir_inode_op_mkdir(
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,15,0)) */
static int fsapi_linux_dir_inode_op_mkdir(
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,15,0)) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct inode *,
		struct dentry *,
		umode_t);

static int fsapi_linux_dir_inode_op_rmdir(
		struct inode *,
		struct dentry *);

static int fsapi_linux_dir_inode_op_mknod(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct inode *,
		struct dentry *,
		umode_t,
		dev_t);

static int fsapi_linux_dir_inode_op_rename(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct inode *,
		struct dentry *,
		struct inode *,
		struct dentry *,
		unsigned int);

static int fsapi_linux_dir_inode_op_setattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *,
		struct iattr *);

static int fsapi_linux_dir_inode_op_getattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		const struct path *,
		struct kstat *,
		u32,
		unsigned int);

static ssize_t fsapi_linux_dir_inode_op_listxattr(
		struct dentry *,
		char *,
		size_t);

static int fsapi_linux_dir_inode_op_fiemap(
		struct inode *inode,
		struct fiemap_extent_info *fieinfo,
		u64 start,
		u64 len);

static int fsapi_linux_dir_inode_op_update_time(
		struct inode *,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0))
		enum fs_update_time type,
		unsigned
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0)) */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0))
		struct timespec64 *,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)) */
		struct timespec *,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) ... */
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) ... */
		int);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0))
static int fsapi_linux_dir_inode_op_fileattr_set(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *mnt_userns,
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0) */
		struct user_namespace *mnt_userns,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *dentry,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		struct file_kattr *fa);
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0) */
		struct fileattr *fa);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */

static int fsapi_linux_dir_inode_op_fileattr_get(
		struct dentry *dentry,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		struct file_kattr *fa);
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0) */
		struct fileattr *fa);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)) */

static const struct inode_operations fsapi_linux_dir_inode_operations = {
	/* struct dentry* (*lookup)(
	 *     struct inode *,
	 *     struct dentry *,
	 *     unsigned int) */
	.lookup = fsapi_linux_dir_inode_op_lookup,
	/* const char* (*get_link)(
	 *     struct dentry *,
	 *     struct inode *,
	 *     struct delayed_call *) */
	.get_link = NULL,
	/* int (*permission)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     int) */
	.permission = NULL,
	/* struct posix_acl* (*get_acl)(
	 *     struct inode *,
	 *     int,
	 *     bool) */
	.get_acl = NULL,
	/* int (*readlink)(
	 *     struct dentry *,
	 *     char __user *,
	 *     int) */
	.readlink = NULL,
	/* int (*create)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t,
	 *     bool) */
	.create = fsapi_linux_dir_inode_op_create,
	/* int (*link)(
	 *     struct dentry *,
	 *     struct inode *,
	 *     struct dentry *) */
	.link = fsapi_linux_dir_inode_op_link,
	/* int (*unlink)(
	 *     struct inode *,
	 *     struct dentry *) */
	.unlink = fsapi_linux_dir_inode_op_unlink,
	/* int (*symlink)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     const char *) */
	.symlink = fsapi_linux_dir_inode_op_symlink,
	/* int (*mkdir)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t) */
	.mkdir = fsapi_linux_dir_inode_op_mkdir,
	/* int (*rmdir)(
	 *     struct inode *,
	 *     struct dentry *) */
	.rmdir = fsapi_linux_dir_inode_op_rmdir,
	/* int (*mknod)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t,
	 *     dev_t) */
	.mknod = fsapi_linux_dir_inode_op_mknod,
	/* int (*rename)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     unsigned int) */
	.rename = fsapi_linux_dir_inode_op_rename,
	/* int (*setattr)(
	 *     struct user_namespace *,
	 *     struct dentry *,
	 *     struct iattr *) */
	.setattr = fsapi_linux_dir_inode_op_setattr,
	/* int (*getattr)(
	 *     struct user_namespace *,
	 *     const struct path *,
	 *     struct kstat *,
	 *     u32,
	 *     unsigned int) */
	.getattr = fsapi_linux_dir_inode_op_getattr,
	/* ssize_t (*listxattr)(
	 *     struct dentry *,
	 *     char *,
	 *     size_t) */
	.listxattr = fsapi_linux_dir_inode_op_listxattr,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
	.setxattr = fsapi_linux_dir_inode_op_setxattr,
	.getxattr = fsapi_linux_dir_inode_op_getxattr,
	.removexattr = fsapi_linux_dir_inode_op_removexattr,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)) */
	/* int (*fiemap)(
	 *     struct inode *,
	 *     struct fiemap_extent_info *,
	 *     u64 start,
	 *     u64 len) */
	.fiemap = fsapi_linux_dir_inode_op_fiemap,
	/* int (*update_time)(
	 *     struct inode *,
	 *     enum fs_update_time type,(>=7.0)
	 *     struct timespec *,(<=4.17)
	 *     struct timespec64 *,(>=4.18, <=6.5)
	 *     unsigned (>=7.0) int) */
	.update_time = fsapi_linux_dir_inode_op_update_time,
	/* int (*atomic_open)(
	 *     struct inode *,
	 *     struct dentry *,
	 *     struct file *,
	 *     unsigned open_flag,
	 *     umode_t create_mode) */
	.atomic_open = NULL,
	/* int (*tmpfile)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct dentry *,
	 *     umode_t) */
	.tmpfile = NULL,
	/* int (*set_acl)(
	 *     struct user_namespace *,
	 *     struct inode *,
	 *     struct posix_acl *,
	 *     int) */
	.set_acl = NULL,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0))
	/* int (*fileattr_set)(
	 *     struct user_namespace *mnt_userns,(<=6.2-ish)
	 *     struct mnt_idmap *mnt_userns, (>=6.5-ish),
	 *     struct dentry *dentry,
	 *     struct fileattr *fa) */
	.fileattr_set = fsapi_linux_dir_inode_op_fileattr_set,
	/* int (*fileattr_get)(
	 *     struct dentry *dentry,
	 *     struct fileattr *fa) */
	.fileattr_get = fsapi_linux_dir_inode_op_fileattr_get,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)) */
};

static const char* fsapi_linux_symlink_inode_op_get_link(
		struct dentry *,
		struct inode *,
		struct delayed_call *);

static int fsapi_linux_symlink_inode_op_setattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *entry,
		struct iattr *attr);

static int fsapi_linux_symlink_inode_op_getattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
		const struct path *path,
		struct kstat *stat,
		u32 request_mask,
		unsigned int query_flags
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)) ... */
		struct vfsmount *mnt,
		struct dentry *dentry,
		struct kstat *stat
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)) ... */
		);

static ssize_t fsapi_linux_symlink_inode_op_listxattr(
		struct dentry *,
		char *,
		size_t);

static int fsapi_linux_symlink_inode_op_fiemap(
		struct inode *inode,
		struct fiemap_extent_info *fieinfo,
		u64 start,
		u64 len);

static int fsapi_linux_symlink_inode_op_update_time(
		struct inode *,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0))
		enum fs_update_time type,
		unsigned
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0)) */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0))
		struct timespec64 *,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)) */
		struct timespec *,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) ... */
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) */
		int);

static const struct inode_operations fsapi_linux_symlink_inode_operations = {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0))
	/* const char* (*get_link)(
	 *     struct dentry *,
	 *     struct inode *,
	 *     struct delayed_call *) */
	.get_link = fsapi_linux_symlink_inode_op_get_link,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)) */
	.follow_link = fsapi_linux_symlink_inode_op_follow_link,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)) ... */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0))
	/* int (*readlink)(
	 *     struct dentry *,
	 *     char __user *,
	 *     int) */
	.readlink = generic_readlink,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)) */
	/* int (*setattr)(
	 *     struct user_namespace *,
	 *     struct dentry *,
	 *     struct iattr *) */
	.setattr = fsapi_linux_symlink_inode_op_setattr,
	/* int (*getattr)(
	 *     struct user_namespace *,
	 *     const struct path *,
	 *     struct kstat *,
	 *     u32,
	 *     unsigned int) */
	.getattr = fsapi_linux_symlink_inode_op_getattr,
	/* ssize_t (*listxattr)(
	 *     struct dentry *,
	 *     char *,
	 *     size_t) */
	.listxattr = fsapi_linux_symlink_inode_op_listxattr,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
	.setxattr = fsapi_linux_symlink_inode_op_setxattr,
	.getxattr = fsapi_linux_symlink_inode_op_getxattr,
	.removexattr = fsapi_linux_symlink_inode_op_removexattr,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)) */
	/* int (*fiemap)(
	 *     struct inode *,
	 *     struct fiemap_extent_info *,
	 *     u64 start,
	 *     u64 len) */
	.fiemap = fsapi_linux_symlink_inode_op_fiemap,
	/* int (*update_time)(
	 *     struct inode *,
	 *     enum fs_update_time type,(>=7.0)
	 *     struct timespec *,(<=4.17)
	 *     struct timespec64 *,(>=4.18, <=6.5)
	 *     unsigned (>=7.0) int) */
	.update_time = fsapi_linux_symlink_inode_op_update_time,
};

static int fsapi_linux_special_inode_op_setattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *entry,
		struct iattr *attr);

static int fsapi_linux_special_inode_op_getattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
		const struct path *path,
		struct kstat *stat,
		u32 request_mask,
		unsigned int query_flags
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)) */
		struct vfsmount *mnt,
		struct dentry *dentry,
		struct kstat *stat
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)) ... */
		);

static ssize_t fsapi_linux_special_inode_op_listxattr(
		struct dentry *,
		char *,
		size_t);

static int fsapi_linux_special_inode_op_update_time(
		struct inode *,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0))
		enum fs_update_time type,
		unsigned
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0)) */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0))
		struct timespec64 *,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)) */
		struct timespec *,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) ... */
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) ... */
		int);

static const struct inode_operations fsapi_linux_special_inode_operations = {
	/* int (*setattr)(
	 *     struct user_namespace *,
	 *     struct dentry *,
	 *     struct iattr *) */
	.setattr = fsapi_linux_special_inode_op_setattr,
	/* int (*getattr)(
	 *     struct user_namespace *,
	 *     const struct path *,
	 *     struct kstat *,
	 *     u32,
	 *     unsigned int) */
	.getattr = fsapi_linux_special_inode_op_getattr,
	/* ssize_t (*listxattr)(
	 *     struct dentry *,
	 *     char *,
	 *     size_t) */
	.listxattr = fsapi_linux_special_inode_op_listxattr,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
	.setxattr = fsapi_linux_special_inode_op_setxattr,
	.getxattr = fsapi_linux_special_inode_op_getxattr,
	.removexattr = fsapi_linux_special_inode_op_removexattr,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)) */
	/* int (*update_time)(
	 *     struct inode *,
	 *     enum fs_update_time type,(>=7.0)
	 *     struct timespec *,(<=4.17)
	 *     struct timespec64 *,(>=4.18, <=6.5)
	 *     unsigned (>=7.0) int) */
	.update_time = fsapi_linux_special_inode_op_update_time,
};

static const struct vm_operations_struct fsapi_linux_vm_operations = {
	/* void (*open)(
	 *     struct vm_area_struct * area) */
	.open = NULL,

	/* void (*close)(
	 *     struct vm_area_struct * area) */
	.close = NULL,

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0))
	/* int (*may_split)(
	 *     struct vm_area_struct *area,
	 *     unsigned long addr) */
	.may_split = NULL,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)) */
	/* int (*split)(
	 *     struct vm_area_struct *area,
	 *     unsigned long addr) */
	.split = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)) ... */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0))
	/* int (*mremap)(
	 *     struct vm_area_struct *area,
	 *     unsigned long flags) */
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)) */
	/* int (*mremap)(
	 *     struct vm_area_struct * area);*/
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)) ... */
	.mremap = NULL,

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0))
	/* int (*mprotect)(
	 *     struct vm_area_struct *vma,
	 *     unsigned long start,
	 *     unsigned long end,
	 *     unsigned long newflags) */
	.mprotect = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)) ... */

	/* vm_fault_t (*fault)(
	 *     struct vm_fault *vmf) */
	.fault = filemap_fault,

	/* vm_fault_t (*huge_fault)(
	 *     struct vm_fault *vmf,
	 *     enum page_entry_size pe_size) */
	.huge_fault = NULL,

	/* vm_fault_t (*map_pages)(
	 *     struct vm_fault *vmf,
	 *     pgoff_t start_pgoff,
	 *     pgoff_t end_pgoff) */
	.map_pages = filemap_map_pages,

	/* unsigned long (*pagesize)(
	 *     struct vm_area_struct * area) */
	.pagesize = NULL,

	/* vm_fault_t (*page_mkwrite)(
	 *     struct vm_fault *vmf) */
	.page_mkwrite = filemap_page_mkwrite,

	/* vm_fault_t (*pfn_mkwrite)(
	 *     struct vm_fault *vmf) */
	.pfn_mkwrite = NULL,

	/* int (*access)(
	 *     struct vm_area_struct *vma,
	 *     unsigned long addr,
	 *     void *buf,
	 *     int len,
	 *     int write) */
	.access = NULL,

	/* const char* (*name)(
	 *     struct vm_area_struct *vma) */
	.name = NULL,

#ifdef CONFIG_NUMA
	/* int (*set_policy)(
	 *     struct vm_area_struct *vma,
	 *     struct mempolicy *new) */
	.set_policy = NULL,

	/* struct mempolicy* (*get_policy)(
	 *     struct vm_area_struct *vma,
	 *     unsigned long addr) */
	.get_policy = NULL,
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0))
#ifdef CONFIG_FIND_NORMAL_PAGE
	/* struct page *(*find_normal_page)(
	 *     struct vm_area_struct *vma,
	 *     unsigned long addr) */
	.find_normal_page = NULL,
#endif /* CONFIG_FIND_NORMAL_PAGE */
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,18,0)) */
	/* struct page* (*find_special_page)(
	 *     struct vm_area_struct *vma,
	 *     unsigned long addr) */
	.find_special_page = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0)) ... */
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0))
static int fsapi_linux_address_space_op_read_folio(struct file *,
		struct folio *);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)) */
static int fsapi_linux_address_space_op_readpage(struct file *, struct page *);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)) ... */

/* Write back some dirty pages from this mapping. */
static int fsapi_linux_address_space_op_writepages(struct address_space *,
		struct writeback_control *);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
/* Mark a folio dirty.  Return true if this dirtied it */
static bool fsapi_linux_address_space_op_dirty_folio(struct address_space *,
		struct folio *);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
static int fsapi_linux_address_space_op_set_page_dirty(struct page *);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
static void fsapi_linux_address_space_op_readahead(struct readahead_control *);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
static int fsapi_linux_address_space_op_readpages(struct file *,
		struct address_space *, struct list_head *, unsigned);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */

static int fsapi_linux_address_space_op_write_begin(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		const struct kiocb *iocb,
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0) */
		struct file *file,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
		struct address_space *mapping,
		loff_t pos,
		unsigned len,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0))
		unsigned flags,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)) */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0))
		struct folio **foliop,
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0) */
		struct page **pagep,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)) ... */
		void **fsdata);

static int fsapi_linux_address_space_op_write_end(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		const struct kiocb *,
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0) */
		struct file *,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
		struct address_space *mapping,
		loff_t pos,
		unsigned len,
		unsigned copied,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0))
		struct folio *folio,
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0) */
		struct page *page,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)) ... */
		void *fsdata);

static sector_t fsapi_linux_address_space_op_bmap(struct address_space *,
		sector_t);

static ssize_t fsapi_linux_address_space_op_direct_IO(struct kiocb *,
		struct iov_iter *iter);

const struct address_space_operations fsapi_linux_address_space_operations = {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0))
	/* int (*read_folio)(struct file *, struct folio *) */
	.read_folio = fsapi_linux_address_space_op_read_folio,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)) */
	/* int (*readpage)(struct file *, struct page *) */
	.readpage = fsapi_linux_address_space_op_readpage,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)) ... */

	/* int (*writepages)(struct address_space *,
	 *     struct writeback_control *) */
	.writepages = 1 ? NULL : fsapi_linux_address_space_op_writepages,

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	/* bool (*dirty_folio)(struct address_space *, struct folio *) */
	.dirty_folio = 1 ? NULL : fsapi_linux_address_space_op_dirty_folio,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
	/* int (*set_page_dirty)(struct page *) */
	.set_page_dirty = 1 ? NULL : fsapi_linux_address_space_op_set_page_dirty,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	/* void (*readahead)(struct readahead_control *) */
	.readahead = fsapi_linux_address_space_op_readahead,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
	/* int (*readpages)(struct file *, struct address_space *,
	 *     struct list_head *, unsigned) */
	.readpages = fsapi_linux_address_space_op_readpages,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */

	/* int (*write_begin)(
	 *     const struct kiocb * (>= 6.17),
	 *     struct file * (< 6.17),
	 *     struct address_space *mapping,
	 *     loff_t pos,
	 *     unsigned len,
	 *     unsigned flags (<= 5.19),
	 *     struct folio **foliop (>= 6.12),
	 *     struct page **pagep (< 6.12),
	 *     void **fsdata) */
	.write_begin = 1 ? NULL : fsapi_linux_address_space_op_write_begin,

	/* int (*write_end)(
	 *     const struct kiocb * (>= 6.17),
	 *     struct file * (< 6.17),
	 *     struct address_space *mapping,
	 *     loff_t pos,
	 *     unsigned len,
	 *     unsigned copied,
	 *     struct folio *folio (>= 6.12),
	 *     struct page *page (< 6.12),
	 *     void *fsdata) */
	.write_end = 1 ? NULL : fsapi_linux_address_space_op_write_end,

	/* sector_t (*bmap)(struct address_space *, sector_t) */
	.bmap = fsapi_linux_address_space_op_bmap,

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	/* void (*invalidate_folio) (struct folio *, size_t offset,
	 *     size_t len) */
	.invalidate_folio = 1 ? NULL : block_invalidate_folio,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
	/* void (*invalidatepage) (struct page *, unsigned int, unsigned int) */
	.invalidatepage = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0))
	/* bool (*release_folio)(struct folio *, gfp_t) */
	.release_folio = NULL,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)) */
	/* int (*releasepage) (struct page *, gfp_t) */
	.releasepage = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)) ... */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0))
	/* void (*free_folio)(struct folio *folio) */
	.free_folio = NULL,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)) */
	/* void (*freepage)(struct page *) */
	.freepage = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)) ... */

	/* ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *iter) */
	.direct_IO = fsapi_linux_address_space_op_direct_IO,

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0))
	/* int (*migrate_folio)(struct address_space *, struct folio *dst,
	 *     struct folio *src, enum migrate_mode) */
	.migrate_folio = buffer_migrate_folio,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)) */
	/* int (*migratepage) (struct address_space *, struct page *,
	 *     struct page *, enum migrate_mode) */
	.migratepage = buffer_migrate_page,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)) ... */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
	/* int (*launder_folio)(struct folio *) */
	.launder_folio = NULL,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,17,0)) */
	/* int (*launder_page) (struct page *); */
	.launder_page = NULL,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)) */

	/* bool (*is_partially_uptodate) (struct folio *, size_t from,
	 *     size_t count) */
	.is_partially_uptodate = block_is_partially_uptodate,

	/* void (*is_dirty_writeback) (struct folio *, bool *dirty, bool *wb) */
	.is_dirty_writeback = NULL,

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
	/* int (*error_remove_folio)(struct address_space *, struct folio *) */
	.error_remove_folio = generic_error_remove_folio,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
	/* int (*error_remove_page)(struct address_space *, struct page *) */
	.error_remove_page = generic_error_remove_page,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */
};

static int fsapi_linux_xattr_get(
		const struct xattr_handler *handler,
		struct dentry *dentry,
		struct inode *inode,
		const char *name,
		void *value,
		size_t size);

static int fsapi_linux_xattr_set(
		const struct xattr_handler *handler,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *idmap,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *idmap,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *dentry,
		struct inode *inode,
		const char *name,
		const void *value,
		size_t size,
		int flags);

static const struct xattr_handler fsapi_linux_xattr_handler = {
	/* const char *name */
	NULL,
	/* const char *prefix */
	"",
	/* int flags */
	0,
	/* bool (*list)(struct dentry *dentry) */
	NULL,
	/* int (*get)(const struct xattr_handler *, struct dentry *dentry,
	 *     struct inode *inode, const char *name, void *buffer,
	 *     size_t size) */
	fsapi_linux_xattr_get,
	/* int (*set)(const struct xattr_handler *,
	 *     struct mnt_idmap *idmap, struct dentry *dentry,
	 *     struct inode *inode, const char *name, const void *buffer,
	 *     size_t size, int flags) */
	fsapi_linux_xattr_set,
};

static const struct xattr_handler* fsapi_linux_xattr_handlers[] = {
	&fsapi_linux_xattr_handler,
	NULL,
};

static inline fsapi_volume* fsapi_linux_sb_to_fsapi_volume(
		struct super_block *sb)
{
	return sb->s_fs_info ? ((fsapi_linux_context*) sb->s_fs_info)->vol :
		NULL;
}

static inline fsapi_node* fsapi_linux_inode_to_fsapi_node(
		struct inode *inode)
{
	return inode ? (fsapi_node*) inode->i_private : NULL;
}

static void fsapi_linux_attributes_to_inode(
		const fsapi_node_attributes *const attributes,
		struct inode *const ino,
		const sys_bool fill_operations)
{
	dev_t rdev = 0;

	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_MODE) {
		ino->i_mode = attributes->mode;
	}
	else {
		ino->i_mode =
			(attributes->is_directory ? S_IFDIR : S_IFREG) | 0777U;
	}
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT) {
		set_nlink(ino, attributes->link_count);
	}
	else {
		set_nlink(ino, attributes->is_directory ? 3 : 1);
	}
#if 0
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATION_BLOCK_SIZE)
	{
		ino->i_blkbits = ffs(attributes->allocation_block_size);
	}
	else
#endif
	{
		ino->i_blkbits = PAGE_SHIFT;
	}
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER) {
		ino->i_ino = attributes->inode_number;
	}
#if 0
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_DEVICE_NUMBER) {
		rdev = MKDEV(attributes->device_number_major,
			attributes->device_number_minor);
	}
#endif
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_UID) {
		ino->i_uid = KUIDT_INIT(attributes->uid);
	}
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_GID) {
		ino->i_gid = KGIDT_INIT(attributes->gid);
	}
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_SIZE) {
		ino->i_size = attributes->size;
	}
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
		inode_set_atime(ino, attributes->last_data_access_time.tv_sec,
			attributes->last_data_access_time.tv_nsec);
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0) */
		ino->i_atime.tv_sec = attributes->last_data_access_time.tv_sec;
		ino->i_atime.tv_nsec =
			attributes->last_data_access_time.tv_nsec;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0) ... */
	}
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
		inode_set_mtime(ino, attributes->last_data_change_time.tv_sec,
			attributes->last_data_change_time.tv_nsec);
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0) */
		ino->i_mtime.tv_sec = attributes->last_data_change_time.tv_sec;
		ino->i_mtime.tv_nsec =
			attributes->last_data_change_time.tv_nsec;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0) ... */
	}
	if(attributes->valid &
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)
		inode_set_ctime(ino,
			attributes->last_status_change_time.tv_sec,
			attributes->last_status_change_time.tv_nsec);
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0) */
		ino->i_ctime.tv_sec =
			attributes->last_status_change_time.tv_sec;
		ino->i_ctime.tv_nsec =
			attributes->last_status_change_time.tv_nsec;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0) ... */
	}
	if(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE) {
		ino->i_blocks = (attributes->allocated_size + 511) / 512;
	}
	else {
		ino->i_blocks = (ino->i_size + 511) / 512;
	}
	ino->i_flags = 0;
	ino->i_generation = 0;

	if(!fill_operations);
	else if(attributes->is_directory) {
		sys_log_debug("Setting directory operations for inode %p with "
			"mode 0%o...", ino, ino->i_mode);
		ino->i_op = &fsapi_linux_dir_inode_operations;
		ino->i_fop = &fsapi_linux_dir_operations;
	}
	else if(S_ISLNK(ino->i_mode)) {
		sys_log_debug("Setting symlink operations for inode %p with "
			"mode 0%o...", ino, ino->i_mode);
		ino->i_op = &fsapi_linux_symlink_inode_operations;
		ino->i_fop = &fsapi_linux_null_file_operations;
	}
	else if(S_ISBLK(ino->i_mode) || S_ISCHR(ino->i_mode)) {
		sys_log_debug("Setting special operations for inode %p with "
			"mode 0%o...", ino, ino->i_mode);
		ino->i_blkbits = ino->i_sb->s_blocksize_bits;
		init_special_inode(ino, ino->i_mode, rdev);
		ino->i_op = &fsapi_linux_special_inode_operations;
	}
	else {
		sys_log_debug("Setting file operations for inode %p with mode "
			"0%o...", ino, ino->i_mode);
		ino->i_op = &fsapi_linux_file_inode_operations;
		ino->i_fop = &fsapi_linux_file_operations;
		ino->i_mapping->a_ops = &fsapi_linux_address_space_operations;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
		mapping_set_large_folios(
			/* struct address_space *mapping */
			ino->i_mapping);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) */
	}
}

static int fsapi_linux_getattr_common(
		fsapi_volume *const vol,
		fsapi_node *const node,
		const int request_mask,
		struct kstat *const stat)
{
	int ret = 0;
	int err = 0;
	fsapi_node_attributes attrs;

	memset(&attrs, 0, sizeof(attrs));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	attrs.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATION_BLOCK_SIZE |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS |
		FSAPI_NODE_ATTRIBUTE_TYPE_WINDOWS_FLAGS |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_DEVICE_NUMBER |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE;

	err = fsapi_node_get_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* fsapi_node_attributes *out_attributes */
		&attrs);
	if(err) {
		ret = -EIO;
		goto out;
	}

	if(!attrs.valid) {
		ret = -EOPNOTSUPP; /* ? */
		goto out;
	}

	memset(stat, 0, sizeof(*stat));

	/* Regardless of what was actually returned, pretend that we returned
	 * valid data for all of the basic 'statx' fields that the caller
	 * requests. */
	stat->result_mask = STATX_BASIC_STATS & request_mask;
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_MODE) {
		stat->/* (umode_t) */ mode = attrs.mode;
	}
	else {
		stat->/* (umode_t) */ mode =
			(attrs.is_directory ? S_IFDIR : S_IFREG) | 0777;
	}
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT) {
		stat->/* (unsigned int) */ nlink = attrs.link_count;
	}
	else {
		stat->/* (unsigned int) */ nlink =
			attrs.is_directory ? 3 : 1;
	}
#if 0
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATION_BLOCK_SIZE) {
		stat->/* (uint32_t) */ blksize = attrs.allocation_block_size;
	}
	else
#endif
	{
		stat->/* (uint32_t) */ blksize = 128UL * 1024UL;
	}
#ifdef UF_HIDDEN
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_BSD_FLAGS) {
		stat->/* (u64) */ attributes =
			((attrs.bsd_flags & (UF_IMMUTABLE | SF_IMMUTABLE)) ?
				STATX_ATTR_IMMUTABLE : 0);
		stat->/* (u64) */ attributes_mask |= STATX_ATTR_IMMUTABLE;
	}
	else
#endif /* defined(UF_HIDDEN) */
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_WINDOWS_FLAGS) {
		stat->/* (u64) */ attributes =
			(attrs.windows_flags & 0x1) ? STATX_ATTR_IMMUTABLE : 0;
		stat->/* (u64) */ attributes_mask |= STATX_ATTR_IMMUTABLE;
	}
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER) {
		stat->/* (u64) */ ino = attrs.inode_number;
	}
#if 0
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_) {
		stat->/* (dev_t) */ dev = 0; /* Do we need to fill this in? */
	}
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_DEVICE_NUMBER) {
		stat->/* (dev_t) */ rdev =
			MKDEV(attrs.device_number.major,
			attrs.device_number.minor);
	}
#endif
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_UID) {
		stat->/* (kuid_t) */ uid.val = attrs.uid;
	}
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_GID) {
		stat->/* (kgid_t) */ gid.val = attrs.gid;
	}
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_SIZE) {
		stat->/* (loff_t) */ size = attrs.size;
	}
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME) {
		stat->/* (struct timespec64) */ atime.tv_sec =
			attrs.last_data_access_time.tv_sec;
		stat->/* (struct timespec64) */ atime.tv_nsec =
			attrs.last_data_access_time.tv_nsec;
	}
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME) {
		stat->/* (struct timespec64) */ mtime.tv_sec =
			attrs.last_data_change_time.tv_sec;
		stat->/* (struct timespec64) */ mtime.tv_nsec =
			attrs.last_data_change_time.tv_nsec;
	}
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME) {
		stat->/* (struct timespec64) */ ctime.tv_sec =
			attrs.last_status_change_time.tv_sec;
		stat->/* (struct timespec64) */ ctime.tv_nsec =
			attrs.last_status_change_time.tv_nsec;
	}
	else if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME) {
		/* Fill in the last data change time when the last status change
		 * time isn't provided by the filesystem. */
		stat->/* (struct timespec64) */ ctime.tv_sec =
			attrs.last_data_change_time.tv_sec;
		stat->/* (struct timespec64) */ ctime.tv_nsec =
			attrs.last_data_change_time.tv_nsec;
	}
	if((request_mask & STATX_BTIME) &&
		attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME)
	{
		stat->/* (struct timespec64) */ btime.tv_sec =
			attrs.creation_time.tv_sec;
		stat->/* (struct timespec64) */ btime.tv_nsec =
			attrs.creation_time.tv_nsec;
		stat->result_mask |= STATX_BTIME;
	}
	if(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE) {
		stat->/* (u64) */ blocks = attrs.allocated_size / 512;
	}
	else {
		stat->/* (u64) */ blocks = (stat->size + 511) / 512;
	}
#if 0
	/* Do we need to fill these in? */
	stat->/* (u64) */ mnt_id = 0;
	stat->/* (u64) */ change_cookie = 0;
	stat->/* (u64) */ subvol = 0;
	stat->/* (u32) */ dio_mem_align = 0;
	stat->/* (u32) */ dio_offset_align = 0;
	stat->/* (u32) */ dio_read_offset_align = 0;
	stat->/* (u32) */ atomic_write_unit_min = 0;
	stat->/* (u32) */ atomic_write_unit_max = 0;
	stat->/* (u32) */ atomic_write_unit_max_opt = 0;
	stat->/* (u32) */ atomic_write_segments_max = 0;
#endif
out:
	return ret;
}

static int fsapi_linux_setattr_common(
		fsapi_volume *const vol,
		fsapi_node *const node,
		struct inode *const inode,
		struct iattr *const attr)
{
	int ret = 0;
	int err = 0;
	fsapi_node_attributes attrs;

	memset(&attrs, 0, sizeof(attrs));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	attrs.is_directory =
		((inode->i_mode & S_IFMT) == S_IFDIR) ? SYS_TRUE : SYS_FALSE;

	if(attr->ia_valid & ATTR_MODE) {
		if((attr->ia_mode & S_IFMT) &&
			(inode->i_mode & S_IFMT) != (attr->ia_mode & S_IFMT))
		{
			/* Attempted to change type of file. Let's return EINVAL
			 * if this ever happens. */
			ret = -EINVAL;
			goto out;
		}

		attrs.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_MODE;
		attrs.mode =
			(inode->i_mode & S_IFMT) |
			(attr->/* (umode_t) */ ia_mode & ~S_IFMT);
	}
	if(attr->ia_valid & ATTR_UID) {
		attrs.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_UID;
		attrs.uid = attr->/* (kuid_t) */ ia_uid.val;
	}
	if(attr->ia_valid & ATTR_GID) {
		attrs.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_GID;
		attrs.gid = attr->/* (kgid_t) */ ia_gid.val;
	}
	if(attr->ia_valid & ATTR_SIZE) {
		attrs.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_SIZE;
		attrs.size = attr->/* (loff_t) */ ia_size;
	}
	if(attr->ia_valid & ATTR_ATIME) {
		attrs.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME;
		attrs.last_data_access_time.tv_sec =
			attr->/* (struct timespec64) */ ia_atime.tv_sec;
		attrs.last_data_access_time.tv_nsec =
			attr->/* (struct timespec64) */ ia_atime.tv_nsec;
	}

	if(attr->ia_valid & ATTR_MTIME) {
		attrs.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME;
		attrs.last_data_change_time.tv_sec =
			attr->/* (struct timespec64) */ ia_mtime.tv_sec;
		attrs.last_data_change_time.tv_nsec =
			attr->/* (struct timespec64) */ ia_mtime.tv_nsec;
	}

	if(attr->ia_valid & ATTR_CTIME) {
		attrs.valid |=
			FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME;
		attrs.last_status_change_time.tv_sec =
			attr->/* (struct timespec64) */ ia_ctime.tv_sec;
		attrs.last_status_change_time.tv_nsec =
			attr->/* (struct timespec64) */ ia_ctime.tv_nsec;
	}

	attrs.requested = attrs.valid;

	err = fsapi_node_set_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* fsapi_node_attributes *attributes */
		&attrs);
	if(err) {
		ret = -err;
		goto out;
	}

	/* Update the inode fields with the values that were written to the
	 * filesystem entry. */
	fsapi_linux_attributes_to_inode(
		/* const fsapi_node_attributes *attributes */
		&attrs,
		/* struct inode *ino */
		inode,
		/* sys_bool fill_operations */
		SYS_FALSE);
out:
	return ret;
}

static int fsapi_linux_update_time_common(
		struct inode *inode,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0))
		enum fs_update_time type,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0)) */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0))
		struct timespec64 *time,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)) */
		struct timespec *time,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) ... */
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) ... */
		const int flags)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0))
	const struct timespec64 cur_time = current_time(inode);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)) */

	const sys_timespec systime = {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0))
		cur_time.tv_sec,
		cur_time.tv_nsec
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) */
		time->tv_sec,
		time->tv_nsec
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)) ... */
	};

	int ret = 0;
	int err = 0;
	fsapi_node_attributes attrs;

	memset(&attrs, 0, sizeof(attrs));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	if(FSAPI_IFELSE_LINUX_7_0(type == FS_UPD_ATIME, flags & S_ATIME)) {
		attrs.last_data_access_time = systime;
		attrs.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME;
	}
	if(FSAPI_IFELSE_LINUX_7_0(type == FS_UPD_CMTIME, flags & S_MTIME)) {
		attrs.last_data_change_time = systime;
		attrs.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME;
	}
	if(FSAPI_IFELSE_LINUX_7_0(type == FS_UPD_CMTIME, flags & S_CTIME)) {
		attrs.last_status_change_time = systime;
		attrs.valid |=
			FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME;
	}

	err = fsapi_node_set_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* fsapi_node_attributes *attributes */
		&attrs);
	if(err) {
		ret = -err;
		goto out;
	}

	if(FSAPI_IFELSE_LINUX_7_0(type == FS_UPD_ATIME, flags & S_ATIME)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
		inode_set_atime(inode, attrs.last_data_access_time.tv_sec,
			attrs.last_data_access_time.tv_nsec);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) */
		inode->i_atime.tv_sec = attrs.last_data_access_time.tv_sec;
		inode->i_atime.tv_nsec = attrs.last_data_access_time.tv_nsec;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0) ... */
	}
	if(FSAPI_IFELSE_LINUX_7_0(type == FS_UPD_CMTIME, flags & S_MTIME)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
		inode_set_mtime(inode, attrs.last_data_change_time.tv_sec,
			attrs.last_data_change_time.tv_nsec);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) */
		inode->i_mtime.tv_sec = attrs.last_data_change_time.tv_sec;
		inode->i_mtime.tv_nsec = attrs.last_data_change_time.tv_nsec;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0) ... */
	}
	if(FSAPI_IFELSE_LINUX_7_0(type == FS_UPD_CMTIME, flags & S_CTIME)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)
		inode_set_ctime(inode, attrs.last_status_change_time.tv_sec,
			attrs.last_status_change_time.tv_nsec);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)) */
		inode->i_ctime.tv_sec = attrs.last_status_change_time.tv_sec;
		inode->i_ctime.tv_nsec = attrs.last_status_change_time.tv_nsec;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0) ... */
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(7,0,0)
	if(flags & S_VERSION) {
		inode_inc_iversion(inode);
	}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(7,0,0) */
out:
	return ret;
}

static int fsapi_linux_fsync_common(
		struct file *const filp,
		const loff_t start,
		const loff_t end,
		const int datasync)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		filp->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		filp->f_inode);

	int ret = 0;
	int err = 0;

	if(start < 0 || end < start) {
		ret = -EINVAL;
		goto out;
	}
	else if(!vol) {
		goto out;
	}

	err = fsapi_node_sync(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* u64 start */
		(u64) start,
		/* u64 length */
		(u64) (end - start),
		/* sys_bool data_only */
		datasync ? SYS_TRUE : SYS_FALSE);
	if(err) {
		ret = -err;
	}
out:
	return ret;
}

typedef struct {
	/** The target buffer of the xattr listing. */
	char *buf;

	/** The allocated size of 'buf'. */
	size_t buf_size;

	/** The number of currently valid (filled) bytes in buf. */
	size_t buf_valid_size;

	/** Total size of the list of extended attributes. */
	size_t total_size;
} fsapi_linux_listxattr_context;

static int fsapi_linux_listxattr_handler(
		void *const ctx,
		const char *const name,
		const size_t name_length,
		const size_t size)
{
	fsapi_linux_listxattr_context *const context =
		(fsapi_linux_listxattr_context*) ctx;

	const size_t cur_entry_size = name_length + 1;

	int err = 0;

	(void) size;

	context->total_size += cur_entry_size;

	if(context->buf &&
		context->buf_size - context->buf_valid_size < cur_entry_size)
	{
		err = ERANGE;
		goto out;
	}

	if(context->buf) {
		memcpy(&context->buf[context->buf_valid_size], name,
			name_length);
		context->buf[context->buf_valid_size + name_length] =
			'\0';
		context->buf_valid_size += cur_entry_size;
	}
out:
	return err;
}

static ssize_t fsapi_linux_listxattr_common(
		struct dentry *const dentry,
		char *const list,
		const size_t size)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		dentry->d_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		dentry->d_inode);

	ssize_t ret = 0;
	int err = 0;
	fsapi_linux_listxattr_context context;

	memset(&context, 0, sizeof(context));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	context.buf = list;
	context.buf_size = size;

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
		fsapi_linux_listxattr_handler);
	if(err) {
		ret = -err;
		goto out;
	}

	if(list) {
		ret = (context.buf_valid_size > SSIZE_MAX) ? SSIZE_MAX :
			(ssize_t) context.buf_valid_size;
	}
	else {
		ret = (context.total_size > SSIZE_MAX) ? SSIZE_MAX :
			(ssize_t) context.total_size;
	}
out:
	return ret;
}

static struct inode* fsapi_linux_super_op_alloc_inode(
		struct super_block *sb)
{
	struct inode *ino = NULL;

	fsapi_linux_op_log_enter("sb=%p", sb);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	ino = alloc_inode_sb(sb, fsapi_inode_cache, GFP_NOFS);
#else
	ino = kmem_cache_alloc(fsapi_inode_cache, GFP_NOFS);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */
	if(unlikely(!ino)) {
		sys_log_error("Allocation of inode structure failed.");
		goto out;
	}

	inode_set_iversion(ino, 1);
out:
	fsapi_linux_op_log_leave(0, "sb=%p -> %p", sb, ino);

	return ino;
}

static void fsapi_linux_super_op_free_inode(
		struct inode *inode)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	fsapi_linux_op_log_enter("inode=%p", inode);

	(void) vol;
	(void) node;

	kmem_cache_free(fsapi_inode_cache, inode);

	fsapi_linux_op_log_leave(0, "inode=%p", inode);
}

static int fsapi_linux_super_op_write_inode(
		struct inode *inode,
		struct writeback_control *wbc)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	fsapi_linux_op_log_enter("inode=%p, wbc=%p", inode, wbc);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "inode=%p, wbc=%p", inode, wbc);

	return -EIO;
}

static int fsapi_linux_super_op_drop_inode(
		struct inode *inode)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	int ret = 0;

	fsapi_linux_op_log_enter("inode=%p", inode);

	(void) vol;
	(void) node;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0))
	ret = inode_generic_drop(inode);
#else
	ret = generic_drop_inode(inode);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0)) ... */

	fsapi_linux_op_log_leave(ret, "inode=%p", inode);

	return ret;
}

static void fsapi_linux_super_op_evict_inode(
		struct inode *inode)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_linux_context *const context =
		(fsapi_linux_context*) inode->i_sb->s_fs_info;

	int err = 0;
	fsapi_node *node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	fsapi_linux_op_log_enter("inode=%p", inode);

	if(vol && node && node != context->root_node) {
		err = fsapi_node_release(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **node */
			&node,
			/* size_t release_count */
			1);
		if(err) {
			sys_log_perror(err, "Error while releasing node %p",
				node);
		}
	}

	inode->i_private = NULL;

	truncate_inode_pages_final(&inode->i_data);
	invalidate_inode_buffers(inode);
	clear_inode(inode);

	fsapi_linux_op_log_leave(0, "inode=%p", inode);
}

static void fsapi_linux_super_op_put_super(
		struct super_block *sb)
{
	fsapi_linux_context *context = (fsapi_linux_context*) sb->s_fs_info;

	int err = 0;

	fsapi_linux_op_log_enter("sb=%p", sb);

	sys_log_debug("ctx=%p, ctx->dev=%p, ctx->vol=%p",
		context,
		context ? context->dev : NULL,
		context ? context->vol : NULL);

	sys_log_debug("Putting root %p (context: %p)...",
		context->root_inode, context);
	remove_inode_hash(context->root_inode);
	iput(context->root_inode);

	if(context->vol) {
		sys_log_debug("Unmounting volume.");
		err = fsapi_volume_unmount(
			/* fsapi_volume **vol */
			&context->vol);
		if(err) {
			sys_log_perror(err, "Error while unmounting fsapi "
				"volume");
		}

		context->root_node = NULL;
	}

	sys_log_debug("Closing device %p.", context->dev);
	err = sys_device_close(
		/* sys_device *dev */
		&context->dev);
	if(err) {
		sys_log_perror(err, "Error while closing device on unmount");
	}

	sys_log_debug("Freeing context %p.", context);
	kfree(context);
	sb->s_fs_info = NULL;

	invalidate_bdev(sb->s_bdev);

	fsapi_linux_op_log_leave(0, "sb=%p", sb);

	return;
}

static int fsapi_linux_super_op_sync_fs(
		struct super_block *sb,
		int wait)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		sb);

	int ret = 0;

	fsapi_linux_op_log_enter("sb=%p, wait=%d",
		sb, wait);

	if(vol) {
		int err = 0;

		sys_log_debug("Syncing volume %p.", vol);
		err = fsapi_volume_sync(
			/* fsapi_volume *vol */
			vol);
		if(err) {
			sys_log_perror(err, "Error while syncing fsapi volume");
			ret = -err;
		}
	}

	fsapi_linux_op_log_leave(ret, "sb=%p, wait=%d",
		sb, wait);

	return ret;
}


static int fsapi_linux_super_op_statfs(
		struct dentry *dentry,
		struct kstatfs *sfs)
{
	static const fsapi_volume_attribute_types required_kstatfs_attributes =
		FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_SIZE |
		FSAPI_VOLUME_ATTRIBUTE_TYPE_BLOCK_COUNT |
		FSAPI_VOLUME_ATTRIBUTE_TYPE_FREE_BLOCKS;

	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		dentry->d_inode->i_sb);

	int ret = 0;
	int err = 0;
	fsapi_volume_attributes attributes;

	fsapi_linux_op_log_enter(
		"dentry=%" PRIdentry ", "
		"sfs=%p",
		PRAdentry(dentry),
		sfs);

	memset(&attributes, 0, sizeof(attributes));

	attributes.requested = required_kstatfs_attributes;

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	err = fsapi_volume_get_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_volume_attributes *out_attributes */
		&attributes);
	if(err) {
		sys_log_perror(err, "Error while getting attributes for fsapi "
			"volume");
		ret = -err;
		goto out;
	}
	else if((attributes.valid & required_kstatfs_attributes) !=
		required_kstatfs_attributes)
	{
		sys_log_error("Required volume attributes not returned. "
			"Filesystem implementation is incomplete.");
		ret = -EIO;
		goto out;
	}

	sfs->f_type = 0x53466552UL; /* ReFS in ASCII stored as little endian. */
	sfs->f_bsize = attributes.block_size;
	sfs->f_blocks = attributes.block_count;
	sfs->f_bfree = sfs->f_bavail = attributes.free_blocks;

	sfs->f_files = sfs->f_blocks;
	sfs->f_ffree = sfs->f_bfree;

	sfs->f_fsid.val[0] =
		(int) (((uintptr_t) vol) ^ ((uintptr_t) dentry->d_inode->i_sb));
	sfs->f_fsid.val[1] =
		(SIZE_MAX < U64_MAX) ? ~sfs->f_fsid.val[0] :
		(int) ((((uintptr_t) vol) ^
		((uintptr_t) dentry->d_inode->i_sb)) >> 32);
	sfs->f_namelen = 255;
	sfs->f_frsize = sfs->f_bsize;
	sfs->f_flags =
		ST_RDONLY |
		/* ST_NOSUID | */
		/* ST_NODEV | */
		/* ST_NOEXEC | */
		/* ST_SYNCHRONOUS | */
		/* ST_VALID | */
		/* ST_MANDLOCK | */
		/* 0x0080 used for ST_WRITE in glibc */
		/* 0x0100 used for ST_APPEND in glibc */
		/* 0x0200 used for ST_IMMUTABLE in glibc */
		/* ST_NOATIME | */
		/* ST_NODIRATIME | */
		/* ST_RELATIME | */
		/* ST_NOSYMFOLLOW | */
		0;
out:
	fsapi_linux_op_log_leave(ret,
		"dentry=%" PRIdentry ", "
		"sfs=%p",
		PRAdentry(dentry),
		sfs);

	return ret;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(7,0,0))
static int fsapi_linux_super_op_remount_fs(
		struct super_block *sb,
		int *flags,
		char *opt)
{
	fsapi_linux_op_log_enter("sb=%p, flags=%p, opt=%s",
		sb, flags, opt ? opt : "NULL");

	fsapi_linux_op_log_leave(-EIO, "sb=%p, flags=%p, opt=%s",
		sb, flags, opt ? opt : "NULL");

	return -EIO;
}
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(7,0,0)) */

static int fsapi_linux_super_op_show_options(
		struct seq_file *sf,
		struct dentry *root)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		root->d_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		root->d_inode);

	fsapi_linux_op_log_enter("sf=%p, root=%p", sf, root);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(0, "sf=%p, root=%p", sf, root);

	return 0;
}

#if FSAPI_LINUX_SLOW_SYNCHRONOUS_READ_PATH
typedef struct {
	char __user *buf;
	size_t bytes_read;
} fsapi_linux_read_iocontext;

static int fsapi_linux_read_copy_data(
		void *const context,
		const void *const data,
		const size_t size)
{
	fsapi_linux_read_iocontext *const iocontext =
		(fsapi_linux_read_iocontext*) context;

	int err = 0;

	sys_log_debug("Copying %" PRIuz " bytes to user buffer %p, offset "
		"%" PRIuz "...",
		PRAuz(size), iocontext->buf, PRAuz(iocontext->bytes_read));

	if(copy_to_user(&iocontext->buf[iocontext->bytes_read], data, size)) {
		/* The user may have passed a bad buffer address. */
		err = EFAULT;
		goto out;
	}

	iocontext->bytes_read += size;
out:
	return err;
}

static int fsapi_linux_read_handle_io(
		void *const context,
		sys_device *const dev,
		const u64 offset,
		const size_t size)
{
	fsapi_linux_read_iocontext *const iocontext =
		(fsapi_linux_read_iocontext*) context;

	int err = 0;
	sys_iohandler iohandler;

	memset(&iohandler, 0, sizeof(iohandler));

	sys_log_debug("Transferring %" PRIuz " bytes from device offset "
		"%" PRIu64 " to user buffer %p, offset %" PRIuz "...",
		PRAuz(size), PRAu64(offset), iocontext->buf,
		PRAuz(iocontext->bytes_read));

	iohandler.context = iocontext;
	iohandler.copy_data = fsapi_linux_read_copy_data;

	err = sys_device_pread_iohandler(
		/* sys_device *dev */
		dev,
		/* u64 offset */
		offset,
		/* size_t nbytes */
		size,
		/* sys_iohandler *iohandler */
		&iohandler);

	return err;
}

static ssize_t fsapi_linux_file_op_read(
		struct file *file,
		char __user *buf,
		size_t size,
		loff_t *offset)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		file->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		file->f_inode);

	int ret = 0;
	int err = 0;
	fsapi_linux_read_iocontext iocontext;
	sys_iohandler iohandler;

	fsapi_linux_op_log_enter("file=%p, buf=%p, size=%" PRIuz ", "
		"offset=%p (->%" PRId64 ")",
		file, buf, PRAuz(size), offset, PRAd64(offset ? *offset : 0));

	memset(&iocontext, 0, sizeof(iocontext));
	memset(&iohandler, 0, sizeof(iohandler));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	iocontext.buf = buf;
	iohandler.context = &iocontext;
	iohandler.handle_io = fsapi_linux_read_handle_io;
	iohandler.copy_data = fsapi_linux_read_copy_data;

	err = fsapi_node_read(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* u64 offset */
		*offset,
		/* size_t size */
		size,
		/* fsapi_iohandler *iohandler */
		&iohandler);
	if(err) {
		ret = -err;
	}
	else {
		if(S64_MAX - *offset < iocontext.bytes_read) {
			*offset = S64_MAX;
		}
		else {
			*offset += iocontext.bytes_read;
		}

		ret = (iocontext.bytes_read > INT_MAX) ? INT_MAX :
			(int) iocontext.bytes_read;
	}
out:
	fsapi_linux_op_log_leave(ret, "file=%p, buf=%p, size=%" PRIuz ", "
		"offset=%p (->%" PRId64 ")",
		file, buf, PRAuz(size), offset, PRAd64(offset ? *offset : 0));

	return ret;
}
#endif /* FSAPI_LINUX_SLOW_SYNCHRONOUS_READ_PATH */

typedef struct {
	const char __user *buf;
	size_t bytes_written;
} fsapi_linux_write_iocontext;

static int fsapi_linux_write_get_data(
		void *const context,
		void *const data,
		const size_t size)
{
	fsapi_linux_write_iocontext *const iocontext =
		(fsapi_linux_write_iocontext*) context;

	int err = 0;

	sys_log_debug("Copying %" PRIuz " bytes from user buffer %p, offset "
		"%" PRIuz "...",
		PRAuz(size), iocontext->buf, PRAuz(iocontext->bytes_written));

	if(copy_from_user(data, &iocontext->buf[iocontext->bytes_written],
		size))
	{
		/* The user may have passed a bad buffer address. */
		err = EFAULT;
		goto out;
	}

	iocontext->bytes_written += size;
out:
	return err;
}

static ssize_t fsapi_linux_file_op_write(
		struct file *file,
		const char __user *buf,
		size_t size,
		loff_t *offset)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		file->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		file->f_inode);

	ssize_t ret = 0;
	int err = 0;
	fsapi_linux_write_iocontext iocontext;
	sys_iohandler iohandler;

	fsapi_linux_op_log_enter("file=%p, buf=%p, size=%" PRIuz ", "
		"offset=%p (->%" PRId64 ")",
		file, buf, PRAuz(size), offset, PRAd64(offset ? *offset : 0));

	memset(&iocontext, 0, sizeof(iocontext));
	memset(&iohandler, 0, sizeof(iohandler));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	iocontext.buf = buf;
	iohandler.context = &iocontext;
	iohandler.get_data = fsapi_linux_write_get_data;

	err = fsapi_node_write(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* u64 offset */
		*offset,
		/* size_t size */
		size,
		/* fsapi_iohandler *iohandler */
		&iohandler);
	if(err) {
		ret = -err;
	}
	else {
		if(S64_MAX - *offset < iocontext.bytes_written) {
			*offset = S64_MAX;
		}
		else {
			*offset += iocontext.bytes_written;
		}

		ret = (iocontext.bytes_written > INT_MAX) ? INT_MAX :
			(int) iocontext.bytes_written;
	}
out:
	fsapi_linux_op_log_leave(ret, "file=%p, buf=%p, size=%" PRIuz ", "
		"offset=%p (->%" PRId64 ")",
		file, buf, PRAuz(size), offset, PRAd64(offset ? *offset : 0));

	return ret;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
static ssize_t fsapi_linux_file_op_read_iter(
		struct kiocb *const iocb,
		struct iov_iter *const iter)
{
	ssize_t res = 0;

	fsapi_linux_op_log_enter("iocb=%p, iter=%p",
		iocb, iter);

	res = generic_file_read_iter(
		/* struct kiocb *iocb */
		iocb,
		/* struct iov_iter *iter */
		iter);

	fsapi_linux_op_log_leave(res, "iocb=%p, iter=%p",
		iocb, iter);

	return res;
}
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) */
static ssize_t fsapi_linux_file_op_aio_read(
		struct kiocb *const iocb,
		const struct iovec *const iov,
		const unsigned long nr_segs,
		const loff_t pos)
{
	ssize_t res = 0:

	fsapi_linux_op_log_enter("iocb=%p, iov=%p, nr_segs=%lu, "
		"pos=%" PRId64,
		iocb, iov, nr_segs, PRAd64(pos));

	res = generic_file_aio_read(
		/* struct kiocb *iocb */
		iocb,
		/* const struct iovec *iov */
		iov,
		/* unsigned long nr_segs */
		nr_segs,
		/* loff_t pos */
		pos);

	fsapi_linux_op_log_leave(res, "iocb=%p, iov=%p, nr_segs=%lu, "
		"pos=%" PRId64,
		iocb, iov, nr_segs, PRAd64(pos));

	return res;
}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) ... */

#if 0
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
static ssize_t fsapi_linux_file_op_write_iter(
		struct kiocb *iocb,
		struct iov_iter *from)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		iocb->ki_filp->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		iocb->ki_filp->f_inode);

	fsapi_linux_op_log_enter("iocb=%p, from=%p",
		iocb, from);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "iocb=%p, from=%p",
		iocb, from);

	return -EIO;
}
#else
static ssize_t fsapi_linux_file_op_aio_write(
		struct kiocb *iocb,
		const struct iovec *iov,
		unsigned long nr_segs,
		loff_t pos)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		iocb->ki_filp->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		iocb->ki_filp->f_inode);

	fsapi_linux_op_log_enter("iocb=%p, iov=%p, nr_segs=%lu, "
		"pos=%" PRId64,
		iocb, iov, nr_segs, PRAd64(pos));

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "iocb=%p, iov=%p, nr_segs=%lu, "
		"pos=%" PRId64,
		iocb, iov, nr_segs, PRAd64(pos));

	return -EIO;
}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) ... */
#endif

static long fsapi_linux_file_op_unlocked_ioctl(
		struct file *file,
		unsigned int cmd,
		unsigned long arg)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		file->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		file->f_inode);

	fsapi_linux_op_log_enter("file=%p, cmd=0x%X, arg=0x%lX",
		file, cmd, arg);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "file=%p, cmd=0x%X, arg=0x%lX",
		file, cmd, arg);

	return -EIO;
}

#ifdef CONFIG_COMPAT
static long fsapi_linux_file_op_compat_ioctl(
		struct file *file,
		unsigned int cmd,
		unsigned long arg)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		file->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		file->f_inode);

	fsapi_linux_op_log_enter("file=%p, cmd=0x%X, arg=0x%lX",
		file, cmd, arg);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "file=%p, cmd=0x%X, arg=0x%lX",
		file, cmd, arg);

	return -EIO;
}
#endif /* defined(CONFIG_COMPAT) */

static int fsapi_linux_file_op_mmap(
		struct file *file,
		struct vm_area_struct *vma)
{
	int ret = 0;

	fsapi_linux_op_log_enter("file=%p, vma=%p",
		file, vma);

	file_accessed(file);
	vma->vm_ops = &fsapi_linux_vm_operations;

	fsapi_linux_op_log_leave(ret, "file=%p, vma=%p",
		file, vma);

	return ret;
}

static int fsapi_linux_file_op_open(
		struct inode *inode,
		struct file *filp)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	fsapi_linux_op_log_enter("inode=%p, filp=%p",
		inode, filp);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(0, "inode=%p, filp=%p",
		inode, filp);

	return 0;
}

static int fsapi_linux_file_op_release(
		struct inode *inode,
		struct file *filp)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	fsapi_linux_op_log_enter("inode=%p, filp=%p",
		inode, filp);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(0, "inode=%p, filp=%p",
		inode, filp);

	return 0;
}

static int fsapi_linux_file_op_fsync(
		struct file *filp,
		loff_t start,
		loff_t end,
		int datasync)
{
	int ret = 0;

	fsapi_linux_op_log_enter("filp=%p, start=%" PRId64 ", "
		"end=%" PRId64 ", datasync=%d",
		filp, PRAd64(start), PRAd64(end), datasync);

	ret = fsapi_linux_fsync_common(
		/* struct file *filp */
		filp,
		/* loff_t start */
		start,
		/* loff_t end */
		end,
		/* int datasync */
		datasync);

	fsapi_linux_op_log_leave(ret, "filp=%p, start=%" PRId64 ", "
		"end=%" PRId64 ", datasync=%d",
		filp, PRAd64(start), PRAd64(end), datasync);

	return ret;
}

#if 0
static ssize_t fsapi_linux_file_op_splice_write(
		struct pipe_inode_info *pipe,
		struct file *out,
		loff_t *ppos,
		size_t len,
		unsigned int flags)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		out->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		out->f_inode);

	fsapi_linux_op_log_enter("pipe=%p, out=%p, ppos=%p "
		"(->%" PRId64 "), len=%" PRIuz ", flags=0x%X",
		pipe, out, ppos, PRAd64(ppos ? *ppos : 0), PRAuz(len), flags);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "pipe=%p, out=%p, ppos=%p "
		"(->%" PRId64 "), len=%" PRIuz ", flags=0x%X",
		pipe, out, ppos, PRAd64(ppos ? *ppos : 0), PRAuz(len), flags);

	return -EIO;
}

static ssize_t fsapi_linux_file_op_splice_read(
		struct file *in,
		loff_t *ppos,
		struct pipe_inode_info *pipe,
		size_t len,
		unsigned int flags)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		in->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		in->f_inode);

	fsapi_linux_op_log_enter("in=%p, ppos=%p (->%" PRId64 "),"
		" pipe=%p, len=%" PRIuz ", flags=0x%X",
		in, ppos, PRAd64(ppos ? *ppos : 0), pipe, PRAuz(len), flags);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "in=%p, ppos=%p (->%" PRId64 "), "
		"pipe=%p, len=%" PRIuz ", flags=0x%X",
		in, ppos, PRAd64(ppos ? *ppos : 0), pipe, PRAuz(len), flags);

	return -EIO;
}
#endif

static long fsapi_linux_file_op_fallocate(
		struct file *file,
		int mode,
		loff_t offset,
		loff_t len)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		file->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		file->f_inode);

	int ret = 0;
	int err = 0;
	int supported_modes = 0;
	fsapi_node_fallocate_flags flags = 0;

	fsapi_linux_op_log_enter(
		"file=%p, "
		"mode=0x%X, "
		"offset=%" PRId64 ", "
		"len=%" PRId64,
		file,
		mode,
		PRAd64(offset),
		PRAd64(len));

#if defined(FALLOC_FL_KEEP_SIZE)
	if(mode & FALLOC_FL_KEEP_SIZE) {
		flags |= FSAPI_NODE_FALLOCATE_FLAG_KEEP_SIZE;
	}

	supported_modes |= FALLOC_FL_KEEP_SIZE;
#endif /* defined(FALLOC_FL_KEEP_SIZE) */

#if defined(FALLOC_FL_PUNCH_HOLE)
	if(mode & FALLOC_FL_PUNCH_HOLE) {
		flags |= FSAPI_NODE_FALLOCATE_FLAG_PUNCH_HOLE;
	}

	supported_modes |= FALLOC_FL_PUNCH_HOLE;
#endif /* defined(FALLOC_FL_PUNCH_HOLE) */

#if defined(FALLOC_FL_NO_HIDE_STALE)
	if(mode & FALLOC_FL_NO_HIDE_STALE) {
		flags |= FSAPI_NODE_FALLOCATE_FLAG_NO_HIDE_STALE;
	}

	supported_modes |= FALLOC_FL_NO_HIDE_STALE;
#endif /* defined(FALLOC_FL_NO_HIDE_STALE) */

#if defined(FALLOC_FL_COLLAPSE_RANGE)
	if(mode & FALLOC_FL_COLLAPSE_RANGE) {
		flags |= FSAPI_NODE_FALLOCATE_FLAG_COLLAPSE_RANGE;
	}

	supported_modes |= FALLOC_FL_COLLAPSE_RANGE;
#endif /* defined(FALLOC_FL_COLLAPSE_RANGE) */

#if defined(FALLOC_FL_ZERO_RANGE)
	if(mode & FALLOC_FL_ZERO_RANGE) {
		flags |= FSAPI_NODE_FALLOCATE_FLAG_ZERO_RANGE;
	}

	supported_modes |= FALLOC_FL_ZERO_RANGE;
#endif /* defined(FALLOC_FL_ZERO_RANGE) */

#if defined(FALLOC_FL_INSERT_RANGE)
	if(mode & FALLOC_FL_INSERT_RANGE) {
		flags |= FSAPI_NODE_FALLOCATE_FLAG_INSERT_RANGE;
	}

	supported_modes |= FALLOC_FL_INSERT_RANGE;
#endif /* defined(FALLOC_FL_INSERT_RANGE) */

#if defined(FALLOC_FL_UNSHARE_RANGE)
	if(mode & FALLOC_FL_UNSHARE_RANGE) {
		flags |= FSAPI_NODE_FALLOCATE_FLAG_UNSHARE_RANGE;
	}

	supported_modes |= FALLOC_FL_UNSHARE_RANGE;
#endif /* defined(FALLOC_FL_UNSHARE_RANGE) */

#if defined(FALLOC_FL_WRITE_ZEROES)
	if(mode & FALLOC_FL_WRITE_ZEROES) {
		flags |= FSAPI_NODE_FALLOCATE_FLAG_WRITE_ZEROES;
	}

	supported_modes |= FALLOC_FL_WRITE_ZEROES;
#endif /* defined(FALLOC_FL_WRITE_ZEROES) */

	if(mode & ~supported_modes) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	err = fsapi_node_fallocate(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* fsapi_node_fallocate_flags flags */
		flags,
		/* u64 offset */
		offset,
		/* u64 length */
		len);
	if(err) {
		ret = -err;
	}
out:
	fsapi_linux_op_log_leave(ret,
		"file=%p, "
		"mode=0x%X, "
		"offset=%" PRId64 ", "
		"len=%" PRId64,
		file,
		mode,
		PRAd64(offset),
		PRAd64(len));

	return ret;
}

static int fsapi_linux_file_inode_op_setattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *entry,
		struct iattr *attr)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		entry->d_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		entry->d_inode);

	int ret = 0;

	fsapi_linux_op_log_enter(FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"entry=%p, attr=%p",
		FSAPI_IF_LINUX_5_12(namespace,) entry, attr);

	ret = fsapi_linux_setattr_common(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* struct inode *inode */
		entry->d_inode,
		/* struct iattr *attr */
		attr);

	fsapi_linux_op_log_leave(ret, FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"entry=%p, attr=%p",
		FSAPI_IF_LINUX_5_12(namespace,) entry, attr);

	return ret;
}

static int fsapi_linux_file_inode_op_getattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
		const struct path *path,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)) */
		struct vfsmount *mnt,
		struct dentry *dentry,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)) ... */
		struct kstat *stat
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
		,
		u32 request_mask,
		unsigned int query_flags
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)) */
		)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		FSAPI_IF_LINUX_4_11(path->)dentry->d_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		FSAPI_IF_LINUX_4_11(path->)dentry->d_inode);

	int ret = 0;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		FSAPI_IF_LINUX_4_11("path=%p, ")
		FSAPI_NOT_LINUX_4_11("mnt=%p, ")
		FSAPI_NOT_LINUX_4_11("dentry=%" PRIdentry ", ")
		"stat=%p"
		FSAPI_IF_LINUX_4_11(", request_mask=0x%" PRIX32)
		FSAPI_IF_LINUX_4_11(", query_flags=%X"),
		FSAPI_IF_LINUX_5_12(namespace,)
		FSAPI_IF_LINUX_4_11(path,)
		FSAPI_NOT_LINUX_4_11(mnt,)
		FSAPI_NOT_LINUX_4_11(PRAdentry(dentry),)
		stat
		FSAPI_IF_LINUX_4_11(, PRAX32(request_mask))
		FSAPI_IF_LINUX_4_11(, query_flags));

	ret = fsapi_linux_getattr_common(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* int request_mask */
		FSAPI_IF_LINUX_4_11(request_mask)
		FSAPI_NOT_LINUX_4_11(STATX_BASIC_STATS),
		/* struct kstat *stat */
		stat);

	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		FSAPI_IF_LINUX_4_11("path=%p, ")
		FSAPI_NOT_LINUX_4_11("mnt=%p, ")
		FSAPI_NOT_LINUX_4_11("dentry=%" PRIdentry ", ")
		"stat=%p"
		FSAPI_IF_LINUX_4_11(", request_mask=0x%" PRIX32)
		FSAPI_IF_LINUX_4_11(", query_flags=%X"),
		FSAPI_IF_LINUX_5_12(namespace,)
		FSAPI_IF_LINUX_4_11(path,)
		FSAPI_NOT_LINUX_4_11(mnt,)
		FSAPI_NOT_LINUX_4_11(PRAdentry(dentry),)
		stat
		FSAPI_IF_LINUX_4_11(, PRAX32(request_mask))
		FSAPI_IF_LINUX_4_11(, query_flags));

	return ret;
}

static ssize_t fsapi_linux_file_inode_op_listxattr(
		struct dentry *dentry,
		char *list,
		size_t size)
{
	int ret = 0;

	fsapi_linux_op_log_enter(
		"dentry=%" PRIdentry ", "
		"list=%p, "
		"size=%" PRIuz,
		PRAdentry(dentry),
		list,
		PRAuz(size));

	ret = fsapi_linux_listxattr_common(
		/* struct dentry *dentry */
		dentry,
		/* char *list */
		list,
		/* size_t size */
		size);

	fsapi_linux_op_log_leave(ret,
		"dentry=%" PRIdentry ", "
		"list=%p, "
		"size=%" PRIuz,
		PRAdentry(dentry),
		list,
		PRAuz(size));

	return ret;
}

static int fsapi_linux_file_inode_op_fiemap(
		struct inode *inode,
		struct fiemap_extent_info *fieinfo,
		u64 start,
		u64 len)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	fsapi_linux_op_log_enter("inode=%p, fieinfo=%p, start=%" PRIu64 ", "
		"len=%" PRIu64,
		inode, fieinfo, PRAu64(start), PRAu64(len));

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "inode=%p, fieinfo=%p, "
		"start=%" PRIu64 ", len=%" PRIu64,
		inode, fieinfo, PRAu64(start), PRAu64(len));

	return -EIO;
}

static int fsapi_linux_file_inode_op_update_time(
		struct inode *inode,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0))
		enum fs_update_time type,
		unsigned
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0)) */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0))
		struct timespec64 *time,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)) */
		struct timespec *time,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) ... */
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) ... */
		int flags)
{
	int ret = 0;

	fsapi_linux_op_log_enter(
		"inode=%p, "
		FSAPI_NOT_LINUX_6_6("time=%p, ")
		"flags=0x%X",
		inode,
		FSAPI_NOT_LINUX_6_6(time,)
		flags);

	ret = fsapi_linux_update_time_common(
		/* struct inode *inode */
		inode,
		/* enum fs_update_time type */
		FSAPI_IF_LINUX_7_0(type,)
		/* struct timespec[64] *time */
		FSAPI_NOT_LINUX_6_6(time,)
		/* int flags */
		flags);

	fsapi_linux_op_log_leave(ret,
		"inode=%p, "
		FSAPI_NOT_LINUX_6_6("time=%p, ")
		"flags=0x%X",
		inode,
		FSAPI_NOT_LINUX_6_6(time,)
		flags);

	return ret;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0))
static int fsapi_linux_file_inode_op_fileattr_set(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *mnt_userns,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0)) */
		struct user_namespace *mnt_userns,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *dentry,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		struct file_kattr *fa)
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)) */
		struct fileattr *fa)
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		dentry->d_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		dentry->d_inode);

	fsapi_linux_op_log_enter(
		"mnt_userns=%p, "
		"dentry=%" PRIdentry ", "
		"fa=%p",
		mnt_userns,
		PRAdentry(dentry),
		fa);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO,
		"mnt_userns=%p, "
		"dentry=%" PRIdentry ", "
		"fa=%p",
		mnt_userns,
		PRAdentry(dentry),
		fa);

	return -EIO;
}

static int fsapi_linux_file_inode_op_fileattr_get(
		struct dentry *dentry,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		struct file_kattr *fa)
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)) */
		struct fileattr *fa)
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		dentry->d_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		dentry->d_inode);

	int ret = 0;
	int err = 0;
	fsapi_node_attributes attrs;

	memset(&attrs, 0, sizeof(attrs));

	fsapi_linux_op_log_enter(
		"dentry=%" PRIdentry ", "
		"fa=%p",
		PRAdentry(dentry),
		fa);

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	attrs.requested = FSAPI_NODE_ATTRIBUTE_TYPE_WINDOWS_FLAGS;

	err = fsapi_node_get_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* fsapi_node_attributes *out_attributes */
		&attrs);
	if(err) {
		ret = -EIO;
		goto out;
	}

	if(!(attrs.valid & FSAPI_NODE_ATTRIBUTE_TYPE_WINDOWS_FLAGS)) {
		ret = -ENOTSUP;
		goto out;
	}

	memset(fa, 0, sizeof(*fa));

	fa->flags_valid = true;
	if(attrs.windows_flags & 0x01) {
		fa->flags |= FS_IMMUTABLE_FL;
	}
out:
	fsapi_linux_op_log_leave(ret,
		"dentry=%" PRIdentry ", "
		"fa=%p",
		PRAdentry(dentry),
		fa);

	return ret;
}
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)) */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0) || \
		defined(BACKPORT_DIR_CONTEXT))

typedef struct {
	struct dir_context *actor;
	u64 cur_index;
	u64 requested_index;
} fsapi_linux_readdir_context;

static int fsapi_linux_readdir_handle_dirent(
		void *context,
		const char *name,
		size_t name_length,
		fsapi_node_attributes *attributes)
{
	fsapi_linux_readdir_context *const ctx =
		(fsapi_linux_readdir_context*) context;
	int err = 0;
	u64 next_index;

	sys_log_debug("Emitting %s entry \"%.*s\" with index %" PRIu64 ", mode "
		"0%" PRIo32 "...",
		attributes->is_directory ? "directory" : "file",
		(name_length > INT_MAX) ? INT_MAX : (int) name_length, name,
		PRAu64(ctx->cur_index), PRAo32(attributes->mode));

	next_index = ctx->cur_index + 1;

	if(ctx->cur_index >= ctx->requested_index && !dir_emit(
		/* struct dir_context *ctx */
		ctx->actor,
		/* const char *name */
		name,
		/* int namelen */
		name_length,
		/* u64 ino */
		(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER) ?
			attributes->inode_number : 0,
		/* unsigned type */
		(attributes->valid & FSAPI_NODE_ATTRIBUTE_TYPE_MODE) ?
			S_DT(attributes->mode) :
			(attributes->is_directory ? DT_DIR : DT_REG)))
	{
		err = -1;
	}
	else {
		ctx->actor->pos = 2 + next_index;
		ctx->cur_index = next_index;
	}

	return err;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0))
static int fsapi_linux_dir_op_iterate_shared(
		struct file *filp,
		struct dir_context *actor)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0) || \
		defined(BACKPORT_DIR_CONTEXT))
static int fsapi_linux_dir_op_iterate(
		struct file *filp,
		struct dir_context *actor)
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)) ... */
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		filp->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		filp->f_inode);

	int ret = 0;
	int err = 0;
	u64 offset;
	sys_bool abort = SYS_FALSE;
	fsapi_node_attributes attributes;
	fsapi_linux_readdir_context context;

	fsapi_linux_op_log_enter("filp=%p, actor=%p (pos: %" PRIu64 ")",
		filp, actor, PRAu64(actor ? actor->pos : 0));

	memset(&attributes, 0, sizeof(attributes));
	memset(&context, 0, sizeof(context));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	offset = actor->pos;

	/* Offset 0 and 1 are reserved for the synthesized '.'/'..' entries. */
	if(offset == 0) {
		sys_log_debug("Calling actor for . with len 1, pos 0x0, "
			"inode %lu, DT_DIR.", filp->f_inode->i_ino);

		actor->pos = offset;
		abort = !dir_emit(
			/* struct dir_context *ctx */
			actor,
			/* const char *name */
			".",
			/* int namelen */
			1,
			/* u64 ino */
			(filp->f_inode->i_ino < 2) ? 2 : filp->f_inode->i_ino,
			/* unsigned type */
			DT_DIR);
		if(abort) {
			goto out;
		}
		offset++;
		actor->pos = offset;
	}
	if(offset == 1) {
		const u64 parent_inode_number =
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,11,0))
			d_parent_ino(filp->f_path.dentry);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,11,0)) */
			parent_ino(filp->f_path.dentry);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,11,0)) ... */

		sys_log_debug("Calling actor for .. with len 2, pos 0x1, inode "
			"%" PRIu64 ", DT_DIR.",
			PRAu64(parent_inode_number));

		actor->pos = offset;
		abort = !dir_emit(
			/* struct dir_context *ctx */
			actor,
			/* const char *name */
			"..",
			/* int namelen */
			2,
			/* u64 ino */
			(parent_inode_number < 2) ? 2 : parent_inode_number,
			/* unsigned type */
			DT_DIR);
		if(abort) {
			goto out;
		}

		offset++;
		actor->pos = offset;
	}


	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER;

	context.actor = actor;
	context.requested_index = (offset > 2) ? offset - 2 : 0;

	sys_log_debug("Calling node_list with index %" PRIu64,
		PRAu64(context.requested_index));

	err = fsapi_node_list(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *directory_node */
		node,
#if 0
		/* u64 offset */
		(offset > 2) ? offset - 2 : 0,
#endif
		/* fsapi_node_attributes *attributes */
		&attributes,
		/* void *context */
		&context,
		/* int (*handle_dirent)(
		 *     void *context,
		 *     const char *name,
		 *     size_t name_length,
		 *     fsapi_node_attributes *attributes) */
		fsapi_linux_readdir_handle_dirent);
	if(err == -1) {
		/* Break code when the buffer is full, not an error. */
		err = 0;
	}
	else if(err == ENOENT) {
		/* This is expected if the directory has been removed. */
		sys_log_debug("Attempted to list removed directory.");
		ret = -ENOENT;
	}
	else if(err) {
		sys_log_perror(err, "handle_dirent callback returned error for "
			"offset %" PRIu64, PRAu64(offset));
		ret = -err;
	}
out:
	fsapi_linux_op_log_leave(-ret, "filp=%p, actor=%p",
		filp, actor);

	return -ret;
}
#else
static int fsapi_linux_dir_op_readdir(
		struct file *filp,
		void *dirent,
		filldir_t filldir)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		filp->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		filp->f_inode);

	fsapi_linux_op_log_enter("filp=%p, dirent=%p, filldir=%p",
		filp, dirent, filldir);

	(void) vol;
	(void) node;

#error "readdir not implemented yet"

	fsapi_linux_op_log_leave(-EIO, "filp=%p, dirent=%p, filldir=%p",
		filp, dirent, filldir);

	return -EIO;
}
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0) || ... */

static long fsapi_linux_dir_op_unlocked_ioctl(
		struct file *file,
		unsigned int cmd,
		unsigned long arg)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		file->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		file->f_inode);

	fsapi_linux_op_log_enter("file=%p, cmd=0x%X, arg=0x%" PRIX32,
		file, cmd, PRAX32(arg));

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "file=%p, cmd=0x%X, arg=0x%" PRIX32,
		file, cmd, PRAX32(arg));

	return -EIO;
}

#ifdef CONFIG_COMPAT
static long fsapi_linux_dir_op_compat_ioctl(
		struct file *file,
		unsigned int cmd,
		unsigned long arg)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		file->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		file->f_inode);

	fsapi_linux_op_log_enter("file=%p, cmd=0x%X, arg=0x%" PRIX32,
		file, cmd, PRAX32(arg));

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "file=%p, cmd=0x%X, arg=0x%" PRIX32,
		file, cmd, PRAX32(arg));

	return -EIO;
}
#endif /* CONFIG_COMPAT */

static int fsapi_linux_dir_op_open(
		struct inode *inode,
		struct file *filp)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	fsapi_linux_op_log_enter("inode=%p, filp=%p", inode, filp);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(0, "inode=%p, filp=%p", inode, filp);

	return 0;
}

static int fsapi_linux_dir_op_release(
		struct inode *inode,
		struct file *filp)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	fsapi_linux_op_log_enter("inode=%p, filp=%p",
		inode, filp);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(0, "inode=%p, filp=%p",
		inode, filp);

	return 0;
}

static int fsapi_linux_dir_op_fsync(
		struct file *filp,
		loff_t start,
		loff_t end,
		int datasync)
{
	int ret = 0;

	fsapi_linux_op_log_enter("filp=%p, start=%" PRId64 ", "
		"end=%" PRId64 ", datasync=%d",
		filp, PRAd64(start), PRAd64(end), datasync);

	ret = fsapi_linux_fsync_common(
		/* struct file *filp */
		filp,
		/* loff_t start */
		start,
		/* loff_t end */
		end,
		/* int datasync */
		datasync);

	fsapi_linux_op_log_leave(ret, "filp=%p, start=%" PRId64 ", "
		"end=%" PRId64 ", datasync=%d",
		filp, PRAd64(start), PRAd64(end), datasync);

	return ret;
}

static struct dentry* fsapi_linux_dir_inode_op_lookup(
		struct inode *target_inode,
		struct dentry *dent,
		unsigned int flags)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		target_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		target_inode);

	int ret = 0;
	struct dentry *ret_dent = NULL;
	int err = 0;
	fsapi_node_attributes attributes;
	fsapi_node *child_node = NULL;
	struct inode *child_ino = NULL;

	fsapi_linux_op_log_enter(
		"target_inode=%p, "
		"dent=%" PRIdentry ", "
		"flags=0x%X",
		target_inode,
		PRAdentry(dent),
		flags);

	memset(&attributes, 0, sizeof(attributes));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATION_BLOCK_SIZE |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_DEVICE_NUMBER |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE;

	err = fsapi_node_lookup(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* const char *name */
		dent->d_name.name,
		/* size_t name_length */
		dent->d_name.len,
		/* fsapi_node **out_node */
		&child_node,
		/* fsapi_node_attributes *out_attributes */
		&attributes);
	if(err) {
		ret = -err;
		goto out;
	}
	else if(!child_node) {
		d_add(dent, NULL);
		ret = 0;
		ret_dent = NULL;
		goto out;
	}

	child_ino = new_inode(target_inode->i_sb);
	if(unlikely(!child_ino)) {
#if 0
		bforget(bh);
#endif
		sys_log_error("Failed to allocate inode for looked up fsapi "
			"node %p.", node);
		ret = -ENOMEM;
		goto out;
	}

	child_ino->i_private = child_node;

	fsapi_linux_attributes_to_inode(
		/* const fsapi_node_attributes *attributes */
		&attributes,
		/* struct inode *ino */
		child_ino,
		/* sys_bool fill_operations */
		SYS_TRUE);

	ret_dent = d_splice_alias(child_ino, dent);
out:
	fsapi_linux_op_log_leave(ret,
		"target_inode=%p, "
		"dent=%" PRIdentry ", "
		"flags=0x%X",
		target_inode,
		PRAdentry(dent),
		flags);

	return ret ? (struct dentry*) ERR_PTR(ret) : ret_dent;
}

static int fsapi_linux_dir_inode_op_create(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct inode *target_inode,
		struct dentry *dent,
		umode_t mode,
		bool excl)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		target_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		target_inode);

	int ret = 0;
	int err = 0;
	struct inode *child_ino = NULL;
	fsapi_node_attributes attributes;
	fsapi_node *child_node = NULL;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"target_inode=%p, "
		"dent=%" PRIdentry ", "
		"mode=0%" PRIo32 ", "
		"excl=%d",
		FSAPI_IF_LINUX_5_12(namespace,)
		target_inode,
		PRAdentry(dent),
		PRAo32(mode),
		excl);

	memset(&attributes, 0, sizeof(attributes));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	child_ino = new_inode(target_inode->i_sb);
	if(unlikely(!child_ino)) {
		sys_log_error("Failed to allocate inode for fsapi node that "
			"we are about to create.");
		ret = -ENOMEM;
		goto out;
	}

	child_ino->i_mode = mode;

	inode_init_owner(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		/* struct mnt_idmap *idmap */
		namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)) */
		/* struct inode *inode */
		child_ino,
		/* const struct inode *dir */
		target_inode,
		/* umode_t mode */
		mode);

	attributes.uid = child_ino->i_uid.val;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_UID;
	attributes.gid = child_ino->i_gid.val;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_GID;
	attributes.mode = child_ino->i_mode;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_MODE;

	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATION_BLOCK_SIZE |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_DEVICE_NUMBER |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE;

	err = fsapi_node_create(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* const char *name */
		dent->d_name.name,
		/* size_t name_length */
		dent->d_name.len,
		/* fsapi_node_attributes *attributes */
		&attributes,
		/* fsapi_node **out_node */
		&child_node);
	if(err == ENOSPC) {
		ret = -ENOSPC;
		goto out;
	}
	else if(err == EEXIST) {
		ret = -EEXIST;
		goto out;
	}
	else if(err) {
		ret = -err;
		goto out;
	}

	child_ino->i_private = child_node;

	fsapi_linux_attributes_to_inode(
		/* const fsapi_node_attributes *attributes */
		&attributes,
		/* struct inode *ino */
		child_ino,
		/* sys_bool fill_operations */
		SYS_TRUE);

	inode_inc_iversion(target_inode); /* needed? */
	d_instantiate(dent, child_ino);
out:
	if(ret) {
		if(child_ino) {
			iput(child_ino);
		}
	}

	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"target_inode=%p, "
		"dent=%" PRIdentry ", "
		"mode=0%" PRIo32 ", "
		"excl=%d",
		FSAPI_IF_LINUX_5_12(namespace,)
		target_inode,
		PRAdentry(dent),
		PRAo32(mode),
		excl);

	return ret;
}

static int fsapi_linux_dir_inode_op_link(
		struct dentry *source_dent,
		struct inode *target_dir_inode,
		struct dentry *target_dent)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		target_dir_inode->i_sb);

	fsapi_node *const target_dir_node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		target_dir_inode);

	int ret = 0;
	int err = 0;
	fsapi_node *source_node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		source_dent->d_inode);

	fsapi_linux_op_log_enter(
		"source_dent=%" PRIdentry ", "
		"target_dir_inode=%p, "
		"target_dent=%" PRIdentry,
		PRAdentry(source_dent),
		target_dir_inode,
		PRAdentry(target_dent));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	err = fsapi_node_hardlink(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		source_node,
		/* fsapi_node *link_parent */
		target_dir_node,
		/* const char *link_name */
		target_dent->d_name.name,
		/* size_t link_name_length */
		target_dent->d_name.len,
		/* fsapi_node_attributes *out_attributes */
		NULL);
	if(err) {
		ret = -err;
		goto out;
	}


	inc_nlink(source_dent->d_inode);
	ihold(source_dent->d_inode);

	if(vol) {
		/* Release the fsapi reference so that we don't need to refcount
		 * here. */
		err = fsapi_node_release(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node **node */
			&source_node,
			/* size_t release_count */
			1);
		if(err) {
			sys_log_perror(err, "Error while releasing hardlinked "
				"node %p",
				source_node);
			drop_nlink(source_dent->d_inode);
			iput(source_dent->d_inode);
			ret = -err;
			goto out;
		}
	}

	d_instantiate(target_dent, source_dent->d_inode);
out:
	fsapi_linux_op_log_leave(ret,
		"source_dent=%" PRIdentry ", "
		"target_dir_inode=%p, "
		"target_dent=%" PRIdentry,
		PRAdentry(source_dent),
		target_dir_inode,
		PRAdentry(target_dent));

#if 1
	return ret;
#else
	/* The link(2) manpage documents EPERM as the expected errno when
	 * attempting to hard link a directory. We could still send this request
	 * down to the fsapi volume but what's the point? */

	return -EPERM;
#endif
}

static int fsapi_linux_dir_inode_op_unlink(
		struct inode *parent_inode,
		struct dentry *dent)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		parent_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		parent_inode);

	int ret = 0;
	int err = 0;

	fsapi_linux_op_log_enter(
		"parent_inode=%p, "
		"dent=%" PRIdentry,
		parent_inode,
		PRAdentry(dent));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	err = fsapi_node_remove(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *parent_node */
		node,
		/* sys_bool is_directory */
		SYS_FALSE,
		/* const char *name */
		dent->d_name.name,
		/* size_t name_length */
		dent->d_name.len,
		/* fsapi_node **out_removed_node */
		NULL);
	if(err == ENOENT) {
		ret = -ENOENT;
		goto out;
	}
	else if(err == EISDIR) {
		/* The unlink(2) manpage documents EPERM as the expected POSIX
		 * errno value when attempting to unlink a directory but Linux
		 * in general instead returns EISDIR. Since we are in the Linux
		 * kernel we'd better behave like it. */
		ret = -EISDIR;
		goto out;
	}
	else if(err) {
		ret = -err;
		goto out;
	}

	if(dent->d_inode) {
		drop_nlink(dent->d_inode);
	}
out:
	fsapi_linux_op_log_leave(ret,
		"parent_inode=%p, "
		"dent=%" PRIdentry,
		parent_inode,
		PRAdentry(dent));

	return ret;
}

static int fsapi_linux_dir_inode_op_symlink(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct inode *parent_inode,
		struct dentry *dent,
		const char *target)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		parent_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		parent_inode);

	int ret = 0;
	int err = 0;
	struct inode *child_ino = NULL;
	fsapi_node_attributes attributes;
	fsapi_node *child_node = NULL;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"parent_inode=%p, "
		"dent=%" PRIdentry ", "
		"target=%p (->\"%s\")",
		FSAPI_IF_LINUX_5_12(namespace,)
		parent_inode,
		PRAdentry(dent),
		target, target ? target : "");

	memset(&attributes, 0, sizeof(attributes));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	child_ino = new_inode(parent_inode->i_sb);
	if(unlikely(!child_ino)) {
		sys_log_error("Failed to allocate inode for fsapi node that "
			"we are about to create.");
		ret = -ENOMEM;
		goto out;
	}

	child_ino->i_mode = S_IFLNK | 0666;

	inode_init_owner(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		/* struct mnt_idmap *idmap */
		namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)) */
		/* struct inode *inode */
		child_ino,
		/* const struct inode *dir */
		parent_inode,
		/* umode_t mode */
		child_ino->i_mode);

	attributes.uid = child_ino->i_uid.val;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_UID;
	attributes.gid = child_ino->i_gid.val;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_GID;
	attributes.mode = child_ino->i_mode;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_MODE;
	/* TODO: Const-to-non const cast should be eliminated with an API
	 * change. */
	attributes.symlink_target = (char*) target;
	attributes.symlink_target_length = strlen(target);

	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATION_BLOCK_SIZE |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_DEVICE_NUMBER |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_SYMLINK_TARGET;

	err = fsapi_node_create(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* const char *name */
		dent->d_name.name,
		/* size_t name_length */
		dent->d_name.len,
		/* fsapi_node_attributes *attributes */
		&attributes,
		/* fsapi_node **out_created_node */
		&child_node);
	if(err == ENOSPC) {
		ret = -ENOSPC;
		goto out;
	}
	else if(err == EEXIST) {
		ret = -EEXIST;
		goto out;
	}
	else if(err) {
		ret = -err;
		goto out;
	}

	child_ino->i_private = child_node;

	fsapi_linux_attributes_to_inode(
		/* const fsapi_node_attributes *attributes */
		&attributes,
		/* struct inode *ino */
		child_ino,
		/* sys_bool fill_operations */
		SYS_TRUE);

	inode_inc_iversion(parent_inode); /* needed? */
	d_instantiate(dent, child_ino);
out:
	if(ret) {
		if(child_ino) {
			iput(child_ino);
		}
	}

	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"parent_inode=%p, "
		"dent=%" PRIdentry ", "
		"target=%p (->\"%s\")",
		FSAPI_IF_LINUX_5_12(namespace,)
		parent_inode,
		PRAdentry(dent),
		target, target ? target : "");

	return ret;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,15,0))
static struct dentry* fsapi_linux_dir_inode_op_mkdir(
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,15,0)) */
static int fsapi_linux_dir_inode_op_mkdir(
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,15,0)) */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct inode *parent_inode,
		struct dentry *dent,
		umode_t mode)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		parent_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		parent_inode);

	int ret = 0;
	int err = 0;
	struct inode *child_ino = NULL;
	fsapi_node_attributes attributes;
	fsapi_node *child_node = NULL;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"parent_inode=%p, "
		"dent=%" PRIdentry ", "
		"mode=0%" PRIo32,
		FSAPI_IF_LINUX_5_12(namespace,)
		parent_inode,
		PRAdentry(dent),
		PRAo32(mode));

	memset(&attributes, 0, sizeof(attributes));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	child_ino = new_inode(parent_inode->i_sb);
	if(unlikely(!child_ino)) {
		sys_log_error("Failed to allocate inode for fsapi node that "
			"we are about to create.");
		ret = -ENOMEM;
		goto out;
	}

	child_ino->i_mode = (mode & ~S_IFMT) | S_IFDIR;

	inode_init_owner(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		/* struct mnt_idmap *idmap */
		namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)) */
		/* struct inode *inode */
		child_ino,
		/* const struct inode *dir */
		parent_inode,
		/* umode_t mode */
		mode);

	attributes.is_directory = SYS_TRUE;
	attributes.uid = child_ino->i_uid.val;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_UID;
	attributes.gid = child_ino->i_gid.val;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_GID;
	attributes.mode = (child_ino->i_mode & ~S_IFMT) | S_IFDIR;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_MODE;

	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATION_BLOCK_SIZE |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_DEVICE_NUMBER |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE;

	err = fsapi_node_create(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* const char *name */
		dent->d_name.name,
		/* size_t name_length */
		dent->d_name.len,
		/* fsapi_node_attributes *attributes */
		&attributes,
		/* fsapi_node **out_created_node */
		&child_node);
	if(err == ENOSPC) {
		ret = -ENOSPC;
		goto out;
	}
	else if(err == EEXIST) {
		ret = -EEXIST;
		goto out;
	}
	else if(err) {
		ret = -err;
		goto out;
	}

	child_ino->i_private = child_node;

	fsapi_linux_attributes_to_inode(
		/* const fsapi_node_attributes *attributes */
		&attributes,
		/* struct inode *ino */
		child_ino,
		/* sys_bool fill_operations */
		SYS_TRUE);

	inode_inc_iversion(parent_inode); /* needed? */
	d_instantiate(dent, child_ino);
out:
	if(ret) {
		if(child_ino) {
			iput(child_ino);
		}
	}

	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"parent_inode=%p, "
		"dent=%" PRIdentry ", "
		"mode=0%" PRIo32,
		FSAPI_IF_LINUX_5_12(namespace,)
		parent_inode,
		PRAdentry(dent),
		PRAo32(mode));

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,15,0))
	/* Only return non-NULL if we instantiated a new dirent. When we reuse
	 * the supplied dirent we must return NULL. */
	return ret ? ERR_PTR(ret) : NULL;
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,15,0)) */
	return ret;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,15,0)) */
}

static int fsapi_linux_dir_inode_op_rmdir(
		struct inode *parent_inode,
		struct dentry *dent)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		parent_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		parent_inode);

	int ret = 0;
	int err = 0;

	fsapi_linux_op_log_enter(
		"parent_inode=%p, "
		"dent=%" PRIdentry,
		parent_inode,
		PRAdentry(dent));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	err = fsapi_node_remove(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *parent_node */
		node,
		/* sys_bool is_directory */
		SYS_TRUE,
		/* const char *name */
		dent->d_name.name,
		/* size_t name_length */
		dent->d_name.len,
		/* fsapi_node **out_removed_node */
		NULL);
	if(err == ENOENT) {
		ret = -ENOENT;
		goto out;
	}
	else if(err == ENOTDIR) {
		ret = -ENOTDIR;
		goto out;
	}
	else if(err == ENOTEMPTY) {
		ret = -ENOTEMPTY;
		goto out;
	}
	else if(err) {
		ret = -err;
		goto out;
	}

	if(dent->d_inode) {
		drop_nlink(dent->d_inode);
	}
out:
	fsapi_linux_op_log_leave(ret,
		"parent_inode=%p, "
		"dent=%" PRIdentry,
		parent_inode,
		PRAdentry(dent));

	return ret;
}

static int fsapi_linux_dir_inode_op_mknod(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct inode *parent_inode,
		struct dentry *dent,
		umode_t mode,
		dev_t rdev)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		parent_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		parent_inode);

	int ret = 0;
	int err = 0;
	struct inode *child_ino = NULL;
	fsapi_node_attributes attributes;
	fsapi_node *child_node = NULL;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"parent_inode=%p, "
		"dent=%" PRIdentry ", "
		"mode=0%" PRIo32 ", "
		"rdev=%" PRIX64,
		FSAPI_IF_LINUX_5_12(namespace,)
		parent_inode,
		PRAdentry(dent),
		PRAo32(mode),
		PRAX64(rdev));

	memset(&attributes, 0, sizeof(attributes));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	child_ino = new_inode(parent_inode->i_sb);
	if(unlikely(!child_ino)) {
		sys_log_error("Failed to allocate inode for fsapi node that "
			"we are about to create.");
		ret = -ENOMEM;
		goto out;
	}

	child_ino->i_mode = mode;

	inode_init_owner(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		/* struct mnt_idmap *idmap */
		namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)) */
		/* struct inode *inode */
		child_ino,
		/* const struct inode *dir */
		parent_inode,
		/* umode_t mode */
		mode);

	attributes.uid = child_ino->i_uid.val;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_UID;
	attributes.gid = child_ino->i_gid.val;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_GID;
	attributes.mode = child_ino->i_mode;
	attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_MODE;
#if 0
	if(S_ISCHR(child_ino->i_mode) || S_ISREG(child_ino->i_mode)) {
		attributes.device_number.major = MAJOR(rdev);
		attributes.device_number.minor = MINOR(rdev);
		attributes.valid |= FSAPI_NODE_ATTRIBUTE_TYPE_DEVICE_NUMBER;
	}
#endif

	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATION_BLOCK_SIZE |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_DEVICE_NUMBER |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE;

	err = fsapi_node_create(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* const char *name */
		dent->d_name.name,
		/* size_t name_length */
		dent->d_name.len,
		/* fsapi_node_attributes *attributes */
		&attributes,
		/* fsapi_node **out_node */
		&child_node);
	if(err == ENOSPC) {
		ret = -ENOSPC;
		goto out;
	}
	else if(err == EEXIST) {
		ret = -EEXIST;
		goto out;
	}
	else if(err) {
		ret = -err;
		goto out;
	}

	child_ino->i_private = child_node;

	fsapi_linux_attributes_to_inode(
		/* const fsapi_node_attributes *attributes */
		&attributes,
		/* struct inode *ino */
		child_ino,
		/* sys_bool fill_operations */
		SYS_TRUE);

	inode_inc_iversion(parent_inode); /* needed? */
	d_instantiate(dent, child_ino);
out:
	if(ret) {
		if(child_ino) {
			iput(child_ino);
		}
	}

	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"parent_inode=%p, "
		"dent=%" PRIdentry ", "
		"mode=0%" PRIo32 ", "
		"rdev=%" PRIX64,
		FSAPI_IF_LINUX_5_12(namespace,)
		parent_inode,
		PRAdentry(dent),
		PRAo32(mode),
		PRAX64(rdev));

	return ret;
}

static int fsapi_linux_dir_inode_op_rename(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct inode *source_dir_inode,
		struct dentry *dent,
		struct inode *target_dir_inode,
		struct dentry *target_dent
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))
		, unsigned int flags
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)) */
		)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		source_dir_inode->i_sb);

	fsapi_node *const source_dir_node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		source_dir_inode);
	fsapi_node *const target_dir_node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		target_dir_inode);

	int ret = 0;
	int err = 0;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"source_dir_inode=%p, "
		"dent=%" PRIdentry ", "
		"target_dir_inode=%p, "
		"target_dent=%" PRIdentry
		FSAPI_IF_LINUX_4_9(", flags=0x%X"),
		FSAPI_IF_LINUX_5_12(namespace,)
		source_dir_inode,
		PRAdentry(dent),
		target_dir_inode,
		PRAdentry(target_dent)
		FSAPI_IF_LINUX_4_9(, flags));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	err = fsapi_node_rename(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *source_dir_node */
		source_dir_node,
		/* const char *source_name */
		dent->d_name.name,
		/* size_t source_name_length */
		dent->d_name.len,
		/* fsapi_node *target_dir_node */
		target_dir_node,
		/* const char *target_name */
		target_dent->d_name.name,
		/* size_t target_name_length */
		target_dent->d_name.len,
		/* fsapi_rename_flags flags */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))
		((flags & RENAME_EXCHANGE) ? FSAPI_RENAME_FLAG_EXCHANGE : 0) |
		((flags & RENAME_NOREPLACE) ? FSAPI_RENAME_FLAG_NOREPLACE : 0) |
		((flags & RENAME_WHITEOUT) ? FSAPI_RENAME_FLAG_WHITEOUT : 0) |
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)) */
		0);
	if(err == ENOENT) {
		ret = -ENOSPC;
		goto out;
	}
	else if(err == EEXIST) {
		ret = -EEXIST;
		goto out;
	}
	else if(err == ENOTDIR) {
		ret = -ENOTDIR;
		goto out;
	}
	else if(err == EISDIR) {
		ret = -EISDIR;
		goto out;
	}
	else if(err == ENOTEMPTY) {
		ret = -ENOTEMPTY;
		goto out;
	}
	else if(err == EINVAL) {
		ret = -EINVAL;
		goto out;
	}
	else if(err) {
		ret = -err;
		goto out;
	}

	inode_inc_iversion(source_dir_inode);
	if(source_dir_inode != target_dir_inode) {
		inode_inc_iversion(target_dir_inode);
	}

	if(target_dent->d_inode) {
		drop_nlink(target_dent->d_inode);
	}
out:
	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"source_dir_inode=%p, "
		"dent=%" PRIdentry ", "
		"target_dir_inode=%p, "
		"target_dent=%" PRIdentry
		FSAPI_IF_LINUX_4_9(", flags=0x%X"),
		FSAPI_IF_LINUX_5_12(namespace,)
		source_dir_inode,
		PRAdentry(dent),
		target_dir_inode,
		PRAdentry(target_dent)
		FSAPI_IF_LINUX_4_9(, flags));

	return ret;
}

static int fsapi_linux_dir_inode_op_setattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *entry,
		struct iattr *attr)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		entry->d_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		entry->d_inode);

	int ret = 0;

	fsapi_linux_op_log_enter(FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"entry=%p, attr=%p",
		FSAPI_IF_LINUX_5_12(namespace,) entry, attr);

	ret = fsapi_linux_setattr_common(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* struct inode *inode */
		entry->d_inode,
		/* struct iattr *attr */
		attr);

	fsapi_linux_op_log_leave(ret, FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"entry=%p, attr=%p",
		FSAPI_IF_LINUX_5_12(namespace,) entry, attr);

	return ret;
}

static int fsapi_linux_dir_inode_op_getattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
		const struct path *path,
		struct kstat *stat,
		u32 request_mask,
		unsigned int query_flags
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)) */
		struct vfsmount *mnt,
		struct dentry *dentry,
		struct kstat *stat
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)) ... */
		)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		FSAPI_IF_LINUX_4_11(path->)dentry->d_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		FSAPI_IF_LINUX_4_11(path->)dentry->d_inode);

	int ret = 0;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		FSAPI_IF_LINUX_4_11("path=%p, ")
		FSAPI_NOT_LINUX_4_11("mnt=%p, ")
		FSAPI_NOT_LINUX_4_11("dentry=%" PRIdentry ", ")
		"stat=%p"
		FSAPI_IF_LINUX_4_11(", request_mask=0x%" PRIX32)
		FSAPI_IF_LINUX_4_11(", query_flags=%X"),
		FSAPI_IF_LINUX_5_12(namespace,)
		FSAPI_IF_LINUX_4_11(path,)
		FSAPI_NOT_LINUX_4_11(mnt,)
		FSAPI_NOT_LINUX_4_11(PRAdentry(dentry),)
		stat
		FSAPI_IF_LINUX_4_11(, PRAX32(request_mask))
		FSAPI_IF_LINUX_4_11(, query_flags));

	ret = fsapi_linux_getattr_common(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* int request_mask */
		FSAPI_IF_LINUX_4_11(request_mask)
		FSAPI_NOT_LINUX_4_11(STATX_BASIC_STATS),
		/* struct kstat *stat */
		stat);

	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		FSAPI_IF_LINUX_4_11("path=%p, ")
		FSAPI_NOT_LINUX_4_11("mnt=%p, ")
		FSAPI_NOT_LINUX_4_11("dentry=%" PRIdentry ", ")
		"stat=%p"
		FSAPI_IF_LINUX_4_11(", request_mask=0x%" PRIX32)
		FSAPI_IF_LINUX_4_11(", query_flags=%X"),
		FSAPI_IF_LINUX_5_12(namespace,)
		FSAPI_IF_LINUX_4_11(path,)
		FSAPI_NOT_LINUX_4_11(mnt,)
		FSAPI_NOT_LINUX_4_11(PRAdentry(dentry),)
		stat
		FSAPI_IF_LINUX_4_11(, PRAX32(request_mask))
		FSAPI_IF_LINUX_4_11(, query_flags));

	return ret;
}

static ssize_t fsapi_linux_dir_inode_op_listxattr(
		struct dentry *dentry,
		char *list,
		size_t size)
{
	int ret = 0;

	fsapi_linux_op_log_enter(
		"dentry=%" PRIdentry ", "
		"list=%p, "
		"size=%" PRIuz,
		PRAdentry(dentry),
		list,
		PRAuz(size));

	ret = fsapi_linux_listxattr_common(
		/* struct dentry *dentry */
		dentry,
		/* char *list */
		list,
		/* size_t size */
		size);

	fsapi_linux_op_log_leave(ret,
		"dentry=%" PRIdentry ", "
		"list=%p, "
		"size=%" PRIuz,
		PRAdentry(dentry),
		list,
		PRAuz(size));

	return ret;
}

static int fsapi_linux_dir_inode_op_fiemap(
		struct inode *inode,
		struct fiemap_extent_info *fieinfo,
		u64 start,
		u64 len)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	fsapi_linux_op_log_enter("inode=%p, fieinfo=%p, "
		"start=%" PRIu64 ", len=%" PRIu64,
		inode, fieinfo, PRAu64(start), PRAu64(len));

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "inode=%p, fieinfo=%p, "
		"start=%" PRIu64 ", len=%" PRIu64,
		inode, fieinfo, PRAu64(start), PRAu64(len));

	return -EIO;
}

static int fsapi_linux_dir_inode_op_update_time(
		struct inode *inode,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0))
		enum fs_update_time type,
		unsigned
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0)) */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0))
		struct timespec64 *time,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)) */
		struct timespec *time,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) ... */
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) ... */
		int flags)
{
	int ret = 0;

	fsapi_linux_op_log_enter(
		"inode=%p, "
		FSAPI_NOT_LINUX_6_6("time=%p, ")
		"flags=0x%X",
		inode,
		FSAPI_NOT_LINUX_6_6(time,)
		flags);

	ret = fsapi_linux_update_time_common(
		/* struct inode *inode */
		inode,
		/* enum fs_update_time type */
		FSAPI_IF_LINUX_7_0(type,)
		/* struct timespec[64] *time */
		FSAPI_NOT_LINUX_6_6(time,)
		/* int flags */
		flags);

	fsapi_linux_op_log_leave(ret,
		"inode=%p, "
		FSAPI_NOT_LINUX_6_6("time=%p, ")
		"flags=0x%X",
		inode,
		FSAPI_NOT_LINUX_6_6(time,)
		flags);

	return ret;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0))
static int fsapi_linux_dir_inode_op_fileattr_set(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *mnt_userns,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0)) */
		struct user_namespace *mnt_userns,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *dentry,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		struct file_kattr *fa)
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)) */
		struct fileattr *fa)
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		dentry->d_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		dentry->d_inode);

	fsapi_linux_op_log_enter(
		"mnt_userns=%p, "
		"dentry=%" PRIdentry ", "
		"fa=%p",
		mnt_userns,
		PRAdentry(dentry),
		fa);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO,
		"mnt_userns=%p, "
		"dentry=%" PRIdentry ", "
		"fa=%p",
		mnt_userns,
		PRAdentry(dentry),
		fa);

	return -EIO;
}

static int fsapi_linux_dir_inode_op_fileattr_get(
		struct dentry *dentry,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		struct file_kattr *fa)
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)) */
		struct fileattr *fa)
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		dentry->d_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		dentry->d_inode);

	fsapi_linux_op_log_enter(
		"dentry=%" PRIdentry ", "
		"fa=%p",
		PRAdentry(dentry),
		fa);

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO,
		"dentry=%" PRIdentry ", "
		"fa=%p",
		PRAdentry(dentry),
		fa);

	return -EIO;
}
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)) */

static void fsapi_linux_symlink_inode_cleanup_link(void *link)
{
	sys_free(strlen((char*) link) + 1, &link);
}

static const char* fsapi_linux_symlink_inode_op_get_link(
		struct dentry *dentry,
		struct inode *inode,
		struct delayed_call *callback)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	int ret = 0;
	int err = 0;
	fsapi_node_attributes attributes;

	fsapi_linux_op_log_enter(
		"dentry=%" PRIdentry ", "
		"inode=%p, "
		"callback=%p",
		PRAdentry(dentry),
		inode,
		callback);

	memset(&attributes, 0, sizeof(attributes));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	attributes.requested |= FSAPI_NODE_ATTRIBUTE_TYPE_SYMLINK_TARGET;

	/* TODO: Sleeping here can lead to a WARNING in the kernel if there is
	 * contention becase we are in an RCU read-side critical section.
	 * Ideally we should have read the link into memory on lookup and just
	 * return a pointer to it here with no need for locking, even though
	 * that might be slightly wasteful. */
	err = fsapi_node_get_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* fsapi_node_attributes *out_attributes */
		&attributes);
	if(err) {
		ret = -err;
		goto out;
	}
	else if(!(attributes.valid & FSAPI_NODE_ATTRIBUTE_TYPE_SYMLINK_TARGET))
	{
		ret = -EINVAL;
		goto out;
	}
	else if(!attributes.symlink_target) {
		sys_log_error("Missing symlink target string in returned "
			"attributes.");
		ret = -EIO;
		goto out;
	}

	/* Can be used to clean up the link data when no longer used. */
	callback->fn = fsapi_linux_symlink_inode_cleanup_link;
	callback->arg = attributes.symlink_target;
out:
	fsapi_linux_op_log_leave(ret,
		"dentry=%" PRIdentry ", "
		"inode=%p, "
		"callback=%p",
		PRAdentry(dentry),
		inode,
		callback);

	return ret ? ERR_PTR(ret) : attributes.symlink_target;
}

static int fsapi_linux_symlink_inode_op_setattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *entry,
		struct iattr *attr)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		entry->d_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		entry->d_inode);

	int ret = 0;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"entry=%p, "
		"attr=%p",
		FSAPI_IF_LINUX_5_12(namespace,)
		entry,
		attr);

	ret = fsapi_linux_setattr_common(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* struct inode *inode */
		entry->d_inode,
		/* struct iattr *attr */
		attr);

	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"entry=%p, "
		"attr=%p",
		FSAPI_IF_LINUX_5_12(namespace,)
		entry,
		attr);

	return ret;
}

static int fsapi_linux_symlink_inode_op_getattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
		const struct path *path,
		struct kstat *stat,
		u32 request_mask,
		unsigned int query_flags
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)) */
		struct vfsmount *mnt,
		struct dentry *dentry,
		struct kstat *stat
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)) ... */
		)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		FSAPI_IF_LINUX_4_11(path->)dentry->d_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		FSAPI_IF_LINUX_4_11(path->)dentry->d_inode);

	int ret = 0;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		FSAPI_IF_LINUX_4_11("path=%p, ")
		FSAPI_NOT_LINUX_4_11("mnt=%p, ")
		FSAPI_NOT_LINUX_4_11("dentry=%" PRIdentry ", ")
		"stat=%p"
		FSAPI_IF_LINUX_4_11(", request_mask=0x%" PRIX32)
		FSAPI_IF_LINUX_4_11(", query_flags=%X"),
		FSAPI_IF_LINUX_5_12(namespace,)
		FSAPI_IF_LINUX_4_11(path,)
		FSAPI_NOT_LINUX_4_11(mnt,)
		FSAPI_NOT_LINUX_4_11(PRAdentry(dentry),)
		stat
		FSAPI_IF_LINUX_4_11(, PRAX32(request_mask))
		FSAPI_IF_LINUX_4_11(, query_flags));

	ret = fsapi_linux_getattr_common(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* int request_mask */
		FSAPI_IF_LINUX_4_11(request_mask)
		FSAPI_NOT_LINUX_4_11(STATX_BASIC_STATS),
		/* struct kstat *stat */
		stat);

	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		FSAPI_IF_LINUX_4_11("path=%p, ")
		FSAPI_NOT_LINUX_4_11("mnt=%p, ")
		FSAPI_NOT_LINUX_4_11("dentry=%" PRIdentry ", ")
		"stat=%p"
		FSAPI_IF_LINUX_4_11(", request_mask=0x%" PRIX32)
		FSAPI_IF_LINUX_4_11(", query_flags=%X"),
		FSAPI_IF_LINUX_5_12(namespace,)
		FSAPI_IF_LINUX_4_11(path,)
		FSAPI_NOT_LINUX_4_11(mnt,)
		FSAPI_NOT_LINUX_4_11(PRAdentry(dentry),)
		stat
		FSAPI_IF_LINUX_4_11(, PRAX32(request_mask))
		FSAPI_IF_LINUX_4_11(, query_flags));

	return ret;
}

static ssize_t fsapi_linux_symlink_inode_op_listxattr(
		struct dentry *dentry,
		char *list,
		size_t size)
{
	int ret = 0;

	fsapi_linux_op_log_enter(
		"dentry=%" PRIdentry ", "
		"list=%p, "
		"size=%" PRIuz,
		PRAdentry(dentry),
		list,
		PRAuz(size));

	ret = fsapi_linux_listxattr_common(
		/* struct dentry *dentry */
		dentry,
		/* char *list */
		list,
		/* size_t size */
		size);

	fsapi_linux_op_log_leave(ret,
		"dentry=%" PRIdentry ", "
		"list=%p, "
		"size=%" PRIuz,
		PRAdentry(dentry),
		list,
		PRAuz(size));

	return ret;
}

static int fsapi_linux_symlink_inode_op_fiemap(
		struct inode *inode,
		struct fiemap_extent_info *fieinfo,
		u64 start,
		u64 len)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	fsapi_linux_op_log_enter("inode=%p, fieinfo=%p, "
		"start=%" PRIu64 ", len=%" PRIu64,
		inode, fieinfo, PRAu64(start), PRAu64(len));

	(void) vol;
	(void) node;

	fsapi_linux_op_log_leave(-EIO, "inode=%p, fieinfo=%p, "
		"start=%" PRIu64 ", len=%" PRIu64,
		inode, fieinfo, PRAu64(start), PRAu64(len));

	return -EIO;
}

static int fsapi_linux_symlink_inode_op_update_time(
		struct inode *inode,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0))
		enum fs_update_time type,
		unsigned
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0)) */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0))
		struct timespec64 *time,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)) */
		struct timespec *time,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) ... */
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) ... */
		int flags)
{
	int ret = 0;

	fsapi_linux_op_log_enter(
		"inode=%p, "
		FSAPI_NOT_LINUX_6_6("time=%p, ")
		"flags=0x%X",
		inode,
		FSAPI_NOT_LINUX_6_6(time,)
		flags);

	ret = fsapi_linux_update_time_common(
		/* struct inode *inode */
		inode,
		/* enum fs_update_time type */
		FSAPI_IF_LINUX_7_0(type,)
		/* struct timespec[64] *time */
		FSAPI_NOT_LINUX_6_6(time,)
		/* int flags */
		flags);

	fsapi_linux_op_log_leave(ret,
		"inode=%p, "
		FSAPI_NOT_LINUX_6_6("time=%p, ")
		"flags=0x%X",
		inode,
		FSAPI_NOT_LINUX_6_6(time,)
		flags);

	return ret;
}

static int fsapi_linux_special_inode_op_setattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *entry,
		struct iattr *attr)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		entry->d_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		entry->d_inode);

	int ret = 0;

	fsapi_linux_op_log_enter(FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"entry=%p, attr=%p",
		FSAPI_IF_LINUX_5_12(namespace,) entry, attr);

	ret = fsapi_linux_setattr_common(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* struct inode *inode */
		entry->d_inode,
		/* struct iattr *attr */
		attr);

	fsapi_linux_op_log_leave(ret, FSAPI_IF_LINUX_5_12("namespace=%p, ")
		"entry=%p, attr=%p",
		FSAPI_IF_LINUX_5_12(namespace,) entry, attr);

	return ret;
}

static int fsapi_linux_special_inode_op_getattr(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *namespace,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *namespace,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
		const struct path *path,
		struct kstat *stat,
		u32 request_mask,
		unsigned int query_flags
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)) */
		struct vfsmount *mnt,
		struct dentry *dentry,
		struct kstat *stat
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)) ... */
		)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		FSAPI_IF_LINUX_4_11(path->)dentry->d_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		FSAPI_IF_LINUX_4_11(path->)dentry->d_inode);

	int ret = 0;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		FSAPI_IF_LINUX_4_11("path=%p, ")
		FSAPI_NOT_LINUX_4_11("mnt=%p, ")
		FSAPI_NOT_LINUX_4_11("dentry=%" PRIdentry ", ")
		"stat=%p"
		FSAPI_IF_LINUX_4_11(", request_mask=0x%" PRIX32)
		FSAPI_IF_LINUX_4_11(", query_flags=%X"),
		FSAPI_IF_LINUX_5_12(namespace,)
		FSAPI_IF_LINUX_4_11(path,)
		FSAPI_NOT_LINUX_4_11(mnt,)
		FSAPI_NOT_LINUX_4_11(PRAdentry(dentry),)
		stat
		FSAPI_IF_LINUX_4_11(, PRAX32(request_mask))
		FSAPI_IF_LINUX_4_11(, query_flags));

	ret = fsapi_linux_getattr_common(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* int request_mask */
		FSAPI_IF_LINUX_4_11(request_mask)
		FSAPI_NOT_LINUX_4_11(STATX_BASIC_STATS),
		/* struct kstat *stat */
		stat);

	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_5_12("namespace=%p, ")
		FSAPI_IF_LINUX_4_11("path=%p, ")
		FSAPI_NOT_LINUX_4_11("mnt=%p, ")
		FSAPI_NOT_LINUX_4_11("dentry=%" PRIdentry ", ")
		"stat=%p"
		FSAPI_IF_LINUX_4_11(", request_mask=0x%" PRIX32)
		FSAPI_IF_LINUX_4_11(", query_flags=%X"),
		FSAPI_IF_LINUX_5_12(namespace,)
		FSAPI_IF_LINUX_4_11(path,)
		FSAPI_NOT_LINUX_4_11(mnt,)
		FSAPI_NOT_LINUX_4_11(PRAdentry(dentry),)
		stat
		FSAPI_IF_LINUX_4_11(, PRAX32(request_mask))
		FSAPI_IF_LINUX_4_11(, query_flags));

	return ret;
}

static ssize_t fsapi_linux_special_inode_op_listxattr(
		struct dentry *dentry,
		char *list,
		size_t size)
{
	int ret = 0;

	fsapi_linux_op_log_enter(
		"dentry=%" PRIdentry ", "
		"list=%p, "
		"size=%" PRIuz,
		PRAdentry(dentry),
		list,
		PRAuz(size));

	ret = fsapi_linux_listxattr_common(
		/* struct dentry *dentry */
		dentry,
		/* char *list */
		list,
		/* size_t size */
		size);

	fsapi_linux_op_log_leave(ret,
		"dentry=%" PRIdentry ", "
		"list=%p, "
		"size=%" PRIuz,
		PRAdentry(dentry),
		list,
		PRAuz(size));

	return ret;
}

static int fsapi_linux_special_inode_op_update_time(
		struct inode *inode,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0))
		enum fs_update_time type,
		unsigned
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0)) */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0))
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0))
		struct timespec64 *time,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)) */
		struct timespec *time,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) ... */
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)) ... */
		int flags)
{
	int ret = 0;

	fsapi_linux_op_log_enter(
		"inode=%p, "
		FSAPI_NOT_LINUX_6_6("time=%p, ")
		"flags=0x%X",
		inode,
		FSAPI_NOT_LINUX_6_6(time,)
		flags);

	ret = fsapi_linux_update_time_common(
		/* struct inode *inode */
		inode,
		/* enum fs_update_time type */
		FSAPI_IF_LINUX_7_0(type,)
		/* struct timespec[64] *time */
		FSAPI_NOT_LINUX_6_6(time,)
		/* int flags */
		flags);

	fsapi_linux_op_log_leave(ret,
		"inode=%p, "
		FSAPI_NOT_LINUX_6_6("time=%p, ")
		"flags=0x%X",
		inode,
		FSAPI_NOT_LINUX_6_6(time,)
		flags);

	return ret;
}

typedef struct {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
	struct folio *folio;
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
	struct page *page;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	struct readahead_control *rac;
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
	struct address_space *mapping;
	struct list_head *pages;
	unsigned cur_page;
	unsigned nr_pages;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */
	struct inode *inode;
	size_t block_size_shift;
	size_t block_size;
	size_t block_size_mask;
	size_t block_index;
	struct buffer_head *cur_buffer;
	struct buffer_head *buffer_head;
	struct buffer_head *valid_buffers[MAX_BUF_PER_PAGE];
	size_t num_valid_buffers;
	/**
	 * The number of bytes read in the current unit (page or folio).
	 */
	size_t bytes_read_in_unit;
	/**
	 * The total number of remaining bytes in the read operation (for all
	 * pages/folios).
	 */
	size_t remaining_size;
	sys_bool has_holes;
} fsapi_linux_address_space_read_context;

static void fsapi_linux_address_space_read_submit_io(
		fsapi_linux_address_space_read_context *const context);

static int fsapi_linux_address_space_read_handle_io(
		void *const _context,
		sys_device *const dev,
		const u64 offset,
		const size_t size)
{
	fsapi_linux_address_space_read_context *const context =
		(fsapi_linux_address_space_read_context*) _context;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
	struct folio *const folio = context->folio;
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
	struct page *const page = context->page;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */

	int err = 0;

	u64 physical_block = 0;
	size_t remaining_size =
		(size + ~context->block_size_mask) & context->block_size_mask;

	sys_log_debug("Entering %s(context=%p, dev=%p, "
		"offset=%" PRIu64 ", size=%" PRIuz ")...",
		__FUNCTION__,
		_context, dev, PRAu64(offset), PRAuz(size));

	if(offset & ~context->block_size_mask) {
		sys_log_error("Unexpected I/O offset (not block aligned): "
			"%" PRIu64 " (block size: %" PRIuz ")",
			PRAu64(offset), PRAuz(context->block_size));
		err = EINVAL;
		goto out;
	}
	else if(size > context->remaining_size) {
		sys_log_error("Got more data than requested: %" PRIuz " > "
			"%" PRIuz,
			PRAuz(size), PRAuz(context->remaining_size));
		err = EIO;
		goto out;
	}

	physical_block = offset >> context->block_size_shift;

	if(!context->buffer_head) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
		if(!folio_get_private(
			/* struct folio *folio */
			folio))
		{
			sys_log_debug("folio_size: %" PRIuz,
				PRAuz(folio_size(folio)));

			context->buffer_head = create_empty_buffers(
				/* struct folio *folio */
				folio,
				/* unsigned long blocksize */
				context->block_size,
				/* unsigned long b_state */
				0);
			sys_log_debug("create_empty_buffers(folio=%p, "
				"blocksize=%" PRIuz ", b_state=0): %p",
				folio, PRAuz(context->block_size),
				context->buffer_head);
		}
		else {
			context->buffer_head = folio_buffers(
				/* struct folio *folio */
				folio);

			sys_log_debug("folio_buffers(%p): %p",
				folio, context->buffer_head);
		}
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
		if(!page_has_buffers(
			/* struct page *page */
			page))
		{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,7,0))
			context->buffer_head =
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,7,0)) */
			create_empty_buffers(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,7,0))
				/* struct folio *folio */
				page_folio(page),
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,7,0)) */
				/* struct page *page */
				page,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,7,0)) ... */
				/* unsigned long blocksize */
				context->block_size,
				/* unsigned long b_state */
				0);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,7,0))
			context->buffer_head =
				page_buffers(
					/* struct page *page */
					page);
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,7,0)) */

			sys_log_debug("create_empty_buffers(page=%p, "
				"blocksize=%" PRIuz ", b_state=0): %p",
				page, PRAuz(context->block_size),
				context->buffer_head);
		}
		else {
			context->buffer_head =
				page_buffers(
					/* struct page *page */
					page);
		}
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */

		if(!context->buffer_head) {
			sys_log_error("No buffer head: Ending read with "
				"ENOMEM.");

			err = ENOMEM;
			goto out;
		}

		sys_log_debug("got buffer head: %p", context->buffer_head);

		if(!context->cur_buffer) {
			context->cur_buffer = context->buffer_head;
		}
	}
	else if(context->cur_buffer == context->buffer_head) {
		sys_log_critical("Unexpected: Got data beyond the size of the "
			"page.");
		err = EIO;
		goto out;
	}

	do {
		if(!dev) {
			/* This is a hole, indicated by 'dev' being NULL. */
			sys_log_debug("    Processing buffer %" PRIuz " (%p) "
				"with %" PRIuz " byte hole.",
				PRAuz(context->block_index),
				context->cur_buffer, PRAuz(size));

			context->cur_buffer->b_blocknr = (sector_t) -1;
			clear_buffer_mapped(
				/* struct buffer_head *bh */
				context->cur_buffer);

			if(!buffer_uptodate(context->cur_buffer)) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
				zero_user_segment(
#else /* (LINUX_VERSION_CODE <= KERNEL_VERSION(6,17,0)) */
				zero_user(
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
					/* struct page *page */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
					folio_page(
						/* struct folio *folio */
						folio,
						/* size_t n */
						context->block_index /
						MAX_BUF_PER_PAGE),
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
					page,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */
					/* unsigned start */
					context->block_index *
					context->block_size,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
					/* unsigned end */
#else /* (LINUX_VERSION_CODE <= KERNEL_VERSION(6,17,0)) */
					/* unsigned size */
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
					(context->block_index + 1) *
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) */
					context->block_size);

				set_buffer_uptodate(
					/* struct buffer_head *bh */
					context->cur_buffer);
			}

			context->has_holes = SYS_TRUE;
		}
		else {
			sys_log_debug("    Filling buffer %" PRIuz " (%p) from "
				"block %" PRIu64 ".",
				PRAuz(context->block_index),
				context->cur_buffer, PRAu64(physical_block));

			context->cur_buffer->b_bdev =
				context->inode->i_sb->s_bdev;

			if(!buffer_mapped(context->cur_buffer)) {
				context->cur_buffer->b_blocknr = physical_block;
				set_buffer_mapped(
					/* struct buffer_head *bh */
					context->cur_buffer);
			}
			if(!buffer_uptodate(context->cur_buffer)) {
				if(context->num_valid_buffers ==
					sizeof(context->valid_buffers) /
					sizeof(context->valid_buffers[0]))
				{
					fsapi_linux_address_space_read_submit_io
					(
						/* fsapi_linux_address_space_
						 * read_context *context */
						context);
					context->num_valid_buffers = 0;
				}

				context->valid_buffers[
					context->num_valid_buffers++] =
					context->cur_buffer;
			}
		}

		++physical_block;
		++context->block_index;
		remaining_size -= context->block_size;
	} while((context->cur_buffer = context->cur_buffer->b_this_page) !=
		context->buffer_head && remaining_size);

	sys_log_debug("  Ended read with remaining size: %" PRIuz,
		PRAuz(remaining_size));

	context->bytes_read_in_unit += size;
	context->remaining_size -= size;
out:
	sys_log_pdebug(err, "Leaving %s(context=%p, dev=%p, "
		"offset=%" PRIu64 ", size=%" PRIuz ")",
		__FUNCTION__,
		_context, dev, PRAu64(offset), PRAuz(size));

	return err;
}

static int fsapi_linux_address_space_read_handle_hole(
		void *const context,
		const size_t size)
{
	return fsapi_linux_address_space_read_handle_io(
		/* void *context */
		context,
		/* sys_device *dev */
		NULL,
		/* u64 offset */
		0,
		/* size_t size */
		size);
}

static int fsapi_linux_address_space_read_copy_data(
		void *const _context,
		const void *const data,
		const size_t size)
{
	fsapi_linux_address_space_read_context *const context =
		(fsapi_linux_address_space_read_context*) _context;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
	struct folio *const folio = context->folio;
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
	struct page *const page = context->page;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */

	const size_t copy_size = min(context->remaining_size, size);

	int err = 0;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0))
	size_t end;
	char *page_data = NULL;
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */

	sys_log_trace("Entering %s(context=%p, data=%p, size=%" PRIuz ")...",
		__FUNCTION__,
		_context, data, PRAuz(size));

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
	sys_log_debug("    Filling tail with %" PRIuz " bytes of data at "
		"offset %" PRIuz "...",
		PRAuz(copy_size), PRAuz(context->bytes_read_in_unit));

	folio_fill_tail(
		/* struct folio *folio */
		folio,
		/* size_t offset */
		context->bytes_read_in_unit,
		/* const char *from */
		data,
		/* size_t len */
		copy_size);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) ... */
	end = context->bytes_read_in_unit + copy_size;
	if(end > PAGE_SIZE) {
		sys_log_critical("Unexpected: Attempted to write "
			"beyond end of page. bytes_read: %" PRIuz ", "
			"size: %" PRIuz ", PAGE_SIZE: %" PRIuz,
			PRAuz(context->bytes_read_in_unit),
			PRAuz(copy_size), PRAuz(PAGE_SIZE));
		err = EIO;
		goto out;
	}

	page_data = kmap_atomic(
		/* struct page *page */
		page);

	if(copy_size > 0) {
		memcpy(&page_data[context->bytes_read_in_unit], data,
			copy_size);
	}
	if(end < PAGE_SIZE) {
		memset(&page_data[end], 0, PAGE_SIZE - end);
	}

	flush_dcache_page(
		/* struct page *page */
		page);

	kunmap_atomic(
		/* const void *addr */
		page_data);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */

	context->has_holes = SYS_TRUE;
	context->bytes_read_in_unit += copy_size;
	context->remaining_size -= copy_size;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0))
out:
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
	sys_log_pdebug(err, "Leaving %s(context=%p, data=%p, size=%" PRIuz ")",
		__FUNCTION__,
		_context, data, PRAuz(size));

	return err;
}

static void fsapi_linux_address_space_read_end_io(
		struct buffer_head *const bh,
		const int uptodate)
{
	/* At the moment this is only used for trivially mapped blocks, and only
	 * for reads. Anything that needs postprocessing to e.g. decrypt data,
	 * decompress, update checksums, etc. should use the slow I/O path. */
	struct page *const page = bh->b_page;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
	struct folio *const folio = bh->b_folio;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) */
	struct buffer_head *head_buffer = NULL;
	struct buffer_head *current_buffer = NULL;
	unsigned long flags = 0;
	bool unit_uptodate = true;
	bool unit_io_finished = true;

	sys_log_debug("end_io called for buffer %p", bh);

	if(uptodate) {
		set_buffer_uptodate(
			/* struct buffer_head *bh */
			bh);
	}
	else {
		clear_buffer_uptodate(
			/* struct buffer_head *bh */
			bh);
	}

	/* Iterate over the buffers to check if it's safe to end the read. */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
	head_buffer = folio_buffers(
		/* struct folio *folio */
		folio);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
	head_buffer = page_buffers(
		/* struct page *page */
		page);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */

	sys_log_debug("Iterating over buffers to check if %s %p (page %p) is "
		"up to date. Buffer head: %p",
		FSAPI_IFELSE_LINUX_6_8("folio", "page"),
		FSAPI_IFELSE_LINUX_6_8(folio, page), page,
		head_buffer);

	if(!head_buffer) {
		sys_log_critical("Unexpected: No head buffer in folio.");
		BUG();
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))
	spin_lock_irqsave(
		/* spinlock_t *lock */
		&head_buffer->b_uptodate_lock,
		/* [out] unsigned long flags */
		flags);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)) */
	local_irq_save(
		/* [out] unsigned long flags */
		flags);

	bit_spin_lock(
		/* int bitnum */
		BH_Uptodate_Lock,
		/* unsigned long *addr */
		&head_buffer->b_state);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)) ... */

	sys_log_debug("Locked up-to-date lock.");

	clear_buffer_async_read(
		/* struct buffer_head *bh */
		bh);

	sys_log_debug("Cleared async read.");

	unlock_buffer(
		/* struct buffer_head *bh */
		bh);

	sys_log_debug("Unlocked buffer.");

	current_buffer = head_buffer;
	do {
		sys_log_debug("Checking if %p up-to-date...", current_buffer);

		if(!buffer_uptodate(
			/* struct buffer_head *bh */
			current_buffer))
		{
			unit_uptodate = false;
		}

		sys_log_debug("Checking if %p is async read...",
			current_buffer);

		if(!buffer_async_read(
			/* struct buffer_head *bh */
			current_buffer));
		else if(!buffer_locked(
			/* struct buffer_head *bh */
			current_buffer))
		{
			sys_log_critical("Asynchronous read with non-locked "
				"buffer %p. This shouldn't happen.",
				current_buffer);
			BUG();
		}
		else {
			unit_io_finished = false;
			break;
		}

		sys_log_debug("Current buffer: %p -> %p",
			current_buffer, current_buffer->b_this_page);

		current_buffer = current_buffer->b_this_page;
	} while(current_buffer && current_buffer != head_buffer);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))
	spin_unlock_irqrestore(
		/* spinlock_t *lock */
		&head_buffer->b_uptodate_lock,
		/* unsigned long flags */
		flags);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)) */
	bit_spin_unlock(
		/* int bitnum */
		BH_Uptodate_Lock,
		/* unsigned long *addr */
		&head_buffer->b_state);

	local_irq_restore(
		/* unsigned long flags */
		flags);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)) ... */

	if(unit_io_finished) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
		sys_log_debug("  Unlocking page %p / folio %p with refcount "
			"%d.",
			page, folio, folio_ref_count(folio));

		folio_detach_private(
			/* struct folio *folio */
			folio);

		folio_end_read(
			/* struct folio *folio */
			folio,
			/* bool success */
			unit_uptodate);

		sys_log_debug("  Unlocked page %p / folio %p with refcount %u.",
			page, folio, folio_ref_count(folio));
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
		sys_log_debug("  Unlocking page %p with refcount %d.",
			page, page_ref_count(page));
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
		detach_page_private(
			/* struct page *page */
			page);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)) */
		ClearPagePrivate(
			/* struct page *page */
			page);

		set_page_private(
			/* struct page *page */
			page,
			/* unsigned long private */
			0);

		put_page(
			/* struct page *page */
			page);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)) ... */

		if(unit_uptodate && !PageError(page)) {
			SetPageUptodate(
				/* struct page *page */
				page);
		}

		unlock_page(
			/* struct page *page */
			page);
		sys_log_debug("  Unlocked page %p with refcount %d.",
			page, page_ref_count(page));
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */
	}
	else {
		sys_log_debug("Operations still ongoing, leaving folio "
			"locked.");
	}
}

static void fsapi_linux_address_space_read_submit_io(
		fsapi_linux_address_space_read_context *const context)
{
	size_t i;

	sys_log_debug("    Submitting %" PRIuz " I/O buffers.",
		PRAuz(context->num_valid_buffers));

	for(i = 0; i < context->num_valid_buffers; i++) {
		struct buffer_head *const cur_buffer =
			context->valid_buffers[i];

		lock_buffer(
			/* struct buffer_head *bh */
			cur_buffer);

		cur_buffer->b_end_io =
			fsapi_linux_address_space_read_end_io;

		set_buffer_async_read(
			/* struct buffer_head *bh */
			cur_buffer);
	}

	for(i = 0; i < context->num_valid_buffers; i++) {
		struct buffer_head *const cur_buffer =
			context->valid_buffers[i];

		if(!buffer_uptodate(
			/* struct buffer_head *bh */
			cur_buffer))
		{
			sys_log_debug("      Submitting buffer %p...",
				cur_buffer);
			submit_bh(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0))
				/* blk_opf_t opf */
				REQ_OP_READ | 0,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)) */
				/* int op */
				REQ_OP_READ,
				/* int op_flags */
				0,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)) ... */
				/* struct buffer_head *bh */
				cur_buffer);
		}
		else {
			fsapi_linux_address_space_read_end_io(
				/* struct buffer_head *bh */
				cur_buffer,
				/* int uptodate */
				1);
		}
	}
}

static void fsapi_linux_address_space_end_read(
		fsapi_linux_address_space_read_context *const context,
		const bool success)
{
	sys_log_debug("Calling folio_end_read...");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0))
	folio_end_read(
		/* struct folio *folio */
		context->folio,
		/* bool success */
		success);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)) */
	if(success) {
		SetPageUptodate(
			/* struct page *page */
			FSAPI_IFELSE_LINUX_6_8(
				folio_page(context->folio, 0),
				context->page));
	}

	unlock_page(
		/* struct page *page */
		FSAPI_IFELSE_LINUX_6_8(
			folio_page(context->folio, 0),
			context->page));
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)) ... */
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0))
static int fsapi_linux_address_space_op_read_folio(
		struct file *const file,
		struct folio *const folio)
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)) */
static int fsapi_linux_address_space_op_readpage(
		struct file *const file,
		struct page *const page)
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)) ... */
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		file->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		file->f_inode);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)) && \
		(LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0))
	struct page *page = &folio->page;
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)) && ... */

	int err = 0;
	int ret = 0;
	size_t data_size = 0;
	u64 read_offset = 0;
	fsapi_iohandler iohandler;
	fsapi_linux_address_space_read_context context;

	memset(&iohandler, 0, sizeof(iohandler));
	memset(&context, 0, sizeof(context));

	fsapi_linux_op_log_enter("file=%p, "
		FSAPI_IFELSE_LINUX_5_19("folio", "page") "=%p",
		file, FSAPI_IFELSE_LINUX_5_19(folio, page));

	if(!vol || !node) {
		sys_log_error("No volume or node.");
		ret = -EIO;
		goto out;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
	data_size = folio_size(
		/* struct folio *folio */
		folio);
	read_offset = ((u64) folio->index) << PAGE_SHIFT;
	context.folio = folio;
	context.inode = folio->mapping->host;
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
	data_size = page_size(
		/* struct page *page */
		page);
	read_offset = ((u64) page->index) << PAGE_SHIFT;
	context.page = page;
	context.inode = page->mapping->host;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */
	context.block_size_shift = context.inode->i_blkbits;
	context.block_size = ((size_t) 1) << context.block_size_shift;
	context.block_size_mask = (size_t) ~(context.block_size - 1);
	context.remaining_size = data_size;

	iohandler.context = &context;
	iohandler.handle_io = fsapi_linux_address_space_read_handle_io;
	iohandler.handle_hole = fsapi_linux_address_space_read_handle_hole;
	iohandler.copy_data = fsapi_linux_address_space_read_copy_data;

	sys_log_debug("Reading %" PRIuz " bytes from file offset %" PRIu64 " "
		"into iohandler %p.",
		PRAuz(data_size), PRAu64(read_offset), &iohandler);

	err = fsapi_node_read(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* u64 offset */
		read_offset,
		/* size_t size */
		data_size,
		/* fsapi_iohandler *iohandler */
		&iohandler);
	if(err) {
		sys_log_perror(err, "Error reading from node");
		ret = -err;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0))
		SetPageError(page);
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)) */
		goto out;
	}
	else if(context.bytes_read_in_unit > data_size) {
		sys_log_critical("Unexpected: Read more data than requested.");
		ret = -EIO;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0))
		SetPageError(page);
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)) */
		goto out;
	}

	if(!context.has_holes) {
		sys_log_debug("Setting folio mapped to disk.");
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0))
		folio_set_mappedtodisk(
			/* struct folio *folio */
			folio);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)) */
		SetPageMappedToDisk(
			/* struct page *page */
			page);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)) ... */
	}

	if(context.num_valid_buffers) {
		sys_log_debug("Initiating read on %" PRIuz " mapped buffers "
			"for %s with refcount %d.",
			PRAuz(context.num_valid_buffers),
			FSAPI_IFELSE_LINUX_5_19("folio", "page"),
			FSAPI_IFELSE_LINUX_5_19(folio_ref_count(folio),
				page_ref_count(page)));

		fsapi_linux_address_space_read_submit_io(
			/* fsapi_linux_address_space_read_context *context */
			&context);
	}

	sys_log_debug("Done with reading into "
		FSAPI_IF_LINUX_5_19("folio") FSAPI_NOT_LINUX_5_19("page") ".");
out:
	if(ret || !context.num_valid_buffers) {
		sys_log_debug("Ending read with success=%d.",
			ret ? false : true);

		fsapi_linux_address_space_end_read(
			/* fsapi_linux_address_space_read_context *context */
			&context,
			/* bool success */
			ret ? false : true);
	}

	fsapi_linux_op_log_leave(ret, "file=%p, "
		FSAPI_IFELSE_LINUX_5_19("folio", "page") "=%p",
		file, FSAPI_IFELSE_LINUX_5_19(folio, page));

	return ret;
}

/* Write back some dirty pages from this mapping. */
static int fsapi_linux_address_space_op_writepages(
		struct address_space *mapping,
		struct writeback_control *wbc)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		mapping->host->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		mapping->host);

	int ret = 0;

	fsapi_linux_op_log_enter("mapping=%p, wbc=%p",
		mapping, wbc);

	(void) vol;
	(void) node;

	ret = -EIO;

	fsapi_linux_op_log_leave(ret, "mapping=%p, wbc=%p",
		mapping, wbc);

	return ret;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
/* Mark a folio dirty.  Return true if this dirtied it */
static bool fsapi_linux_address_space_op_dirty_folio(
		struct address_space *mapping,
		struct folio *folio)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		mapping->host->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		mapping->host);

	int ret = 0;

	fsapi_linux_op_log_enter("mapping=%p, folio=%p",
		mapping, folio);

	(void) vol;
	(void) node;

	ret = -EIO;

	fsapi_linux_op_log_leave(ret, "mapping=%p, folio=%p",
		mapping, folio);

	return ret;
}
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
static int fsapi_linux_address_space_op_set_page_dirty(
		struct page *page)
{
	int ret = 0;

	fsapi_linux_op_log_enter("page=%p", page);

	(void) page;

	ret = -EIO;

	fsapi_linux_op_log_leave(ret, "page=%p", page);

	return ret;
}
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */

static bool fsapi_linux_address_space_readahead_next_unit(
		fsapi_linux_address_space_read_context *const context)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
	context->folio = readahead_folio(
		/* struct readahead_control *ractl */
		context->rac);
	return context->folio ? true : false;
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
	if(context->page) {
		put_page(
			/* struct page *page */
			context->page);
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	context->page = readahead_page(
		/* struct readahead_control *ractl */
		context->rac);
	return context->page ? true : false;
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
	for(; context->cur_page < context->nr_pages; ++context->cur_page) {
		context->page = lru_to_page(context->pages);

		prefetchw(&context->page->flags);

		list_del(
			/* struct list_head *entry */
			&context->page->lru);

		if(!add_to_page_cache_lru(
			/* struct page *page */
			context->page,
			/* struct address_space *mapping */
			context->mapping,
			/* pgoff_t index */
			context->page->index,
			/* gfp_t gfp_maskpage */
			readahead_gfp_mask(
				/* struct address_space *x */
				context->mapping)))
		{
			break;
		}

		put_page(
			/* struct page *page */
			context->page);
	}

	if(context->cur_page == context->nr_pages) {
		context->page = NULL;
	}

	return (context->cur_page == context->nr_pages) ? false : true;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */
}

static int fsapi_linux_address_space_readahead_handle_io(
		void *const _context,
		sys_device *const dev,
		const u64 offset,
		const size_t size)
{
	fsapi_linux_address_space_read_context *const context =
		(fsapi_linux_address_space_read_context*) _context;

	int err = 0;
	u64 cur_offset = offset;
	size_t remaining_size = min(size, context->remaining_size);

	if(dev) {
		sys_log_debug("Handling I/O at offset %" PRIu64 ", size "
			"%" PRIuz "...",
			PRAu64(offset), PRAuz(size));
	}
	else {
		sys_log_debug("Handling hole with size %" PRIuz "...",
			PRAuz(size));
	}

	while(remaining_size) {
		const size_t cur_unit_size =
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
			folio_size(context->folio);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
			page_size(context->page);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */

		const size_t remaining_unit_size =
			cur_unit_size - context->bytes_read_in_unit;

		const size_t cur_size =
			min(remaining_unit_size, remaining_size);

		sys_log_debug("  Handling %s for %s %p with offset %" PRIu64 ", "
			"size %" PRIuz ", remaining in read %" PRIuz ".",
			dev ? "I/O" : "hole",
			FSAPI_IFELSE_LINUX_6_8("folio", "page"),
			FSAPI_IFELSE_LINUX_6_8(context->folio, context->page),
			PRAu64(cur_offset), PRAuz(cur_size),
			PRAuz(context->remaining_size));

		err = fsapi_linux_address_space_read_handle_io(
			/* void *context */
			context,
			/* sys_device *dev */
			dev,
			/* u64 offset */
			cur_offset,
			/* size_t size */
			cur_size);
		if(err) {
			sys_log_perror(err, "Error while handling I/O");
			goto out;
		}

		if(!context->remaining_size || cur_size != remaining_unit_size)
		{
			/* No more pages or we only partially filled the folio /
			 * page from the extent. */
			sys_log_debug("  Breaking because of %s%s%s.",
				!context->remaining_size ?
					"no remaining pages in folio" : "",
				(!context->remaining_size &&
				cur_size != remaining_unit_size) ? " and " : "",
				(cur_size != remaining_unit_size) ?
					"partially filled folio" : "");
			break;
		}

		if(!context->has_holes) {
			sys_log_debug("  Setting folio mapped to disk.");
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0))
			folio_set_mappedtodisk(
				/* struct folio *folio */
				context->folio);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)) */
			SetPageMappedToDisk(
				/* struct page *page */
				FSAPI_IFELSE_LINUX_6_8(
					folio_page(context->folio, 0),
					context->page));
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)) ... */
		}

		if(context->num_valid_buffers) {
			sys_log_debug("  Initiating read on %" PRIuz " mapped "
				"buffers for %s with refcount %d.",
				PRAuz(context->num_valid_buffers),
				FSAPI_IFELSE_LINUX_6_8("folio", "page"),
				FSAPI_IFELSE_LINUX_6_8(
					folio_ref_count(context->folio),
					page_ref_count(context->page)));

			fsapi_linux_address_space_read_submit_io(
				/* fsapi_linux_address_space_read_context
				 *     *context */
				context);
		}
		else {
			sys_log_debug("  Ending read with success=%d.", true);

			fsapi_linux_address_space_end_read(
				/* fsapi_linux_address_space_read_context
				 *     *context */
				context,
				/* bool success */
				true);
		}

		if(!fsapi_linux_address_space_readahead_next_unit(
			/* fsapi_linux_address_space_read_context *context */
			context))
		{
			sys_log_error("Readahead ended early with %" PRIu64 " "
				"remaining bytes.",
				PRAu64(context->remaining_size));
			err = EIO;
			goto out;
		}

		sys_log_debug("[handle_io] Readahead requested for %s %p with "
			"refcount %d.",
			FSAPI_IFELSE_LINUX_6_8("folio", "page"),
			context->FSAPI_IFELSE_LINUX_6_8(folio, page),
			FSAPI_IFELSE_LINUX_6_8(folio_ref_count(context->folio),
				page_ref_count(context->page)));

		context->has_holes = SYS_FALSE;
		context->cur_buffer = NULL;
		context->buffer_head = NULL;
		context->num_valid_buffers = 0;
		context->bytes_read_in_unit = 0;
		if(dev) {
			cur_offset += cur_size;
		}
		remaining_size -= cur_size;
	}
out:
	return err;
}

static int fsapi_linux_address_space_readahead_handle_hole(
		void *const context,
		const size_t size)
{
	return fsapi_linux_address_space_readahead_handle_io(
		/* void *context */
		context,
		/* sys_device *dev */
		NULL,
		/* u64 offset */
		0,
		/* size_t size */
		size);
}

static int fsapi_linux_address_space_readahead_copy_data(
		void *const _context,
		const void *const data,
		const size_t size)
{
	fsapi_linux_address_space_read_context *const context =
		(fsapi_linux_address_space_read_context*) _context;

	int err = 0;
	size_t remaining_size = min(size, context->remaining_size);

	sys_log_debug("Handling data with size %" PRIuz "...",
		PRAuz(size));

	while(remaining_size) {
		const size_t cur_unit_size =
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0))
			folio_size(context->folio);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
			page_size(context->page);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)) ... */

		const size_t remaining_unit_size =
			cur_unit_size - context->bytes_read_in_unit;

		const size_t cur_size =
			min(remaining_unit_size, remaining_size);

		sys_log_debug("  Handling data for %s %p with size %" PRIuz ", "
			"remaining in read %" PRIuz ".",
			FSAPI_IFELSE_LINUX_6_8("folio", "page"),
			FSAPI_IFELSE_LINUX_6_8(context->folio, context->page),
			PRAuz(cur_size),
			PRAuz(context->remaining_size));

		err = fsapi_linux_address_space_read_copy_data(
			/* void *context */
			context,
			/* const void *data */
			data,
			/* size_t size */
			cur_size);
		if(err) {
			sys_log_perror(err, "Error while copying data to "
				FSAPI_IFELSE_LINUX_5_19("folio", "page"));
			goto out;
		}

		if(!context->remaining_size || cur_size != remaining_unit_size)
		{
			/* No more pages or we only partially filled the page
			 * from the extent. */
			break;
		}

		if(context->num_valid_buffers) {
			sys_log_debug("  Initiating read on %" PRIuz " mapped "
				"buffers for %s with refcount %d.",
				PRAuz(context->num_valid_buffers),
				FSAPI_IFELSE_LINUX_6_8("folio", "page"),
				FSAPI_IFELSE_LINUX_6_8(
					folio_ref_count(context->folio),
					page_ref_count(context->page)));

			fsapi_linux_address_space_read_submit_io(
				/* fsapi_linux_address_space_read_context
				 *     *context */
				context);
		}
		else {
			sys_log_debug("  Ending read with success=%d.", true);

			fsapi_linux_address_space_end_read(
				/* fsapi_linux_address_space_read_context
				 *     *context */
				context,
				/* bool success */
				true);
		}

		if(!fsapi_linux_address_space_readahead_next_unit(
			/* fsapi_linux_address_space_read_context *context */
			context))
		{
			sys_log_error("Readahead ended early with %" PRIu64 " "
				"remaining bytes.",
				PRAu64(context->remaining_size));
			err = EIO;
			goto out;
		}

		sys_log_debug("[copy_data] Readahead requested for %s %p with "
			"refcount %d.",
			FSAPI_IFELSE_LINUX_6_8("folio", "page"),
			context->FSAPI_IFELSE_LINUX_6_8(folio, page),
			FSAPI_IFELSE_LINUX_6_8(folio_ref_count(context->folio),
				page_ref_count(context->page)));

		context->has_holes = SYS_FALSE;
		context->cur_buffer = NULL;
		context->buffer_head = NULL;
		context->num_valid_buffers = 0;
		context->bytes_read_in_unit = 0;
		remaining_size -= cur_size;
	}
out:
	return err;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
static void fsapi_linux_address_space_op_readahead(
		struct readahead_control *const rac)
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
static int fsapi_linux_address_space_op_readpages(
		struct file *const file,
		struct address_space *const mapping,
		struct list_head *const pages,
		const unsigned nr_pages)
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		FSAPI_IF_LINUX_5_18(rac->)file->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		FSAPI_IF_LINUX_5_18(rac->)file->f_inode);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	const unsigned int count = readahead_count(rac);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) */

	int ret = 0;
	int err = 0;
	size_t data_size = 0;
	u64 read_offset = 0;
	fsapi_iohandler iohandler;
	fsapi_linux_address_space_read_context context;

	memset(&iohandler, 0, sizeof(iohandler));
	memset(&context, 0, sizeof(context));

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	fsapi_linux_op_log_enter("rac=%p (count: %u)", rac, count);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
	fsapi_linux_op_log_enter("file=%p, mapping=%p, pages=%p, "
		"nr_pages=%u",
		file, mapping, pages, nr_pages);
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */

	if(!vol || !node) {
		sys_log_error("No volume or node.");
		ret = -EIO;
		goto out;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	data_size = readahead_length(
		/* struct readahead_control *rac */
		rac);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
	data_size = ((size_t) nr_pages) * PAGE_SIZE;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */
	if(!data_size) {
		sys_log_error("Readahead for 0 bytes received. Why did we get "
			"this call?");
		ret = -EIO;
		goto out;
	}

	context.inode = FSAPI_IF_LINUX_5_18(rac->)file->f_inode;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	context.rac = rac;
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
	context.mapping = mapping;
	context.pages = pages;
	context.nr_pages = nr_pages;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */
	context.block_size_shift = context.inode->i_blkbits;
	context.block_size = ((size_t) 1) << context.block_size_shift;
	context.block_size_mask = (size_t) ~(context.block_size - 1);
	context.remaining_size = data_size;

	if(!fsapi_linux_address_space_readahead_next_unit(
		/* fsapi_linux_address_space_read_context *context */
		&context))
	{
		sys_log_error("No first page in readahead for %" PRIu64 " "
			"bytes. Why did we get this call?",
			PRAu64(context.remaining_size));
		ret = -EIO;
		goto out;
	}

	sys_log_debug("Readahead requested for %s %p with refcount %d.",
		FSAPI_IFELSE_LINUX_6_8("folio", "page"),
		context.FSAPI_IFELSE_LINUX_6_8(folio, page),
		FSAPI_IFELSE_LINUX_6_8(folio_ref_count(context.folio),
			page_ref_count(context.page)));

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	read_offset = readahead_pos(
		/* struct readahead_control *rac */
		rac);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
	read_offset = ((u64) context.page->index) * PAGE_SIZE;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */

	iohandler.context = &context;
	iohandler.handle_io = fsapi_linux_address_space_readahead_handle_io;
	iohandler.handle_hole = fsapi_linux_address_space_readahead_handle_hole;
	iohandler.copy_data = fsapi_linux_address_space_readahead_copy_data;

	sys_log_debug("Reading %" PRIuz " bytes from file offset %" PRIu64 " "
		"into iohandler %p.",
		PRAuz(data_size), PRAu64(read_offset), &iohandler);

	err = fsapi_node_read(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		node,
		/* u64 offset */
		read_offset,
		/* size_t size */
		data_size,
		/* fsapi_iohandler *iohandler */
		&iohandler);
	if(err) {
		sys_log_perror(err, "Error reading from node");
		ret = -err;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0))
		SetPageError(
			/* struct page *page */
			FSAPI_IFELSE_LINUX_6_8(
				folio_page(context.folio, 0),
				context.page));
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)) */
		goto out;
	}

	if(!context.has_holes) {
		sys_log_debug("Setting folio mapped to disk.");
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0))
		folio_set_mappedtodisk(
			/* struct folio *folio */
			context.folio);
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)) */
		SetPageMappedToDisk(
			/* struct page *page */
			FSAPI_IFELSE_LINUX_6_8(
				folio_page(context.folio, 0),
				context.page));
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)) ... */
	}

	if(context.num_valid_buffers) {
		sys_log_debug("Initiating read on %" PRIuz " mapped "
			"buffers for %s with refcount %d.",
			PRAuz(context.num_valid_buffers),
			FSAPI_IFELSE_LINUX_6_8("folio", "page"),
			FSAPI_IFELSE_LINUX_6_8(folio_ref_count(context.folio),
				page_ref_count(context.page)));

		fsapi_linux_address_space_read_submit_io(
			/* fsapi_linux_address_space_read_context *context */
			&context);
	}

	sys_log_debug("Done with readahead into %" PRIu32 " "
		FSAPI_IFELSE_LINUX_5_19("folios", "pages") ".",
		PRAu32(FSAPI_IFELSE_LINUX_5_18(readahead_count(rac),
			nr_pages)));
out:
	if(context.FSAPI_IFELSE_LINUX_6_8(folio, page)) {
		if(ret || !context.num_valid_buffers) {
			sys_log_debug("Ending read with success=%d.",
				ret ? false : true);

			fsapi_linux_address_space_end_read(
				/* fsapi_linux_address_space_read_context *context */
				&context,
				/* bool success */
				ret ? false : true);
		}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0))
		put_page(
			/* struct page *page */
			context.page);
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)) */
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0))
	fsapi_linux_op_log_leave(ret, "rac=%p (count: %u)", rac, count);
	return;
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)) */
	fsapi_linux_op_log_leave(ret, "file=%p, mapping=%p, pages=%p, "
		"nr_pages=%u",
		file, mapping, pages, nr_pages);
	return ret;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(5,18,0)) ... */
}

static int fsapi_linux_address_space_op_write_begin(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		const struct kiocb *iocb,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)) */
		struct file *file,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
		struct address_space *mapping,
		loff_t pos,
		unsigned len,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0))
		unsigned flags,
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)) */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0))
		struct folio **foliop,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)) */
		struct page **pagep,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)) ... */
		void **fsdata)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		mapping->host->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		mapping->host);

	int ret = 0;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_6_17("iocb=%p, ")
		FSAPI_NOT_LINUX_6_17("file=%p, ")
		"mapping=%p, "
		"pos=%" PRId64 ", "
		"len=%u, "
		FSAPI_NOT_LINUX_5_19("flags=0x%X")
		FSAPI_IF_LINUX_6_12("foliop=%p, ")
		FSAPI_NOT_LINUX_6_12("pagep=%p, ")
		"fsdata=%p",
		FSAPI_IF_LINUX_6_17(iocb,)
		FSAPI_NOT_LINUX_6_17(file,)
		mapping,
		PRAd64(pos),
		len,
		FSAPI_NOT_LINUX_5_19(flags,)
		FSAPI_IF_LINUX_6_12(foliop,)
		FSAPI_NOT_LINUX_6_12(pagep,)
		fsdata);

	(void) vol;
	(void) node;

	ret = -EIO;

	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_6_17("iocb=%p, ")
		FSAPI_NOT_LINUX_6_17("file=%p, ")
		"mapping=%p, "
		"pos=%" PRId64 ", "
		"len=%u, "
		FSAPI_NOT_LINUX_5_19("flags=0x%X")
		FSAPI_IF_LINUX_6_12("foliop=%p, ")
		FSAPI_NOT_LINUX_6_12("pagep=%p, ")
		"fsdata=%p",
		FSAPI_IF_LINUX_6_17(iocb,)
		FSAPI_NOT_LINUX_6_17(file,)
		mapping,
		PRAd64(pos),
		len,
		FSAPI_NOT_LINUX_5_19(flags,)
		FSAPI_IF_LINUX_6_12(foliop,)
		FSAPI_NOT_LINUX_6_12(pagep,)
		fsdata);

	return ret;
}

static int fsapi_linux_address_space_op_write_end(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0))
		const struct kiocb *iocb,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)) */
		struct file *file,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)) ... */
		struct address_space *mapping,
		loff_t pos,
		unsigned len,
		unsigned copied,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0))
		struct folio *folio,
#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)) */
		struct page *page,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,12,0)) ... */
		void *fsdata)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		mapping->host->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		mapping->host);

	int ret = 0;

	fsapi_linux_op_log_enter(
		FSAPI_IF_LINUX_6_17("iocb=%p, ")
		FSAPI_NOT_LINUX_6_17("file=%p, ")
		"mapping=%p, "
		"pos=%" PRId64 ", "
		"len=%u, "
		"copied=%u, "
		FSAPI_IF_LINUX_6_12("folio=%p, ")
		FSAPI_NOT_LINUX_6_12("page=%p, ")
		"fsdata=%p",
		FSAPI_IF_LINUX_6_17(iocb,)
		FSAPI_NOT_LINUX_6_17(file,)
		mapping,
		PRAd64(pos),
		len,
		copied,
		FSAPI_IF_LINUX_6_12(folio,)
		FSAPI_NOT_LINUX_6_12(page,)
		fsdata);

	(void) vol;
	(void) node;

	ret = -EIO;

	fsapi_linux_op_log_leave(ret,
		FSAPI_IF_LINUX_6_17("iocb=%p, ")
		FSAPI_NOT_LINUX_6_17("file=%p, ")
		"mapping=%p, "
		"pos=%" PRId64 ", "
		"len=%u, "
		"copied=%u, "
		FSAPI_IF_LINUX_6_12("folio=%p, ")
		FSAPI_NOT_LINUX_6_12("page=%p, ")
		"fsdata=%p",
		FSAPI_IF_LINUX_6_17(iocb,)
		FSAPI_NOT_LINUX_6_17(file,)
		mapping,
		PRAd64(pos),
		len,
		copied,
		FSAPI_IF_LINUX_6_12(folio,)
		FSAPI_NOT_LINUX_6_12(page,)
		fsdata);

	return ret;
}

static sector_t fsapi_linux_address_space_op_bmap(struct address_space *mapping,
		sector_t sector)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		mapping->host->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		mapping->host);

	size_t ret = 0;

	fsapi_linux_op_log_enter("mapping=%p, sector=%" PRIu64,
		mapping, PRAu64(sector));

	(void) vol;
	(void) node;

	/* 0 means error or cannot map, etc. */

	fsapi_linux_op_log_leave(ret, "mapping=%p, sector=%" PRIu64,
		mapping, PRAu64(sector));

	return ret;
}

static ssize_t fsapi_linux_address_space_op_direct_IO(struct kiocb *iocb,
		struct iov_iter *iter)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		iocb->ki_filp->f_inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		iocb->ki_filp->f_inode);

	ssize_t ret = 0;

	fsapi_linux_op_log_enter("iocb=%p, iter=%p",
		iocb, iter);

	(void) vol;
	(void) node;

	ret = -EIO;

	fsapi_linux_op_log_leave(ret, "iocb=%p, iter=%p",
		iocb, iter);

	return ret;
}

static int fsapi_linux_xattr_get(
		const struct xattr_handler *handler,
		struct dentry *dentry,
		struct inode *inode,
		const char *name,
		void *value,
		size_t size)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	int ret = 0;
	int err = 0;
	fsapi_iohandler_buffer_context buffer_context;
	sys_iohandler iohandler;
	u64 xattr_size = 0;

	memset(&buffer_context, 0, sizeof(buffer_context));
	memset(&iohandler, 0, sizeof(iohandler));

	fsapi_linux_op_log_enter(
		"handler=%p, "
		"dentry=%" PRIdentry ", "
		"inode=%p, "
		"name=%p (->\"%s\"), "
		"value=%p, "
		"size=%" PRIuz,
		handler,
		PRAdentry(dentry),
		inode,
		name, name ? name : "",
		value,
		PRAuz(size));

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	if(size) {
		buffer_context.buf.rw = value;
		buffer_context.remaining_size = size;
		buffer_context.is_read = SYS_TRUE;
		iohandler.context = &buffer_context;
		iohandler.handle_io = fsapi_iohandler_buffer_handle_io;
		iohandler.copy_data = fsapi_iohandler_buffer_copy_data;
	}

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
		0,
		/* size_t size */
		size,
		/* fsapi_iohandler *iohandler */
		size ? &iohandler : NULL,
		/* u64 *out_xattr_size */
		size ? NULL : &xattr_size);
	if(err == ENOENT) {
		ret = -ENODATA;
	}
	else if(err) {
		ret = -err;
	}
	else {
		const size_t valid_bytes =
			size ? size - buffer_context.remaining_size :
			xattr_size;

		ret = (valid_bytes > INT_MAX) ? INT_MAX : (int) valid_bytes;
	}
out:
	fsapi_linux_op_log_leave(ret,
		"handler=%p, "
		"dentry=%" PRIdentry ", "
		"inode=%p, "
		"name=%p (->\"%s\"), "
		"value=%p, "
		"size=%" PRIuz,
		handler,
		PRAdentry(dentry),
		inode,
		name, name ? name : "",
		value,
		PRAuz(size));

	return ret;
}

static int fsapi_linux_xattr_set(
		const struct xattr_handler *handler,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
		struct mnt_idmap *idmap,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0))
		struct user_namespace *idmap,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)) ... */
		struct dentry *dentry,
		struct inode *inode,
		const char *name,
		const void *value,
		size_t size,
		int flags)
{
	fsapi_volume *const vol = fsapi_linux_sb_to_fsapi_volume(
		/* struct super_block *sb */
		inode->i_sb);

	fsapi_node *const node = fsapi_linux_inode_to_fsapi_node(
		/* struct inode *inode */
		inode);

	int ret = 0;
	int err = 0;

	fsapi_linux_op_log_enter(
		"handler=%p, "
		FSAPI_IF_LINUX_5_12("idmap=%p, ")
		"dentry=%" PRIdentry ", "
		"inode=%p, "
		"name=%p (->\"%s\"), "
		"value=%p, "
		"size=%" PRIuz ", "
		"flags=0x%X",
		handler,
		FSAPI_IF_LINUX_5_12(idmap,)
		PRAdentry(dentry),
		inode,
		name, name ? name : "",
		value,
		PRAuz(size),
		flags);

	if(!vol) {
		ret = -EIO;
		goto out;
	}

	if(value) {
		fsapi_iohandler_buffer_context buffer_context;
		sys_iohandler iohandler;

		memset(&buffer_context, 0, sizeof(buffer_context));
		memset(&iohandler, 0, sizeof(iohandler));

		buffer_context.buf.ro = value;
		buffer_context.remaining_size = size;
		buffer_context.is_read = SYS_FALSE;
		iohandler.context = &buffer_context;
		iohandler.handle_io = fsapi_iohandler_buffer_handle_io;
		iohandler.get_data = fsapi_iohandler_buffer_get_data;

		err = fsapi_node_write_extended_attribute(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			node,
			/* const char *xattr_name */
			name,
			/* size_t xattr_name_length */
			strlen(name),
			/* fsapi_node_extended_attribute_flags flags */
			(!(flags & XATTR_CREATE) ? 0 :
				FSAPI_NODE_EXTENDED_ATTRIBUTE_FLAG_CREATE) |
			(!(flags & XATTR_REPLACE) ? 0 :
				FSAPI_NODE_EXTENDED_ATTRIBUTE_FLAG_REPLACE) |
			FSAPI_NODE_EXTENDED_ATTRIBUTE_FLAG_TRUNCATE,
			/* u64 offset */
			0,
			/* size_t size */
			size,
			/* fsapi_iohandler *iohandler */
			&iohandler);
	}
	else {
		err = fsapi_node_remove_extended_attribute(
			/* fsapi_volume *vol */
			vol,
			/* fsapi_node *node */
			node,
			/* const char *xattr_name */
			name,
			/* size_t xattr_name_length */
			strlen(name));
	}
	if(err == ENOENT) {
		ret = -ENODATA;
	}
	else if(err) {
		ret = -err;
	}
out:
	fsapi_linux_op_log_leave(ret,
		"handler=%p, "
		FSAPI_IF_LINUX_5_12("idmap=%p, ")
		"dentry=%" PRIdentry ", "
		"inode=%p, "
		"name=%p (->\"%s\"), "
		"value=%p, "
		"size=%" PRIuz ", "
		"flags=0x%X",
		handler,
		FSAPI_IF_LINUX_5_12(idmap,)
		PRAdentry(dentry),
		inode,
		name, name ? name : "",
		value,
		PRAuz(size),
		flags);

	return ret;
}

static int fsapi_linux_fill_super(
		struct super_block *sb,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0))
		struct fs_context *fs_context
#else
		void *opt,
		const int silent
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0)) ... */
		)
{
	int ret = 0;
	int err = 0;
	sys_device *dev = NULL;
	fsapi_node *root_node = NULL;
	fsapi_volume *vol = NULL;
	fsapi_linux_context *ctx = NULL;
	struct inode *inode = NULL;
	fsapi_node_attributes attributes;

	memset(&attributes, 0, sizeof(attributes));

	fsapi_linux_op_log_enter("sb=%p, "
		FSAPI_IF_LINUX_6_18("fs_context=%p")
		FSAPI_NOT_LINUX_6_18("opt=%p, silent=%d"),
		sb,
		FSAPI_IF_LINUX_6_18(fs_context)
		FSAPI_NOT_LINUX_6_18(opt, silent));

	err = sys_device_open(
		/* sys_device **dev */
		&dev,
		/* struct super_block *sb */
		sb);
	if(err) {
		ret = -ENOMEM;
		goto out;
	}

	/* Allocate a new fsapi_linux_context and place it in sb->s_fs_info. */
	ctx = kmalloc(sizeof(fsapi_linux_context), GFP_NOFS);
	if(!ctx) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,18,0))
		if(!silent)
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,18,0)) */
		{
			sys_log_error("Allocation of fsapi volume structure "
				"failed.");
		}

		ret = -ENOMEM;
		goto out;
	}

	err = fsapi_volume_mount(
		/* sys_device *dev */
		dev,
		/* sys_bool read_only */
		SYS_TRUE,
		/* void *custom_mount_options */
		NULL,
		/* fsapi_volume **out_vol */
		&vol,
		/* fsapi_node **out_root_node */
		&root_node,
		/* fsapi_volume_attributes *out_attrs */
		NULL);
	if(err) {
		ret = -EIO; /* ? */
		goto out;
	}

	*ctx = (fsapi_linux_context) {
		.sb = sb,
		.root_inode = NULL,
		.dev = dev,
		.vol = vol,
		.root_node = root_node,
	};

	sb->s_fs_info = ctx;

	sb->s_magic = cpu_to_le32(*((const le32*) "SFeR"));
	sb->s_maxbytes = S64_MAX;
	sb->s_max_links = 0;
	sb->s_time_gran = 100;
	sb->s_op = &fsapi_linux_super_operations;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))
	sb->s_xattr = fsapi_linux_xattr_handlers;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)) */

	inode = new_inode(sb);
	if(unlikely(!inode)) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,18,0))
		if(!silent)
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,18,0)) */
		{
			sys_log_error("Error allocating root directory node.");
		}

		ret = -ENOMEM;
		goto out;
	}

	inode->i_private = root_node;

	attributes.requested =
		FSAPI_NODE_ATTRIBUTE_TYPE_SIZE |
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATED_SIZE |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_ALLOCATION_BLOCK_SIZE |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_UID |
		FSAPI_NODE_ATTRIBUTE_TYPE_GID |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE |
		FSAPI_NODE_ATTRIBUTE_TYPE_LINK_COUNT |
		FSAPI_NODE_ATTRIBUTE_TYPE_INODE_NUMBER |
#if 0
		FSAPI_NODE_ATTRIBUTE_TYPE_DEVICE_NUMBER |
#endif
		FSAPI_NODE_ATTRIBUTE_TYPE_CREATION_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_ACCESS_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_DATA_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_LAST_STATUS_CHANGE_TIME |
		FSAPI_NODE_ATTRIBUTE_TYPE_MODE;

	err = fsapi_node_get_attributes(
		/* fsapi_volume *vol */
		vol,
		/* fsapi_node *node */
		root_node,
		/* fsapi_node_attributes *out_attributes */
		&attributes);
	if(err) {
		ret = -err;
		goto out;
	}

	fsapi_linux_attributes_to_inode(
		/* const fsapi_node_attributes *attributes */
		&attributes,
		/* struct inode *ino */
		inode,
		/* sys_bool fill_operations */
		SYS_TRUE);

	insert_inode_hash(inode);

	ctx->root_inode = inode;
	ihold(inode);
	sb->s_root = d_make_root(inode);
	if (unlikely(!sb->s_root)) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,18,0))
		if(!silent)
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,18,0)) */
		{
			sys_log_error("Failed to allocate root directory.");
		}

		ret = -ENOMEM;
		goto out;
	}

	dev = NULL;
	vol = NULL;
	ctx = NULL;
out:
	if(ret && sb->s_root) {
		dput(sb->s_root);
		sb->s_root = NULL;
	}

	if(ctx) {
		sys_free(sizeof(*ctx), &ctx);
	}

	if(vol) {
		int unmount_err;

		unmount_err = fsapi_volume_unmount(
			/* fsapi_volume **vol */
			&vol);
		if(unmount_err) {
			sys_log_perror(unmount_err, "Error while "
				"unmounting volume on cleanup");
		}
	}

	if(dev) {
		int cleanup_err = 0;

		cleanup_err = sys_device_close(&dev);
		if(cleanup_err) {
			sys_log_perror(cleanup_err, "Error while "
				"closing device on cleanup");
			ret = ret ? ret : -EIO;
		}
	}

	fsapi_linux_op_log_leave(ret, "sb=%p, "
		FSAPI_IF_LINUX_6_18("fs_context=%p")
		FSAPI_NOT_LINUX_6_18("opt=%p, silent=%d"),
		sb,
		FSAPI_IF_LINUX_6_18(fs_context)
		FSAPI_NOT_LINUX_6_18(opt, silent));

	return ret;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0))
enum {
	Opt_uid,
	Opt_gid,
};

static const struct fs_parameter_spec fsapi_linux_param_specs[] = {
	fsparam_uid("uid", Opt_uid),
	fsparam_gid("gid", Opt_gid),
	{}
};

static int fsapi_linux_context_op_parse_param(
		struct fs_context *fc,
		struct fs_parameter *param)
{
	int ret = 0;
	struct fs_parse_result result;

	memset(&result, 0, sizeof(result));

	fsapi_linux_op_log_enter("fc=%p, param=%p", fc, param);

	ret = fs_parse(fc, fsapi_linux_param_specs, param, &result);
	if(ret < 0) {
		goto out;
	}

	switch(ret) {
	case Opt_uid:
		/* ... = result.uid; */
                break;
	case Opt_gid:
		/* ... = result.gid; */
                break;
	}
out:
	fsapi_linux_op_log_leave(ret, "fc=%p, param=%p", fc, param);

	return ret;
}

static int fsapi_linux_context_op_get_tree(struct fs_context *fc)
{
	int ret = 0;

	fsapi_linux_op_log_enter("fc=%p", fc);

	ret = get_tree_bdev(fc, fsapi_linux_fill_super);

	fsapi_linux_op_log_leave(ret, "fc=%p", fc);

	return ret;
}

static int fsapi_linux_context_op_reconfigure(struct fs_context *fc)
{
	int ret = 0;

	fsapi_linux_op_log_enter("fc=%p", fc);

	/* TODO */

	fsapi_linux_op_log_leave(ret, "fc=%p", fc);

	return ret;
}

static void fsapi_linux_context_op_fc_free(struct fs_context *fc)
{
	fsapi_linux_op_log_enter("fc=%p", fc);

	fsapi_linux_op_log_leave(0, "fc=%p", fc);
}

static const struct fs_context_operations fsapi_linux_context_ops = {
	.parse_param = fsapi_linux_context_op_parse_param,
	.get_tree = fsapi_linux_context_op_get_tree,
	.reconfigure = fsapi_linux_context_op_reconfigure,
	.free = fsapi_linux_context_op_fc_free,
};

static int fsapi_init_fs_context(struct fs_context *fc)
{
	int ret = 0;

	fsapi_linux_op_log_enter("fc=%p", fc);

	fc->fs_private = NULL;
	fc->ops = &fsapi_linux_context_ops;

	fsapi_linux_op_log_leave(ret, "fc=%p", fc);

	return ret;
}
#else
static struct dentry* fsapi_linux_mount(
		struct file_system_type *fs_type,
		int flags,
		const char *dev_name,
		void *data)
{
	struct dentry *ret;

	fsapi_linux_op_log_enter("fs_type=%p, flags=0x%X, dev_name=\"%s\", "
		"data=%p",
		fs_type, flags, dev_name, data);

	ret = mount_bdev(
		/* struct file_system_type *fs_type */
		fs_type,
		/* int flags */
		flags,
		/* const char *dev_name */
		dev_name,
		/* void *data */
		data,
		/* int (*fill_super)(struct super_block *, void *, int) */
		fsapi_linux_fill_super);

	fsapi_linux_op_log_leave(IS_ERR(ret) ? PTR_ERR(ret) : 0, "fs_type=%p, "
		"flags=0x%X, dev_name=\"%s\", data=%p -> %p",
		fs_type, flags, dev_name, data, ret);

	return ret;
}
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0)) ... */

static void fsapi_linux_kill_sb(
		struct super_block *sb)
{
	int err = 0;
	fsapi_linux_context *context =
		(fsapi_linux_context*) sb->s_fs_info;
	fsapi_volume *vol = context ? context->vol : NULL;

	fsapi_linux_op_log_enter("sb=%p", sb);

	if(!vol) {
		goto out;
	}

	sys_log_debug("context=%p, context->dev=%p, vol=%p, "
		"context->root_node=%p",
		context, context->dev, vol, context->root_node);

	sys_log_debug("Syncing volume.");

	err = fsapi_volume_sync(
		/* fsapi_volume *vol */
		vol);
	if(err) {
		sys_log_perror(err, "Error while syncing fsapi volume");
	}

	sys_log_debug("Calling shrink_dcache_sb.");
	shrink_dcache_sb(sb);
out:
	sys_log_debug("Calling kill_block_super...");
	kill_block_super(sb);
	sys_log_debug("    kill_block_super done.");

	fsapi_linux_op_log_leave(0, "sb=%p", sb);
}

static struct file_system_type fsapi_type = {
	.owner = THIS_MODULE,
	.name = NULL,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0))
	.init_fs_context = fsapi_init_fs_context,
#else
	.mount = fsapi_linux_mount,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0)) ... */
	.kill_sb = fsapi_linux_kill_sb,
	.fs_flags = FS_REQUIRES_DEV FSAPI_IF_LINUX_5_12(| FS_ALLOW_IDMAP),
};

static void fsapi_inode_init_once(void *ino)
{
	inode_init_once((struct inode*) ino);
}

int fsapi_linux_register_filesystem(
		const char *const fs_name)
{
	int ret = 0;

	if(fsapi_type.name) {
		printk(KERN_CRIT "%s: Tried to register filesystem twice.",
			fs_name);
		ret = -EINVAL;
		goto out;
	}

	fsapi_inode_cache = kmem_cache_create(
		/* const char *name */
		"fsapi_inode_cache",
		/* unsigned int size */
		sizeof(struct inode),
		/* unsigned int align */
		0,
		/* slab_flags_t flags */
		SLAB_RECLAIM_ACCOUNT |
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0))
		SLAB_MEM_SPREAD |
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)) */
		SLAB_ACCOUNT,
		/* void (*ctor)(void *) */
		fsapi_inode_init_once);
	if(!fsapi_inode_cache) {
		sys_log_error("Error while creating inode cache.");
		goto out;
	}

	printk(KERN_INFO "%s version " VERSION " started.\n",
		fs_name);

	fsapi_type.name = fs_name;

	ret = register_filesystem(&fsapi_type);
	if(ret) {
		sys_log_error("Error registering filesystem %s.", fs_name);
		goto out;
	}

	sys_log_debug("%s file system registered successfully.",
		fs_name);
out:
	return ret;
}

int fsapi_linux_unregister_filesystem(void)
{
	int ret = 0;

	if(!fsapi_type.name) {
		printk(KERN_CRIT "Attempted to unregister filesystem that was "
			"never registered.");
		ret = -EINVAL;
		goto out;
	}

	ret = unregister_filesystem(&fsapi_type);
	if(ret) {
		goto out;
	}

	sys_log_debug("%s file system unregistered successfully.",
		fsapi_type.name);

	kmem_cache_destroy(fsapi_inode_cache);

	memset(&fsapi_type, 0, sizeof(fsapi_type));
out:
	return ret;
}
