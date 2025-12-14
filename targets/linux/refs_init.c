/*-
 * refs_init.c - ReFS Linux kernel module initialization code.
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

#include "sys.h"

#include "fsapi_linux.h"

#include <linux/version.h>

#include <asm/atomic.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0))
#include <asm/uaccess.h>
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)) */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,10,0))
#include <linux/string.h>
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(6,10,0)) */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
#include <linux/uaccess.h>
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)) */
#include <linux/utsname.h>

static int __init init_refs(void)
{
	int err;

	sys_log_trace("Testing trace logging.");
	sys_log_ptrace(EINVAL, "Testing ptrace logging");
	sys_log_debug("Testing debug logging.");
	sys_log_pdebug(EIO, "Testing pdebug logging");
	sys_log_info("Testing info logging.");
	sys_log_pinfo(ENXIO, "Testing pinfo logging");
	sys_log_warning("Testing warning logging.");
	sys_log_pwarning(ENOENT, "Testing pwarning logging");
	sys_log_error("Testing error logging.");
	sys_log_perror(EIO, "Testing perror logging");
	sys_log_critical("Testing critical logging.");

	err = fsapi_linux_register_filesystem("refs");
	if(err) {
		sys_log_error("Error registering the ReFS filesystem.");
		goto out;
	}

	sys_log_debug("Successfully registered the ReFS filesystem.");
out:
	return err;
}

static void __exit exit_refs(void)
{
	fsapi_linux_unregister_filesystem();
}

MODULE_AUTHOR("Erik Larsson");
MODULE_DESCRIPTION("ReFS filesystem");
MODULE_VERSION(VERSION);
MODULE_LICENSE("GPL");
MODULE_ALIAS_FS("refs");

module_init(init_refs)
module_exit(exit_refs)
