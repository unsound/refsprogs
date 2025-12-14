/*-
 * sys.c - Lightweight abstractions for system functionality.
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

#ifdef _WIN32
#include <windows.h>
#else
#include <iconv.h>

#if 0
static iconv_t iconv_decode_handle = (iconv_t) -1;
static iconv_t iconv_encode_handle = (iconv_t) -1;
#endif
#endif /* defined(_WIN32) ... */

#ifndef HAVE_STRNDUP
int sys_strndup(const char *str, size_t len, char **dupstr)
{
	int err = 0;

	err = sys_malloc(len + 1, dupstr);
	if(!err) {
		memcpy(*dupstr, str, len);
		(*dupstr)[len] = '\0';
	}

	return err;
}
#endif

int sys_unistr_decode(const refschar *ins, const size_t ins_len,
		char **const outs, size_t *const outs_len)
{
	int err = 0;
#ifdef _WIN32
	int res = 0;
#else
	iconv_t handle = (iconv_t) -1;
#endif
#if defined(__illumos__)
	const char *ins_tmp = (const char*) ins;
#elif !defined(_WIN32)
	char *ins_tmp = (char*) ins;
#endif
	size_t ins_remaining = 0;
	size_t outs_capacity = 0;
	size_t outs_remaining = 0;
	char *outs_tmp = NULL;

#if 0
	if(iconv_decode_handle == (iconv_t) -1) {
		handle = iconv_open("UTF-8", "UTF-16LE");
		if(iconv_decode_handle == (iconv_t) -1) {
			err = errno;
			goto out;
		}
	}
#endif

#ifndef _WIN32
	handle = iconv_open("UTF-8", "UTF-16LE");
	if(handle == (iconv_t) -1) {
		err = errno;
		goto out;
	}
#endif

	if(!*outs) {
		/* Allocate a worst-case string, which is 3 times the number of
		 * characters of the UTF-16LE string times 4 to account for
		 * possible NFD decomposition (+1 for the NULL terminator). */
		outs_capacity = ins_len * (3 * 4) + 1;
		err = sys_malloc(outs_capacity, &outs_tmp);
		if(err) {
			err = errno;
			goto out;
		}

		*outs = outs_tmp;
		outs_remaining = outs_capacity;
	}
	else {
		outs_tmp = *outs;
		outs_remaining = *outs_len;
	}

	ins_remaining = ins_len * sizeof(refschar);

#ifdef _WIN32
	res = WideCharToMultiByte(
		CP_UTF8,
		0,
		ins,
		ins_len,
		outs_tmp,
		outs_remaining,
		NULL,
		NULL);
	if(res <= 0) {
		err = EILSEQ;
		goto out;
	}

	ins_remaining = 0; /* No way of getting this info, so assume all was read. */
	outs_tmp = &outs_tmp[res];
	outs_remaining -= (unsigned int) res;
#else
	if(iconv(
		/* iconv_t cd */
		handle,
		/* const char **restrict inbuf */
		&ins_tmp,
		/* size_t *restrict inbytesleft */
		&ins_remaining,
		/* char **restrict outbuf */
		&outs_tmp,
		/* size_t *restrict outbytesleft */
		&outs_remaining) == (size_t) -1)
	{
		err = errno;
		goto out;
	}
#endif

	if(ins_remaining || (outs_capacity && !outs_remaining)) {
		/* There should be remaining capacity for a NULL terminator
		 * given our worst case allocation. */
		sys_log_critical("Unexpected: Incomplete decoding with no "
			"error (remaining input bytes: %" PRIuz " remaining "
			"output bytes: %" PRIuz ").",
			PRAuz(ins_remaining), PRAuz(outs_remaining));
		err = ENXIO;
		goto out;
	}

	*outs_len = (size_t) outs_tmp - (size_t) *outs;
	(*outs)[*outs_len - (outs_remaining ? 0 : 1)] = '\0';
out:
	if(outs_capacity && outs_tmp) {
		if(!err && *outs_len + 1 < outs_capacity) {
			/* Shrink *outs to actual length. */
			outs_tmp = NULL;
			err = sys_realloc(*outs, outs_capacity, *outs_len + 1,
				&outs_tmp);
			if(!err) {
				*outs = outs_tmp;
			}
		}

		if(err) {
			sys_free(outs_capacity * sizeof((*outs)[0]), outs);
		}
	}

#ifndef _WIN32
	if(handle != (iconv_t) -1) {
		iconv_close(handle);
	}
#endif

	return err;
}

int sys_unistr_encode(const char *const ins, const size_t ins_len,
		refschar **outs, size_t *outs_len)
{
	int err = 0;
#ifdef _WIN32
	int res = 0;
#else
	iconv_t handle = (iconv_t) -1;
#endif
#if defined(__illumos__)
	const char *ins_tmp = ins;
#elif !defined(_WIN32)
	char *ins_tmp = (char*) ins;
#endif
	size_t ins_remaining = ins_len;
	size_t outs_capacity = 0;
	size_t outs_remaining = 0;
	refschar *outs_tmp = NULL;

#ifndef _WIN32
	handle = iconv_open("UTF-16LE", "UTF-8");
	if(handle == (iconv_t) -1) {
		err = errno;
		goto out;
	}
#endif

	if(!*outs) {
		/* Allocate a worst-case string, which is 3 times the number of
		 * characters of the UTF-16LE string times 4 to account for
		 * possible NFD decomposition (+1 for the NULL terminator). */
		outs_capacity = (ins_len * 4 + 1) * sizeof(refschar);
		err = sys_malloc(outs_capacity, &outs_tmp);
		if(err) {
			err = errno;
			goto out;
		}

		*outs = outs_tmp;
		outs_remaining = outs_capacity;
	}
	else {
		outs_tmp = *outs;
		outs_remaining = *outs_len * sizeof(refschar);
	}

#ifdef _WIN32
	res = MultiByteToWideChar(
		CP_UTF8,
		MB_PRECOMPOSED,
		ins,
		ins_len,
		outs_tmp,
		(int) (outs_remaining / sizeof(refschar)));
	if(res <= 0) {
		err = EILSEQ;
		goto out;
	}

	ins_remaining = 0; /* No way of getting this info, so assume all was read. */
	outs_tmp = &outs_tmp[res];
	outs_remaining -= (unsigned int) res;
#else
	if(iconv(
		/* iconv_t cd */
		handle,
		/* const char **restrict inbuf */
		&ins_tmp,
		/* size_t *restrict inbytesleft */
		&ins_remaining,
		/* char **restrict outbuf */
		(char**) &outs_tmp,
		/* size_t *restrict outbytesleft */
		&outs_remaining) == (size_t) -1)
	{
		err = errno;
		goto out;
	}
#endif

	if(ins_remaining || (outs_capacity && !outs_remaining)) {
		/* There should be remaining capacity for a NULL terminator
		 * given our worst case allocation. */
		sys_log_critical("Unexpected: Incomplete encoding with no "
			"error (remaining input bytes: %" PRIuz " remaining "
			"output bytes: %" PRIuz ").",
			PRAuz(ins_remaining), PRAuz(outs_remaining));
		abort();
		err = ENXIO;
		goto out;
	}

	*outs_len = ((size_t) outs_tmp - (size_t) *outs) / sizeof(refschar);
	(*outs)[*outs_len - (outs_remaining > 1 ? 0 : 1)] = cpu_to_le16('\0');
out:
	if(outs_capacity && outs_tmp) {
		if(!err && (*outs_len + 1) * sizeof(refschar) < outs_capacity) {
			/* Shrink *outs to actual length. */
			outs_tmp = NULL;
			err = sys_realloc(*outs,
				outs_capacity * sizeof(refschar),
				(*outs_len + 1) * sizeof(refschar), &outs_tmp);
			if(!err) {
				*outs = outs_tmp;
			}
		}

		if(err) {
			sys_free(outs_capacity * sizeof((*outs)[0]), outs);
		}
	}

#ifndef _WIN32
	if(handle != (iconv_t) -1) {
		iconv_close(handle);
	}
#endif

	return err;
}
