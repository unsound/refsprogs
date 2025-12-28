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
	size_t outs_capacity = 0;
	size_t outs_remaining = 0;
	char *outs_tmp = NULL;
	size_t i;

	if(!outs) {
		/* This is a request for the size of the decoded string only. */
		if(outs_len) {
			*outs_len = 0;
		}
	}
	else if(!*outs) {
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

	for(i = 0; i < ins_len; ++i) {
		const u16 code_unit_1 = le16_to_cpu(ins[i]);
		u32 code_point = 0;
		u8 utf8_code_units = 0;

		if(code_unit_1 >= 0xD800U && code_unit_1 <= 0xDBFFU &&
			i + 1 < ins_len)
		{
			const u16 code_unit_2 = le16_to_cpu(ins[i + 1]);

			if(code_unit_2 >= 0xDC00U && code_unit_2 <= 0xDFFFU) {
				code_point =
					((u32) 0x10000UL) +
					(((((u32) code_unit_1) & 0x3FFU) <<
					10) | (code_unit_2 & 0x3FFU));
				++i;
			}
			else {
				code_point = code_unit_1;
			}
		}
		else {
			code_point = code_unit_1;
		}

		if(code_point <= 0x7FU) {
			utf8_code_units = 1;
		}
		else if(code_point <= 0x7FFU) {
			utf8_code_units = 2;
		}
		else if(code_point <= 0xFFFFU) {
			utf8_code_units = 3;
		}
		else if(code_point <= 0x10FFFFUL) {
			utf8_code_units = 4;
		}
		else {
			/* The UTF-16 encoding allows for at most ~20.087 bits
			 * encoded (0x100000 values in surrogates + 0x10000
			 * non-surrogate values for a maximum encoded value of
			 * 0x10000 + 0x100000 - 1 = 0x10FFFF, log2(0x10FFFF + 1)
			 * ~= 20.087) and UTF-8 can encode 21 bits in 4 bytes
			 * (though the maximum valid value is still 0x10FFFF).
			 * So this should be an impossible situation unless
			 * we've made a mistake in the implementation. */
			sys_log_critical("Invalid Unicode code point "
				"0x%" PRIX32 ". This should be impossible.",
				PRAX32(code_point));
			code_point = 0xFFFDU;
			utf8_code_units = 3;
		}

		if(outs) {
			if(outs_remaining < utf8_code_units + 1) {
				err = E2BIG;
				goto out;
			}

			if(utf8_code_units == 1) {
				outs_tmp[0] = (u8) code_point;
				outs_tmp = &outs_tmp[1];
			}
			else if(utf8_code_units == 2) {
				outs_tmp[0] = (u8) (0xC0 | (code_point >> 6));
				outs_tmp[1] = (u8) (0x80 | (code_point & 0x3F));
				outs_tmp = &outs_tmp[2];
			}
			else if(utf8_code_units == 3) {
				outs_tmp[0] = (u8) (0xE0 | (code_point >> 12));
				outs_tmp[1] = (u8) (0x80 | (code_point >> 6));
				outs_tmp[2] = (u8) (0x80 | (code_point & 0x3F));
				outs_tmp = &outs_tmp[3];
			}
			else {
				outs_tmp[0] = (u8) (0xF0 | (code_point >> 18));
				outs_tmp[1] = (u8) (0x80 | (code_point >> 12));
				outs_tmp[2] = (u8) (0x80 | (code_point >> 6));
				outs_tmp[3] = (u8) (0x80 | (code_point & 0x3F));
				outs_tmp = &outs_tmp[4];
			}

			outs_remaining -= utf8_code_units;
		}
		else if(outs_len) {
			*outs_len += utf8_code_units;
		}
	}

	if(outs) {
		const size_t length = (size_t) outs_tmp - (size_t) *outs;;
		if(outs_len) {
			*outs_len = length;
		}

		(*outs)[length - (outs_remaining ? 0 : 1)] = '\0';
	}
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
