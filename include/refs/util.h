/*-
 * refs_util.h - ReFS utility macros and declarations.
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

#ifndef _REFS_UTIL_H
#define _REFS_UTIL_H

#include "sys.h"

#include <time.h>

#define emit(prefix, indent, format, ...) \
	do { \
		if(print_visitor && print_visitor->print_message) { \
			char __istr[16] = { 0 }; \
			memset(__istr, '\t', ((indent) > 15) ? 15 : (indent)); \
			print_visitor->print_message(print_visitor->context, \
				"%s%s" format, \
				(prefix), __istr, ##__VA_ARGS__); \
		} \
	} while(0)

#define PRIGUID \
	"c%c%c%c%c%c%c%c-%c%c%c%c-%c%c%c%c-%c%c%c%c-%c%c%c%c%c%c%c%c%c%c%c%c"

#define _PRAGUID_hexdigit(x) \
	((((x) & 0xF) < 0xA) ? '0' + ((x) & 0xF) : ('A' + (((x) & 0xF) - 0xA)))

#define _PRAGUID_hexdigits(x) \
	_PRAGUID_hexdigit((x) >> 4), \
	_PRAGUID_hexdigit((x) >> 0)

#define PRAGUID(x) \
	_PRAGUID_hexdigits(((const u8*) &(x))[3]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[2]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[1]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[0]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[5]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[4]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[7]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[6]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[8]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[9]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[10]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[11]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[12]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[13]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[14]), \
	_PRAGUID_hexdigits(((const u8*) &(x))[15])

static inline const char* get_ctime(s64 sec)
{
	time_t sec_time = (time_t) sec;
	return asctime(gmtime(&sec_time));
}

static inline sys_bool zeroed(const void *data, size_t size)
{
	size_t i;

	for(i = 0; i < size; ++i) {
		if(((const u8*) data)[i]) {
			return SYS_FALSE;
		}
	}

	return SYS_TRUE;
}

typedef union {
	le16 value;
	u8 data[2];
} __attribute__((packed)) le16p;

typedef union {
	le32 value;
	u8 data[4];
} __attribute__((packed)) le32p;

typedef union {
	le64 value;
	u8 data[8];
} __attribute__((packed)) le64p;

static inline u16 read_le16(const void *data)
{
	return le16_to_cpup((const le16*) data);
}

static inline u32 read_le32(const void *data)
{
	return le32_to_cpup((const le32*) data);
}

static inline u64 read_le64(const void *data)
{
	return le64_to_cpup((const le64*) data);
}

static inline size_t _print_u8_hex(
		refs_node_print_visitor *const print_visitor,
		const char *const identifier,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	emit(prefix, indent, "%s @ %" PRIuz " / 0x%" PRIXz ": 0x%" PRIX8,
		identifier,
		PRAuz((uintptr_t) value - (uintptr_t) base),
		PRAXz((uintptr_t) value - (uintptr_t) base),
		PRAX8(*((const u8*) value)));
	return 1;
}

#define print_u8_hex(identifier, prefix, indent, base, value) \
	_print_u8_hex(print_visitor, (identifier), (prefix), (indent), \
		(base), (value))

static inline size_t _print_u8_dechex(
		refs_node_print_visitor *const print_visitor,
		const char *const identifier,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	emit(prefix, indent, "%s @ %" PRIuz " / 0x%" PRIXz ": %" PRIu8 " / "
		"0x%" PRIX8,
		identifier,
		PRAuz((uintptr_t) value - (uintptr_t) base),
		PRAXz((uintptr_t) value - (uintptr_t) base),
		PRAu8(*((const u8*) value)),
		PRAX8(*((const u8*) value)));
	return 1;
}

#define print_u8_dechex(identifier, prefix, indent, base, value) \
	_print_u8_dechex(print_visitor, (identifier), (prefix), (indent), \
		(base), (value))

static inline size_t _print_unknown8(
		refs_node_print_visitor *const print_visitor,
		const char *prefix,
		const size_t indent,
		const void *base,
		const u8 *value)
{
	return print_u8_dechex("Unknown8", prefix, indent, base, value);
}

#define print_unknown8(prefix, indent, base, value) \
	_print_unknown8(print_visitor, (prefix), (indent), (base), \
		(const u8*) (value))

static inline size_t _print_le16_dec(
		refs_node_print_visitor *const print_visitor,
		const char *const identifier,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	emit(prefix, indent, "%s @ %" PRIuz " / 0x%" PRIXz ": %" PRIu16,
		identifier,
		PRAuz((uintptr_t) value - (uintptr_t) base),
		PRAXz((uintptr_t) value - (uintptr_t) base),
		PRAu16(read_le16(value)));
	return 2;
}

#define print_le16_dec(identifier, prefix, indent, base, value) \
	_print_le16_dec(print_visitor, (identifier), (prefix), (indent), \
		(base), (value))

static inline size_t _print_le16_hex(
		refs_node_print_visitor *const print_visitor,
		const char *const identifier,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	emit(prefix, indent, "%s @ %" PRIuz " / 0x%" PRIXz ": 0x%" PRIX16,
		identifier,
		PRAuz((uintptr_t) value - (uintptr_t) base),
		PRAXz((uintptr_t) value - (uintptr_t) base),
		PRAX16(read_le16(value)));
	return 2;
}

#define print_le16_hex(identifier, prefix, indent, base, value) \
	_print_le16_hex(print_visitor, (identifier), (prefix), (indent), \
		(base), (value))

static inline size_t _print_le16_dechex(
		refs_node_print_visitor *const print_visitor,
		const char *const identifier,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	emit(prefix, indent, "%s @ %" PRIuz " / 0x%" PRIXz ": %" PRIu16 " / "
		"0x%" PRIX16,
		identifier,
		PRAuz((uintptr_t) value - (uintptr_t) base),
		PRAXz((uintptr_t) value - (uintptr_t) base),
		PRAu16(read_le16(value)),
		PRAX16(read_le16(value)));
	return 2;
}

#define print_le16_dechex(identifier, prefix, indent, base, value) \
	_print_le16_dechex(print_visitor, (identifier), (prefix), (indent), \
		(base), (value))

static inline size_t _print_unknown16(
		refs_node_print_visitor *const print_visitor,
		const char *prefix,
		const size_t indent,
		const void *base,
		const le16p *value)
{
	return print_le16_dechex("Unknown16", prefix, indent, base, value);
}

#define print_unknown16(prefix, indent, base, value) \
	_print_unknown16(print_visitor, (prefix), (indent), (base), \
		(const le16p*) (value))

static inline size_t _print_le32_dec(
		refs_node_print_visitor *const print_visitor,
		const char *const identifier,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	emit(prefix, indent, "%s @ %" PRIuz " / 0x%" PRIXz ": %" PRIu32,
		identifier,
		PRAuz((uintptr_t) value - (uintptr_t) base),
		PRAXz((uintptr_t) value - (uintptr_t) base),
		PRAu32(read_le32(value)));
	return 4;
}

#define print_le32_dec(identifier, prefix, indent, base, value) \
	_print_le32_dec(print_visitor, (identifier), (prefix), (indent), \
		(base), (value))

static inline size_t _print_le32_hex(
		refs_node_print_visitor *const print_visitor,
		const char *const identifier,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	emit(prefix, indent, "%s @ %" PRIuz " / 0x%" PRIXz ": 0x%" PRIX32,
		identifier,
		PRAuz((uintptr_t) value - (uintptr_t) base),
		PRAXz((uintptr_t) value - (uintptr_t) base),
		PRAX32(read_le32(value)));
	return 4;
}

#define print_le32_hex(identifier, prefix, indent, base, value) \
	_print_le32_hex(print_visitor, (identifier), (prefix), (indent), \
		(base), (value))

static inline size_t _print_le32_dechex(
		refs_node_print_visitor *const print_visitor,
		const char *const identifier,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	emit(prefix, indent, "%s @ %" PRIuz " / 0x%" PRIXz ": %" PRIu32 " / "
		"0x%" PRIX32,
		identifier,
		PRAuz((uintptr_t) value - (uintptr_t) base),
		PRAXz((uintptr_t) value - (uintptr_t) base),
		PRAu32(read_le32(value)),
		PRAX32(read_le32(value)));
	return 4;
}

#define print_le32_dechex(identifier, prefix, indent, base, value) \
	_print_le32_dechex(print_visitor, (identifier), (prefix), (indent), \
		(base), (value))

static inline size_t _print_unknown32(
		refs_node_print_visitor *const print_visitor,
		const char *prefix,
		const size_t indent,
		const void *base,
		const le32p *value)
{
	return print_le32_dechex("Unknown32", prefix, indent, base, value);
}

#define print_unknown32(prefix, indent, base, value) \
	_print_unknown32((print_visitor), (prefix), (indent), (base), \
		(const le32p*) (value))

static inline size_t _print_le64_dec(
		refs_node_print_visitor *const print_visitor,
		const char *const identifier,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	emit(prefix, indent, "%s @ %" PRIuz " / 0x%" PRIXz ": %" PRIu64,
		identifier,
		PRAuz((uintptr_t) value - (uintptr_t) base),
		PRAXz((uintptr_t) value - (uintptr_t) base),
		PRAu64(read_le64(value)));
	return 8;
}

#define print_le64_dec(identifier, prefix, indent, base, value) \
	_print_le64_dec(print_visitor, (identifier), (prefix), (indent), \
		(base), (value))

static inline size_t _print_le64_hex(
		refs_node_print_visitor *const print_visitor,
		const char *const identifier,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	emit(prefix, indent, "%s @ %" PRIuz " / 0x%" PRIXz ": 0x%" PRIX64,
		identifier,
		PRAuz((uintptr_t) value - (uintptr_t) base),
		PRAXz((uintptr_t) value - (uintptr_t) base),
		PRAX64(read_le64(value)));
	return 8;
}

#define print_le64_hex(identifier, prefix, indent, base, value) \
	_print_le64_hex(print_visitor, (identifier), (prefix), (indent), \
		(base), (value))

static inline size_t _print_le64_dechex(
		refs_node_print_visitor *const print_visitor,
		const char *const identifier,
		const char *const prefix,
		const size_t indent,
		const void *const base,
		const void *const value)
{
	emit(prefix, indent, "%s @ %" PRIuz " / 0x%" PRIXz ": %" PRIu64 " / "
		"0x%" PRIX64,
		identifier,
		PRAuz((uintptr_t) value - (uintptr_t) base),
		PRAXz((uintptr_t) value - (uintptr_t) base),
		PRAu64(read_le64(value)),
		PRAX64(read_le64(value)));
	return 8;
}

#define print_le64_dechex(identifier, prefix, indent, base, value) \
	_print_le64_dechex(print_visitor, (identifier), (prefix), (indent), \
		(base), (value))

static inline size_t _print_unknown64(
		refs_node_print_visitor *const print_visitor,
		const char *prefix,
		const size_t indent,
		const void *base,
		const le64p *value)
{
	return print_le64_dechex("Unknown64", prefix, indent, base, value);
}

#define print_unknown64(prefix, indent, base, value) \
	_print_unknown64((print_visitor), (prefix), (indent), (base), \
		(const le64p*) (value))

static inline char makeprintable(const char c)
{
	return (c < 0x20 || c >= 0x7F) ? '.' : c;
}

static inline char hex2char(const char c)
{
	return ((c >= 0xA) ? 'A' + (c - 0xA) : '0' + c) ;
}

static void _print_data_with_base(
		refs_node_print_visitor *const print_visitor,
		const char *const prefix,
		const size_t indent,
		const size_t base,
		const size_t maxvalue,
		const u8 *const data,
		const size_t size)
{
	static const char spaces[17] = "                ";
	const size_t i_end = base + size;
	const u8 max_hex_digits =
		(u8) ((sys_fls64(!maxvalue ? i_end : maxvalue) + 3) / 4);

	size_t remaining_size = size;
	size_t i = 0;
	size_t id_run = 0;
	char id[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	while(remaining_size) {
		const size_t true_i = base + i;
		const size_t i_offset = true_i % 8;
		const size_t i_base = true_i - i_offset;
		const size_t remaining_size_in_run =
			sys_min(8 - i_offset, remaining_size);
		const sys_bool is_id =
			(remaining_size_in_run < 8 ||
			memcmp(&data[i], id, 8) ? SYS_FALSE : SYS_TRUE);
		const u8 *const data_run = &data[i - i_offset];

		if(id_run && remaining_size > 8 && is_id) {
			++id_run;
			i += remaining_size_in_run;
			remaining_size -= remaining_size_in_run;
			continue;
		}
		else if(id_run) {
			if(id_run > 2) {
				emit(prefix, indent, "%.*s   ...",
					max_hex_digits,
					spaces);
			}

			if(!is_id && id_run > 1) {
				emit(prefix, indent, "%*" PRIXz " | "
					"%" PRI0PAD(2) PRIX8 " "
					"%" PRI0PAD(2) PRIX8 " "
					"%" PRI0PAD(2) PRIX8 " "
					"%" PRI0PAD(2) PRIX8 " "
					"%" PRI0PAD(2) PRIX8 " "
					"%" PRI0PAD(2) PRIX8 " "
					"%" PRI0PAD(2) PRIX8 " "
					"%" PRI0PAD(2) PRIX8 " | "
					"%c%c%c%c%c%c%c%c",
					max_hex_digits,
					PRAXz(i_base - 8),
					PRAX8(id[0]),
					PRAX8(id[1]),
					PRAX8(id[2]),
					PRAX8(id[3]),
					PRAX8(id[4]),
					PRAX8(id[5]),
					PRAX8(id[6]),
					PRAX8(id[7]),
					makeprintable(id[0]),
					makeprintable(id[1]),
					makeprintable(id[2]),
					makeprintable(id[3]),
					makeprintable(id[4]),
					makeprintable(id[5]),
					makeprintable(id[6]),
					makeprintable(id[7]));
			}

			id_run = 0;
		}

		emit(prefix, indent, "%*" PRIXz " | %c%c %c%c %c%c %c%c "
			"%c%c %c%c %c%c %c%c | %c%c%c%c%c%c%c%c",
			max_hex_digits,
			PRAXz(i_base),
			(((i_base + 0) < true_i) || ((i_base + 0) >= i_end)) ?
				' ' : hex2char((data_run[0] >> 4) & 0xF),
			(((i_base + 0) < true_i) || ((i_base + 0) >= i_end)) ?
				' ' : hex2char(data_run[0] & 0xF),
			(((i_base + 1) < true_i) || ((i_base + 1) >= i_end)) ?
				' ' : hex2char((data_run[1] >> 4) & 0xF),
			(((i_base + 1) < true_i) || ((i_base + 1) >= i_end)) ?
				' ' : hex2char(data_run[1] & 0xF),
			(((i_base + 2) < true_i) || ((i_base + 2) >= i_end)) ?
				' ' : hex2char((data_run[2] >> 4) & 0xF),
			(((i_base + 2) < true_i) || ((i_base + 2) >= i_end)) ?
				' ' : hex2char(data_run[2] & 0xF),
			(((i_base + 3) < true_i) || ((i_base + 3) >= i_end)) ?
				' ' : hex2char((data_run[3] >> 4) & 0xF),
			(((i_base + 3) < true_i) || ((i_base + 3) >= i_end)) ?
				' ' : hex2char(data_run[3] & 0xF),
			(((i_base + 4) < true_i) || ((i_base + 4) >= i_end)) ?
				' ' : hex2char((data_run[4] >> 4) & 0xF),
			(((i_base + 4) < true_i) || ((i_base + 4) >= i_end)) ?
				' ' : hex2char(data_run[4] & 0xF),
			(((i_base + 5) < true_i) || ((i_base + 5) >= i_end)) ?
				' ' : hex2char((data_run[5] >> 4) & 0xF),
			(((i_base + 5) < true_i) || ((i_base + 5) >= i_end)) ?
				' ' : hex2char(data_run[5] & 0xF),
			(((i_base + 6) < true_i) || ((i_base + 6) >= i_end)) ?
				' ' : hex2char((data_run[6] >> 4) & 0xF),
			(((i_base + 6) < true_i) || ((i_base + 6) >= i_end)) ?
				' ' : hex2char(data_run[6] & 0xF),
			(((i_base + 7) < true_i) || ((i_base + 7) >= i_end)) ?
				' ' : hex2char((data_run[7] >> 4) & 0xF),
			(((i_base + 7) < true_i) || ((i_base + 7) >= i_end)) ?
				' ' : hex2char(data_run[7] & 0xF),
			(((i_base + 0) < true_i) || ((i_base + 0) >= i_end)) ?
				' ' : makeprintable(data_run[0]),
			(((i_base + 1) < true_i) || ((i_base + 1) >= i_end)) ?
				' ' : makeprintable(data_run[1]),
			(((i_base + 2) < true_i) || ((i_base + 2) >= i_end)) ?
				' ' : makeprintable(data_run[2]),
			(((i_base + 3) < true_i) || ((i_base + 3) >= i_end)) ?
				' ' : makeprintable(data_run[3]),
			(((i_base + 4) < true_i) || ((i_base + 4) >= i_end)) ?
				' ' : makeprintable(data_run[4]),
			(((i_base + 5) < true_i) || ((i_base + 5) >= i_end)) ?
				' ' : makeprintable(data_run[5]),
			(((i_base + 6) < true_i) || ((i_base + 6) >= i_end)) ?
				' ' : makeprintable(data_run[6]),
			(((i_base + 7) < true_i) || ((i_base + 7) >= i_end)) ?
				' ' : makeprintable(data_run[7]));
		if(is_id) {
			id_run = 1;
		}
		else if(remaining_size_in_run) {
			memcpy(&id[i_offset], &data[i],
				remaining_size_in_run);
		}

		i += remaining_size_in_run;
		
		remaining_size -= remaining_size_in_run;
	}
}

#define print_data_with_base(prefix, indent, base, maxvalue, data, size) \
	do { \
		if(print_visitor && print_visitor->print_message) { \
			_print_data_with_base(print_visitor, (prefix), \
				(indent), (base), (maxvalue), (data), (size)); \
		} \
	} while(0)

static inline void _print_data(
		refs_node_print_visitor *const print_visitor,
		const char *const prefix,
		const size_t indent,
		const u8 *const data,
		const size_t size)
{
	print_data_with_base(prefix, indent, 0, 0, data, size);
}

#define print_data(prefix, indent, data, size) \
	do { \
		if(print_visitor && print_visitor->print_message) { \
			_print_data(print_visitor, (prefix), (indent), (data), \
				(size)); \
		} \
	} while(0)

static inline void _print_filetime(
		refs_node_print_visitor *const print_visitor,
		const char *prefix,
		const size_t indent,
		const char *identifier,
		s64 filetime)
{
	static const s64 filetime_offset =
		((s64) (369 * 365 + 89)) * 24 * 3600 * 10000000;

	const s64 time_sec = (filetime - filetime_offset) / 10000000;
	const s32 time_100nsec = (filetime - filetime_offset) % 10000000;
	const char *ctime_string = get_ctime(time_sec);

	if(!ctime_string) {
		emit(prefix, indent, "%s: <invalid timestamp> (%" PRId64 ")",
			identifier,
			PRAd64(filetime));
	}
	else if(print_visitor->verbose) {
		emit(prefix, indent, "%s: %" PRIbs ".%" PRI0PAD(7) PRId64
			"%" PRIbs " (%" PRId64 ")",
			identifier,
			PRAbs(19, ctime_string),
			PRAd64(time_100nsec),
			PRAbs(5, &ctime_string[19]),
			PRAd64(filetime));
	}
	else {
		emit(prefix, indent, "%s: %" PRIbs ".%" PRI0PAD(7) PRId64
			"%" PRIbs,
			identifier,
			PRAbs(19, ctime_string),
			PRAd64(time_100nsec),
			PRAbs(5, &ctime_string[19]));
	}
}

#define print_filetime(...) \
	do { \
		if(print_visitor && print_visitor->print_message) { \
			_print_filetime(print_visitor, __VA_ARGS__); \
		} \
	} while(0)

#endif /* !defined(_REFS_UTIL_H) */
