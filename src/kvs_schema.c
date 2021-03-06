// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdbool.h>
#include <stdio.h> // DEBUG
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include "kvs_schema.h"
#include "common.h"

static size_t varint_size(uint8_t const *const data) {
	assert(data);
	return (data[0] >> 4) + 1;
}
static uint64_t varint_decode(uint8_t const *const data, size_t const size) {
	assert(data);
	assert(size >= 1);
	size_t const len = varint_size(data);
	kvs_assert(len);
	kvs_assert(size >= len);
	uint64_t x = data[0] & 0x0f;
	for(size_t i = 1; i < len; ++i) x = x << 8 | data[i];
	return x;
}
static size_t varint_encode(uint8_t *const data, size_t const size, uint64_t const x) {
	assert(data);
	assert(size >= KVS_VARINT_MAX);
	size_t rem = 8;
	size_t out = 0;
	while(rem--) {
		uint8_t const y = 0xff & (x >> (8 * rem));
		if(out) {
			data[out++] = y;
		} else if(y && y <= 0x0f) {
			data[out++] = ((rem+0) << 4) | (y & 0x0f);
		} else if(y) {
			data[out++] = ((rem+1) << 4) | 0;
			data[out++] = y;
		}
	}
	if(!out) data[out++] = 0;
	assert(varint_decode(data, size) == x);
	return out;
}
static size_t varint_seek(uint8_t const *const data, size_t const size, unsigned const col) {
	size_t pos = 0;
	for(unsigned i = 0; i < col; ++i) {
		kvs_assert(pos+1 <= size);
		pos += varint_size(data+pos);
	}
	kvs_assert(pos+1 <= size);
	return pos;
}


int kvs_schema_verify(KVS_txn *const txn) {
	char const magic[] = "DBDB schema layer v1";
	size_t const len = sizeof(magic)-1;

	KVS_val key[1];
	KVS_VAL_STORAGE(key, KVS_VARINT_MAX*2);
	kvs_bind_uint64(key, DBSchema);
	kvs_bind_uint64(key, 0);
	KVS_val val[1];

	KVS_cursor *cur;
	int rc = kvs_txn_cursor(txn, &cur);
	if(rc < 0) return rc;
	rc = kvs_cursor_first(cur, NULL, NULL, +1);
	if(rc < 0 && KVS_NOTFOUND != rc) return rc;

	// If the database is completely empty
	// we can assume it's ours to play with
	if(KVS_NOTFOUND == rc) {
		*val = (KVS_val){ len, (char *)magic };
		rc = kvs_put(txn, key, val, 0);
		if(rc < 0) return rc;
		return 0;
	}

	rc = kvs_get(txn, key, val);
	if(KVS_NOTFOUND == rc) return KVS_VERSION_MISMATCH;
	if(rc < 0) return rc;
	if(len != val->size) return KVS_VERSION_MISMATCH;
	if(0 != memcmp(val->data, magic, len)) return KVS_VERSION_MISMATCH;
	return 0;
}


// TODO: kvs_bind_* functions should accept buffer size for bounds checking

uint64_t kvs_read_uint64(KVS_val *const val) {
	kvs_assert(val->size >= 1);
	size_t const len = varint_size(val->data);
	kvs_assert(val->size >= len);
	uint64_t const x = varint_decode(val->data, val->size);
	val->data += len;
	val->size -= len;
	return x;
}
void kvs_bind_uint64(KVS_val *const val, uint64_t const x) {
	unsigned char *const out = val->data;
	size_t const len = varint_encode(out+val->size, SIZE_MAX, x);
	val->size += len;
}

uint64_t kvs_next_id(dbid_t const table, KVS_txn *const txn) {
	KVS_cursor *cur = NULL;
	if(kvs_txn_cursor(txn, &cur) < 0) return 0;
	KVS_range range[1];
	KVS_RANGE_STORAGE(range, KVS_VARINT_MAX);
	kvs_bind_uint64(range->min, table+0);
	kvs_bind_uint64(range->max, table+1);
	KVS_val prev[1];
	int rc = kvs_cursor_firstr(cur, range, prev, NULL, -1);
	if(KVS_NOTFOUND == rc) return 1;
	if(rc < 0) return 0;
	uint64_t const t = kvs_read_uint64(prev);
	kvs_assert(table == t);
	return kvs_read_uint64(prev)+1;
}


// Inline strings can be up to 96 bytes including nul. Longer strings are
// truncated at 64 bytes (including nul), followed by the 32-byte SHA-256 hash.
// The first byte of the hash may not be 0x00 (if it's 0x00, it's replaced with
// 0x01). If a string is exactly 64 bytes (including nul), it's followed by an
// extra 0x00 to indicate it wasn't truncated. A null pointer is 0x00 00, and
// an empty string is 0x00 01.
#define KVS_INLINE_TRUNC (KVS_INLINE_MAX-SHA256_DIGEST_LENGTH)

char const *kvs_read_string(KVS_val *const val, KVS_txn *const txn) {
	assert(txn);
	assert(val);
	kvs_assert(val->size >= 1);
	char const *const str = val->data;
	size_t const len = strnlen(str, MIN(val->size, KVS_INLINE_MAX));
	kvs_assert('\0' == str[len]);
	if(0 == len) {
		kvs_assert(val->size >= 2);
		val->data += 2;
		val->size -= 2;
		if(0x00 == str[1]) return NULL;
		if(0x01 == str[1]) return "";
		kvs_assertf(0, "Invalid string type %u\n", str[1]);
		return NULL;
	}
	if(KVS_INLINE_TRUNC != len+1) {
		val->data += len+1;
		val->size -= len+1;
		return str;
	}
	kvs_assert(val->size >= len+2);
	if(0x00 == str[len+1]) {
		val->data += len+2;
		val->size -= len+2;
		return str;
	}

	KVS_val key = { KVS_INLINE_MAX, (char *)str };
	KVS_val full[1];
	int rc = kvs_get(txn, &key, full);
	kvs_assertf(rc >= 0, "Database error %s", kvs_strerror(rc));
	char const *const fstr = full->data;
	kvs_assert('\0' == fstr[full->size-1]);
	val->data += KVS_INLINE_MAX;
	val->size -= KVS_INLINE_MAX;
	return fstr;
}
void kvs_bind_string(KVS_val *const val, char const *const str, KVS_txn *const txn) {
	size_t const len = str ? strlen(str) : 0;
	kvs_bind_string_len(val, str, len, true, txn);
}
void kvs_bind_string_len(KVS_val *const val, char const *const str, size_t const len, int const nulterm, KVS_txn *const txn) {
	assert(val);

	// Be careful to avoid insidious undefined behavior here.
	// strnlen() is undefined if str is null, which GCC was using
	// to skip the NULL check, causing us to store "" instead.
	assert(!str || len == strnlen(str, len));

	unsigned char *const out = val->data;
	if(0 == len) {
		out[val->size++] = '\0';
		out[val->size++] = str ? 0x01 : 0x00;
		return;
	}
	if(len < KVS_INLINE_MAX) {
		memcpy(out+val->size, str, len);
		val->size += len;
		out[val->size++] = '\0';
		if(KVS_INLINE_TRUNC != len+1) return;
		out[val->size++] = '\0';
		return;
	}

	memcpy(out+val->size, str, KVS_INLINE_TRUNC-1);
	val->size += KVS_INLINE_TRUNC-1;
	out[val->size++] = '\0';

	SHA256_CTX algo[1];
	int rc;
	rc = SHA256_Init(algo);
	kvs_assert(rc >= 0);
	rc = SHA256_Update(algo, str, len);
	kvs_assert(rc >= 0);
	rc = SHA256_Final(out+val->size, algo);
	kvs_assert(rc >= 0);
	if(0x00 == out[val->size]) out[val->size] = 0x01;
	val->size += SHA256_DIGEST_LENGTH;

	if(!txn) return;
	unsigned flags = 0;
	rc = kvs_txn_get_flags(txn, &flags);
	kvs_assertf(rc >= 0, "Database error %s", kvs_strerror(rc));
	if(flags & KVS_RDONLY) return;

	KVS_val key = { KVS_INLINE_MAX, out+val->size-KVS_INLINE_MAX };
	char *str2 = nulterm ? (char *)str : strndup(str, len);
	KVS_val full = { len+1, str2 };
	assert('\0' == str2[full.size-1]);
	rc = kvs_put(txn, &key, &full, 0);
	if(!nulterm) free(str2);
	str2 = NULL;
	kvs_assertf(rc >= 0, "Database error %s", kvs_strerror(rc));
}

unsigned char const *kvs_read_blob(KVS_val *const val, size_t const len) {
	assert(val);
	assert(val->data);
	kvs_assert(val->size >= len);
	unsigned char const *const x = val->data;
	val->data += len;
	val->size -= len;
	return x;
}
void kvs_bind_blob(KVS_val *const val, unsigned char const *const buf, size_t const len) {
	assert(val);
	assert(val->data);
	assert(buf || 0 == len);
	memcpy(val->data+val->size, buf, len);
	val->size += len;
}


void kvs_range_genmax(KVS_range *const range) {
	assert(range);
	assert(range->min);
	assert(range->max);
	unsigned char *const out = range->max->data;
	memcpy(out, range->min->data, range->min->size);
	range->max->size = range->min->size;
	size_t i = range->max->size;
	while(i--) {
		if(out[i] < 0xff) {
			out[i]++;
			return;
		} else {
			out[i] = 0;
		}
	}
	kvs_assert(!"range overflow");
	// TODO: It would be nice to represent an unbounded range maximum
	// by {0, NULL}, but our range code would probably need a lot of
	// special cases to handle it.
}

