// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#ifndef KVSTORE_KVS_SCHEMA_H
#define KVSTORE_KVS_SCHEMA_H

#include <stdint.h>
#include "kvs_base.h"

#ifndef NDEBUG
#define kvs_assert(x) assert(x)
#define kvs_assertf(x, y, z...) assertf(x, y, ##z)
#else
#error "Database assertions not configured for NDEBUG" // TODO
#endif

// "Blind write" support. There shouldn't be a collision
// but in some cases we don't want to pay for the lookup.
#if 0
#define KVS_NOOVERWRITE_FAST KVS_NOOVERWRITE
#else
#define KVS_NOOVERWRITE_FAST 0
#endif

// FASTHIT expects a collision and pays the read to avoid the write.
// FASTMISS expects a miss and always writes to avoid the read.
#define KVS_NOOVERWRITE_FASTHIT KVS_NOOVERWRITE
#define KVS_NOOVERWRITE_FASTMISS KVS_NOOVERWRITE_FAST

#define KVS_VAL_STORAGE(val, len) \
	uint8_t __buf_##val[(len)]; \
	*(val) = (KVS_val){ 0, __buf_##val };
#define KVS_RANGE_STORAGE(range, len) \
	uint8_t __buf_min_##range[(len)]; \
	uint8_t __buf_max_##range[(len)]; \
	*(range)->min = (KVS_val){ 0, __buf_min_##range }; \
	*(range)->max = (KVS_val){ 0, __buf_max_##range };

// TODO: These checks are better than nothing, but they're far from ideal.
// We can calculate the storage needed at compile-time, so we shouldn't need
// to hardcode+verify at all. Just generate the right answer and use that.
// We could also count the theoretical storage needed at runtime and verify
// that. Probably by adding an in/out counter to kvs_bind_*.
#define KVS_VAL_STORAGE_VERIFY(val) \
	assert((val)->size <= sizeof(__buf_##val))
#define KVS_RANGE_STORAGE_VERIFY(range) do { \
	assert((range)->min->size <= sizeof(__buf_min_##range)); \
	assert((range)->max->size <= sizeof(__buf_max_##range)); \
} while(0)

typedef uint64_t dbid_t;
enum {
	// 0-19 are reserved.
	DBSchema = 0, // TODO
	DBBigString = 1,
};

int kvs_schema_verify(KVS_txn *const txn);

#define KVS_VARINT_MAX 9
uint64_t kvs_read_uint64(KVS_val *const val);
void kvs_bind_uint64(KVS_val *const val, uint64_t const x);

uint64_t kvs_next_id(dbid_t const table, KVS_txn *const txn);

#define KVS_INLINE_MAX 96
char const *kvs_read_string(KVS_val *const val, KVS_txn *const txn);
void kvs_bind_string(KVS_val *const val, char const *const str, KVS_txn *const txn);
void kvs_bind_string_len(KVS_val *const val, char const *const str, size_t const len, int const nulterm, KVS_txn *const txn);

// Blobs are fixed length and stored inline.
#define KVS_BLOB_MAX(n) (n)
unsigned char const *kvs_read_blob(KVS_val *const val, size_t const len);
void kvs_bind_blob(KVS_val *const val, unsigned char const *const buf, size_t const len);

// Increments range->min to fill in range->max.
// Assumes lexicographic ordering. Don't use it if you changed cmp functions.
void kvs_range_genmax(KVS_range *const range);

static void kvs_nullval(KVS_val *const val) {
	val->size = 0;
	val->data = NULL;
}

#endif

