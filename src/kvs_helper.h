// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#ifndef KVSTORE_KVS_HELPER_H
#define KVSTORE_KVS_HELPER_H

#include "kvs_base_custom.h"

// Use these to get a simple implementation, typically in terms of other operations.

typedef struct {
	KVS_env *env;
	KVS_txn *parent;
	KVS_txn *child;
	unsigned flags;
	KVS_cursor *cursor;
} KVS_helper_txn;

int kvs_helper_txn_get_config(KVS_txn *const txn, KVS_helper_txn *const helper, char const *const type, void *data);
int kvs_helper_txn_set_config(KVS_txn *const txn, KVS_helper_txn *const helper, char const *const type, void *data);
int kvs_helper_txn_commit(KVS_helper_txn *const helper); // Call first in commit_destroy
void kvs_helper_txn_abort(KVS_helper_txn *const helper); // Call first in abort_destroy

int kvs_helper_get(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data);
int kvs_helper_put(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data, unsigned const flags);
int kvs_helper_del(KVS_txn *const txn, KVS_val const *const key, unsigned const flags); // For write-optimized back-ends, implement kvs_del and use the helper for kvs_cursor_del.
int kvs_helper_cmd(KVS_txn *const txn, unsigned char const *const buf, size_t const len);

int kvs_helper_countr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out); // Very slow.
int kvs_helper_delr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out); // Very slow and can bloat transactions.

int kvs_helper_cursor_seekr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir);
int kvs_helper_cursor_firstr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir);
int kvs_helper_cursor_nextr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir);
int kvs_helper_cursor_del(KVS_cursor *const cursor, unsigned const flags);

#define KVS_HELPER_CURSOR_RANGE_FUNCS(pfx) \
KVS_FN int pfx##cursor_seekr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) { \
	return kvs_helper_cursor_seekr(cursor, range, key, data, dir); \
} \
KVS_FN int pfx##cursor_firstr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) { \
	return kvs_helper_cursor_firstr(cursor, range, key, data, dir); \
} \
KVS_FN int pfx##cursor_nextr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) { \
	return kvs_helper_cursor_nextr(cursor, range, key, data, dir); \
}

#endif

