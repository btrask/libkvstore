// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#ifndef KVSTORE_KVS_BASE_CUSTOM_H
#define KVSTORE_KVS_BASE_CUSTOM_H

#include "kvs_base.h"

#define KVS_FN static
#define KVS_BASE_V0(_name) \
KVS_base const kvs_base_##_name[1] = {{ \
	.version = 0, \
	.name = #_name, \
	\
	.env_size = kvs__env_size, \
	.env_init = kvs__env_init, \
	.env_get_config = kvs__env_get_config, \
	.env_set_config = kvs__env_set_config, \
	.env_open0 = kvs__env_open0, \
	.env_destroy = kvs__env_destroy, \
	\
	.txn_size = kvs__txn_size, \
	.txn_init = kvs__txn_init, \
	.txn_get_config = kvs__txn_get_config, \
	.txn_set_config = kvs__txn_set_config, \
	.txn_begin0 = kvs__txn_begin0, \
	.txn_commit_destroy = kvs__txn_commit_destroy, \
	.txn_abort_destroy = kvs__txn_abort_destroy, \
	.txn_cmp = kvs__txn_cmp, \
	\
	.get = kvs__get, \
	.put = kvs__put, \
	.del = kvs__del, \
	.cmd = kvs__cmd, \
	\
	.countr = kvs__countr, \
	.delr = kvs__delr, \
	\
	.cursor_size = kvs__cursor_size, \
	.cursor_init = kvs__cursor_init, \
	.cursor_destroy = kvs__cursor_destroy, \
	.cursor_clear = kvs__cursor_clear, \
	.cursor_txn = kvs__cursor_txn, \
	.cursor_cmp = kvs__cursor_cmp, \
	\
	.cursor_current = kvs__cursor_current, \
	.cursor_seek = kvs__cursor_seek, \
	.cursor_first = kvs__cursor_first, \
	.cursor_next = kvs__cursor_next, \
	\
	.cursor_seekr = kvs__cursor_seekr, \
	.cursor_firstr = kvs__cursor_firstr, \
	.cursor_nextr = kvs__cursor_nextr, \
	\
	.cursor_put = kvs__cursor_put, \
	.cursor_del = kvs__cursor_del, \
}};

struct KVS_base {
	unsigned version;
	char const *name; // For debugging and introspection.

	// V0 methods
	size_t (*env_size)(void);
	int (*env_init)(KVS_env *const env);
	int (*env_get_config)(KVS_env *const env, char const *const type, void *data);
	int (*env_set_config)(KVS_env *const env, char const *const type, void *data);
	int (*env_open0)(KVS_env *const env);
	void (*env_destroy)(KVS_env *const env);

	size_t (*txn_size)(KVS_env *const env);
	int (*txn_init)(KVS_txn *const txn);
	int (*txn_get_config)(KVS_txn *const txn, char const *const type, void *data);
	int (*txn_set_config)(KVS_txn *const txn, char const *const type, void *data);
	int (*txn_begin0)(KVS_txn *const txn);
	int (*txn_commit_destroy)(KVS_txn *const txn);
	void (*txn_abort_destroy)(KVS_txn *const txn);
	int (*txn_cmp)(KVS_txn *const txn, KVS_val const *const a, KVS_val const *const b);

	int (*get)(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data);
	int (*put)(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data, unsigned const flags);
	int (*del)(KVS_txn *const txn, KVS_val const *const key, unsigned const flags);
	int (*cmd)(KVS_txn *const txn, unsigned char const *const buf, size_t const len);

	int (*countr)(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out);
	int (*delr)(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out);

	size_t (*cursor_size)(KVS_txn *const txn);
	int (*cursor_init)(KVS_txn *const txn, KVS_cursor *const cursor);
	void (*cursor_destroy)(KVS_cursor *const cursor);
	int (*cursor_clear)(KVS_cursor *const cursor);
	int (*cursor_txn)(KVS_cursor *const cursor, KVS_txn **const out);
	int (*cursor_cmp)(KVS_cursor *const cursor, KVS_val const *const a, KVS_val const *const b);

	int (*cursor_current)(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data);
	int (*cursor_seek)(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir);
	int (*cursor_first)(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir);
	int (*cursor_next)(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir);

	int (*cursor_seekr)(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir);
	int (*cursor_firstr)(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir);
	int (*cursor_nextr)(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir);

	int (*cursor_put)(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, unsigned const flags);
	int (*cursor_del)(KVS_cursor *const cursor, unsigned const flags);
};

extern KVS_base const *const kvs_base_default;
extern KVS_base const kvs_base_mdb[1];
extern KVS_base const kvs_base_leveldb[1];
extern KVS_base const kvs_base_rocksdb[1];
extern KVS_base const kvs_base_hyper[1];
extern KVS_base const kvs_base_lsmdb[1];
extern KVS_base const kvs_base_debug[1];
extern KVS_base const kvs_base_distributed[1];
extern KVS_base const kvs_base_dummy[1];
extern KVS_base const kvs_base_raft[1];

// A prefix cursor wraps a normal cursor, transparently prefixing all keys
// written to the underlying data store, and stripping all prefixes read
// from it.
extern KVS_base const kvs_base_prefix[1];
KVS_env *kvs_prefix_env_raw(KVS_env *const env);
KVS_txn *kvs_prefix_txn_raw(KVS_txn *const txn);
KVS_cursor *kvs_prefix_cursor_raw(KVS_cursor *cursor);

#endif

