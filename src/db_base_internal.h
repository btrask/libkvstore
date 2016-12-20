// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#ifndef KVSTORE_DB_BASE_INTERNAL_H
#define KVSTORE_DB_BASE_INTERNAL_H

#include "db_base.h"

#define DB_FN static
#define DB_BASE_V0(_name) \
DB_base const db_base_##_name[1] = {{ \
	.version = 0, \
	.name = #_name, \
	\
	.env_size = db__env_size, \
	.env_init = db__env_init, \
	.env_get_config = db__env_get_config, \
	.env_set_config = db__env_set_config, \
	.env_open0 = db__env_open0, \
	.env_destroy = db__env_destroy, \
	\
	.txn_size = db__txn_size, \
	.txn_begin_init = db__txn_begin_init, \
	.txn_commit_destroy = db__txn_commit_destroy, \
	.txn_abort_destroy = db__txn_abort_destroy, \
	.txn_upgrade = db__txn_upgrade, \
	.txn_env = db__txn_env, \
	.txn_parent = db__txn_parent, \
	.txn_get_flags = db__txn_get_flags, \
	.txn_cmp = db__txn_cmp, \
	.txn_cursor = db__txn_cursor, \
	\
	.get = db__get, \
	.put = db__put, \
	.del = db__del, \
	.cmd = db__cmd, \
	\
	.countr = db__countr, \
	.delr = db__delr, \
	\
	.cursor_size = db__cursor_size, \
	.cursor_init = db__cursor_init, \
	.cursor_destroy = db__cursor_destroy, \
	.cursor_clear = db__cursor_clear, \
	.cursor_txn = db__cursor_txn, \
	.cursor_cmp = db__cursor_cmp, \
	\
	.cursor_current = db__cursor_current, \
	.cursor_seek = db__cursor_seek, \
	.cursor_first = db__cursor_first, \
	.cursor_next = db__cursor_next, \
	\
	.cursor_seekr = db__cursor_seekr, \
	.cursor_firstr = db__cursor_firstr, \
	.cursor_nextr = db__cursor_nextr, \
	\
	.cursor_put = db__cursor_put, \
	.cursor_del = db__cursor_del, \
}};

struct DB_base {
	unsigned version;
	char const *name; // For debugging and introspection.

	// V0 methods
	size_t (*env_size)(void);
	int (*env_init)(DB_env *const env);
	int (*env_get_config)(DB_env *const env, unsigned const type, void *data);
	int (*env_set_config)(DB_env *const env, unsigned const type, void *data);
	int (*env_open0)(DB_env *const env);
	void (*env_destroy)(DB_env *const env);

	size_t (*txn_size)(DB_env *const env);
	int (*txn_begin_init)(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn *const txn);
	int (*txn_commit_destroy)(DB_txn *const txn);
	void (*txn_abort_destroy)(DB_txn *const txn);
	int (*txn_upgrade)(DB_txn *const txn, unsigned const flags);
	int (*txn_env)(DB_txn *const txn, DB_env **const out);
	int (*txn_parent)(DB_txn *const txn, DB_txn **const out);
	int (*txn_get_flags)(DB_txn *const txn, unsigned *const flags);
	int (*txn_cmp)(DB_txn *const txn, DB_val const *const a, DB_val const *const b);
	int (*txn_cursor)(DB_txn *const txn, DB_cursor **const out);

	int (*get)(DB_txn *const txn, DB_val const *const key, DB_val *const data);
	int (*put)(DB_txn *const txn, DB_val const *const key, DB_val *const data, unsigned const flags);
	int (*del)(DB_txn *const txn, DB_val const *const key, unsigned const flags);
	int (*cmd)(DB_txn *const txn, unsigned char const *const buf, size_t const len);

	int (*countr)(DB_txn *const txn, DB_range const *const range, uint64_t *const out);
	int (*delr)(DB_txn *const txn, DB_range const *const range, uint64_t *const out);

	size_t (*cursor_size)(DB_txn *const txn);
	int (*cursor_init)(DB_txn *const txn, DB_cursor *const cursor);
	void (*cursor_destroy)(DB_cursor *const cursor);
	int (*cursor_clear)(DB_cursor *const cursor);
	int (*cursor_txn)(DB_cursor *const cursor, DB_txn **const out);
	int (*cursor_cmp)(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b);

	int (*cursor_current)(DB_cursor *const cursor, DB_val *const key, DB_val *const data);
	int (*cursor_seek)(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir);
	int (*cursor_first)(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir);
	int (*cursor_next)(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir);

	int (*cursor_seekr)(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir);
	int (*cursor_firstr)(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir);
	int (*cursor_nextr)(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir);

	int (*cursor_put)(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags);
	int (*cursor_del)(DB_cursor *const cursor, unsigned const flags);
};

extern DB_base const *const db_base_default;
extern DB_base const db_base_mdb[1];
extern DB_base const db_base_leveldb[1];
extern DB_base const db_base_rocksdb[1];
extern DB_base const db_base_hyper[1];
extern DB_base const db_base_lsmdb[1];
extern DB_base const db_base_debug[1];
extern DB_base const db_base_distributed[1];

// Helper functions
// Use these to get a simple implementation in terms of other operations.

int db_helper_get(DB_txn *const txn, DB_val const *const key, DB_val *const data);
int db_helper_put(DB_txn *const txn, DB_val const *const key, DB_val *const data, unsigned const flags);
int db_helper_del(DB_txn *const txn, DB_val const *const key, unsigned const flags); // Possibly slow.

int db_helper_countr(DB_txn *const txn, DB_range const *const range, uint64_t *const out); // Very slow.
int db_helper_delr(DB_txn *const txn, DB_range const *const range, uint64_t *const out); // Very slow and can bloat transactions.

int db_helper_cursor_seekr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir);
int db_helper_cursor_firstr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir);
int db_helper_cursor_nextr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir);

#endif

