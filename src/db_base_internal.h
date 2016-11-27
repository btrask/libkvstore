#include "db_base.h"

#ifndef DB_DYNAMIC

#define DB_FN
#define DB_BASE_V0(name)

#else // DB_DYNAMIC

#define DB_FN static
#define DB_BASE_V0(name) \
DB_base const db_base_##name[1] = {{ \
	.version = 0, \
	\
	.env_create = db__env_create, \
	.env_config = db__env_config, \
	.env_open = db__env_open, \
	.env_close = db__env_close, \
	\
	.txn_begin = db__txn_begin, \
	.txn_commit = db__txn_commit, \
	.txn_abort = db__txn_abort, \
	.txn_reset = db__txn_reset, \
	.txn_renew = db__txn_renew, \
	.txn_get_flags = db__txn_get_flags, \
	.txn_cmp = db__txn_cmp, \
	.txn_cursor = db__txn_cursor, \
	\
	.get = db__get, \
	.put = db__put, \
	.del = db__del, \
	.cmd = db__cmd, \
	\
	.cursor_open = db__cursor_open, \
	.cursor_close = db__cursor_close, \
	.cursor_reset = db__cursor_reset, \
	.cursor_renew = db__cursor_renew, \
	.cursor_clear = db__cursor_clear, \
	.cursor_cmp = db__cursor_cmp, \
	\
	.cursor_current = db__cursor_current, \
	.cursor_seek = db__cursor_seek, \
	.cursor_first = db__cursor_first, \
	.cursor_next = db__cursor_next, \
	\
	.cursor_put = db__cursor_put, \
	.cursor_del = db__cursor_del, \
}};

typedef struct {
	unsigned version;

	// V0 methods
	int (*env_create)(DB_env **const out);
	int (*env_config)(DB_env *const env, DB_cfg const type, void *data);
	int (*env_open)(DB_env *const env, char const *const name, unsigned const flags, unsigned const mode);
	void (*env_close)(DB_env *const env);

	int (*txn_begin)(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn **const out);
	int (*txn_commit)(DB_txn *const txn);
	void (*txn_abort)(DB_txn *const txn);
	void (*txn_reset)(DB_txn *const txn);
	int (*txn_renew)(DB_txn *const txn);
	int (*txn_get_flags)(DB_txn *const txn, unsigned *const flags);
	int (*txn_cmp)(DB_txn *const txn, DB_val const *const a, DB_val const *const b);
	int (*txn_cursor)(DB_txn *const txn, DB_cursor **const out);

	int (*get)(DB_txn *const txn, DB_val *const key, DB_val *const data);
	int (*put)(DB_txn *const txn, DB_val *const key, DB_val *const data, unsigned const flags);
	int (*del)(DB_txn *const txn, DB_val *const key, unsigned const flags);
	int (*cmd)(DB_txn *const txn, unsigned char const *const buf, size_t const len);

	int (*cursor_open)(DB_txn *const txn, DB_cursor **const out);
	void (*cursor_close)(DB_cursor *const cursor);
	void (*cursor_reset)(DB_cursor *const cursor);
	int (*cursor_renew)(DB_txn *const txn, DB_cursor **const out);
	int (*cursor_clear)(DB_cursor *const cursor);
	int (*cursor_cmp)(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b);

	int (*cursor_current)(DB_cursor *const cursor, DB_val *const key, DB_val *const data);
	int (*cursor_seek)(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir);
	int (*cursor_first)(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir);
	int (*cursor_next)(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir);

	int (*cursor_put)(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags);
	int (*cursor_del)(DB_cursor *const cursor, unsigned const flags);
} DB_base;

extern DB_base const *const db_base_default;
extern DB_base const db_base_mdb[1];
extern DB_base const db_base_leveldb[1];
extern DB_base const db_base_rocksdb[1];
extern DB_base const db_base_hyper[1];
extern DB_base const db_base_lsmdb[1];

#endif // DB_DYNAMIC

