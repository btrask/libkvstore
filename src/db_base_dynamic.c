// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <string.h>
#include "db_base_internal.h"

DB_base const *const db_base_default = (DB_BASE_DEFAULT);

struct DB_env {
	DB_base const *isa;
};
struct DB_txn {
	DB_base const *isa;
};
struct DB_cursor {
	DB_base const *isa;
};

DB_base const *db_base_find(char const *const name) {
	if(!name) return db_base_default;
	DB_base const *base = db_base_default;
	if(0 == strcmp(name, "default")) base = db_base_default;
	if(0 == strcmp(name, "mdb")) base = db_base_mdb;
	if(0 == strcmp(name, "leveldb")) base = db_base_leveldb;
#ifdef DB_BASE_ROCKSDB
	if(0 == strcmp(name, "rocksdb")) base = db_base_rocksdb;
#endif
//	if(0 == strcmp(name, "hyper")) base = db_base_hyper;
//	if(0 == strcmp(name, "lsmdb")) base = db_base_lsmdb;
	if(0 == strcmp(name, "debug")) base = db_base_debug;
//	if(0 == strcmp(name, "distributed")) base = db_base_distributed;
	return base;
}

int db_env_init_base(char const *const basename, DB_env *const env) {
	return db_env_init_custom(db_base_find(basename), env);
}
int db_env_create_base(char const *const basename, DB_env **const out) {
	return db_env_create_custom(db_base_find(basename), out);
}
int db_env_init_custom(DB_base const *const base, DB_env *const env) {
	if(!base) return DB_EINVAL;
	int rc = base->env_init(env);
	if(rc < 0) return rc;
	assert(env->isa);

	// Set standard settings to ensure as much uniformity as possible.
	unsigned flags = 0; // Synchronous, read-write
	int mode = 0600;
	db_env_set_config(env, DB_CFG_FLAGS, &flags);
	db_env_set_config(env, DB_CFG_FILEMODE, &mode);
	return 0;
}
int db_env_create_custom(DB_base const *const base, DB_env **const out) {
	if(!base) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	DB_env *env = calloc(1, db_env_size(base));
	if(!env) return DB_ENOMEM;
	int rc = db_env_init_custom(base, env);
	if(rc < 0) return rc;
	*out = env; env = NULL;
	return 0;
}

size_t db_env_size(DB_base const *const base) {
	assert(base);
	return base->env_size();
}
int db_env_init(DB_env *const env) {
	if(!db_base_default) return DB_PANIC;
	return db_env_init_custom(db_base_default, env);
}
int db_env_create(DB_env **const out) {
	if(!db_base_default) return DB_PANIC;
	return db_env_create_custom(db_base_default, out);
}
int db_env_get_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	return env->isa->env_get_config(env, type, data);
}
int db_env_set_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	return env->isa->env_set_config(env, type, data);
}
int db_env_open0(DB_env *const env) {
	if(!env) return DB_EINVAL;
	return env->isa->env_open0(env);
}
int db_env_open(DB_env *const env, char const *const name, unsigned flags, int mode) {
	if(!env) return DB_EINVAL;
	db_env_set_config(env, DB_CFG_FILENAME, (char *)name);
	db_env_set_config(env, DB_CFG_FLAGS, &flags);
	db_env_set_config(env, DB_CFG_FILEMODE, &mode);
	return db_env_open0(env);
}
DB_base const *db_env_base(DB_env *const env) {
	if(!env) return NULL;
	return env->isa;
}
void db_env_destroy(DB_env *const env) {
	if(!env) return;
	env->isa->env_destroy(env);
}
void db_env_close(DB_env *env) {
	if(!env) return;
	db_env_destroy(env);
	free(env); env = NULL;
}

size_t db_txn_size(DB_base const *const base) {
	assert(base);
	return base->txn_size();
}
int db_txn_begin_init(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn *const txn) {
	if(!env) return DB_EINVAL;
	int rc = env->isa->txn_begin_init(env, parent, flags, txn);
	if(rc < 0) return rc;
	assert(txn->isa);
	return 0;
}
int db_txn_begin(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn **const out) {
	if(!env) return DB_EINVAL;
	DB_txn *txn = calloc(1, db_txn_size(env->isa));
	if(!txn) return DB_ENOMEM;
	int rc = db_txn_begin_init(env, parent, flags, txn);
	if(rc < 0) goto cleanup;
	*out = txn; txn = NULL;
cleanup:
	free(txn); txn = NULL;
	return rc;
}
int db_txn_commit_destroy(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	int rc = txn->isa->txn_commit_destroy(txn);
	return rc;
}
int db_txn_commit(DB_txn *txn) {
	if(!txn) return DB_EINVAL;
	int rc = db_txn_commit_destroy(txn);
	free(txn); txn = NULL;
	return rc;
}
void db_txn_abort_destroy(DB_txn *const txn) {
	if(!txn) return;
	txn->isa->txn_abort_destroy(txn);
}
void db_txn_abort(DB_txn *txn) {
	if(!txn) return;
	db_txn_abort_destroy(txn);
	free(txn); txn = NULL;
}
int db_txn_upgrade(DB_txn *const txn, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	return txn->isa->txn_upgrade(txn, flags);
}
int db_txn_env(DB_txn *const txn, DB_env **const out) {
	if(!txn) return DB_EINVAL;
	return txn->isa->txn_env(txn, out);
}
int db_txn_parent(DB_txn *const txn, DB_txn **const out) {
	if(!txn) return DB_EINVAL;
	return txn->isa->txn_parent(txn, out);
}
int db_txn_get_flags(DB_txn *const txn, unsigned *const flags) {
	if(!txn) return DB_EINVAL;
	return txn->isa->txn_get_flags(txn, flags);
}
int db_txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	assert(txn); // Can't return errors.
	return txn->isa->txn_cmp(txn, a, b);
}
int db_txn_cursor(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	return txn->isa->txn_cursor(txn, out);
}

int db_get(DB_txn *const txn, DB_val *const key, DB_val *const data) {
	if(!txn) return DB_EINVAL;
	return txn->isa->get(txn, key, data);
}
int db_put(DB_txn *const txn, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	return txn->isa->put(txn, key, data, flags);
}
int db_del(DB_txn *const txn, DB_val *const key, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	return txn->isa->del(txn, key, flags);
}
int db_cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len) {
	if(!txn) return DB_EINVAL;
	return txn->isa->cmd(txn, buf, len);
}

int db_countr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	if(!txn) return DB_EINVAL;
	return txn->isa->countr(txn, range, out);
}
int db_delr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	if(!txn) return DB_EINVAL;
	return txn->isa->delr(txn, range, out);
}

size_t db_cursor_size(DB_base const *const base) {
	assert(base);
	return base->cursor_size();
}
int db_cursor_init(DB_txn *const txn, DB_cursor *const cursor) {
	if(!txn) return DB_EINVAL;
	int rc = txn->isa->cursor_init(txn, cursor);
	if(rc < 0) return rc;
	assert(cursor->isa);
	return 0;
}
int db_cursor_open(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	DB_cursor *cursor = calloc(1, db_cursor_size(txn->isa));
	if(!cursor) return DB_ENOMEM;
	int rc = db_cursor_init(txn, cursor);
	if(rc < 0) goto cleanup;
	*out = cursor; cursor = NULL;
cleanup:
	free(cursor); cursor = NULL;
	return rc;
}
void db_cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	cursor->isa->cursor_destroy(cursor);
}
void db_cursor_close(DB_cursor *cursor) {
	if(!cursor) return;
	db_cursor_destroy(cursor);
	free(cursor); cursor = NULL;
}
int db_cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_clear(cursor);
}
int db_cursor_txn(DB_cursor *const cursor, DB_txn **const out) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_txn(cursor, out);
}
int db_cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	assert(cursor); // Can't return errors.
	return cursor->isa->cursor_cmp(cursor, a, b);
}

int db_cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_current(cursor, key, data);
}
int db_cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_seek(cursor, key, data, dir);
}
int db_cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_first(cursor, key, data, dir);
}
int db_cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_next(cursor, key, data, dir);
}

int db_cursor_seekr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_seekr(cursor, range, key, data, dir);
}
int db_cursor_firstr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_firstr(cursor, range, key, data, dir);
}
int db_cursor_nextr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_nextr(cursor, range, key, data, dir);
}

int db_cursor_put(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_put(cursor, key, data, flags);
}
int db_cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_del(cursor, flags);
}

