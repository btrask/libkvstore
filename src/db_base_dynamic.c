// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
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

int db_env_create(DB_env **const out) {
	if(!db_base_default) return DB_PANIC;
	return db_base_default->env_create(out);
}
int db_env_set_mapsize(DB_env *const env, size_t const size) {
	if(!env) return DB_EINVAL;
	return env->isa->env_set_mapsize(env, size);
}
int db_env_open(DB_env *const env, char const *const name, unsigned const flags, unsigned const mode) {
	if(!env) return DB_EINVAL;
	return env->isa->env_open(env, name, flags, mode);
}
void db_env_close(DB_env *const env) {
	if(!env) return;
	env->isa->env_close(env);
}

int db_txn_begin(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn **const out) {
	if(!env) return DB_EINVAL;
	return env->isa->txn_begin(env, parent, flags, out);
}
int db_txn_commit(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	return txn->isa->txn_commit(txn);
}
void db_txn_abort(DB_txn *const txn) {
	if(!txn) return;
	txn->isa->txn_abort(txn);
}
void db_txn_reset(DB_txn *const txn) {
	if(!txn) return;
	txn->isa->txn_reset(txn);
}
int db_txn_renew(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	return txn->isa->txn_renew(txn);
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

int db_cursor_open(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	return txn->isa->cursor_open(txn, out);
}
void db_cursor_close(DB_cursor *const cursor) {
	if(!cursor) return;
	cursor->isa->cursor_close(cursor);
}
void db_cursor_reset(DB_cursor *const cursor) {
	if(!cursor) return;
	cursor->isa->cursor_reset(cursor);
}
int db_cursor_renew(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	return txn->isa->cursor_renew(txn, out);
}
int db_cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_clear(cursor);
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

int db_cursor_put(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_put(cursor, key, data, flags);
}
int db_cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	return cursor->isa->cursor_del(cursor, flags);
}

