// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include "db_base_internal.h"
#include "common.h"

// db_base_dummy.c
// There purpose of this back-end is two-fold. First is to demonstrate and
// document the minimum possible implementation, for developers wishing to
// create their own. Second is to measure the incidental complexity/overhead
// of creating a new back-end.
// For both of these reasons, this back-end tries to be as small as possible,
// taking full advantage of the provided "helpers."
// As you can see, there is still some unnecessary complexity left, especially
// in the init/destruction of transactions and cursors.

struct DB_env {
	DB_base const *isa;
	// Inner env
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
	DB_txn *child;
	DB_cursor *cursor;
	// Inner txn
};
struct DB_cursor {
	DB_base const *isa;
	DB_txn *txn;
	// Inner cursor
};
#define ENV_INNER(env) ((env)+1)
#define TXN_INNER(txn) ((txn)+1)
#define CURSOR_INNER(cursor) ((cursor)+1)

DB_FN size_t db__env_size(void) {
	return sizeof(struct DB_env)+db_env_size(db_base_default);
}
DB_FN int db__env_init(DB_env *const env) {
	if(!env) return DB_EINVAL;
	int rc = 0;
	env->isa = db_base_dummy;
	rc = db_env_init_custom(db_base_default, ENV_INNER(env));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) db_env_destroy(env);
	return 0;
}
DB_FN int db__env_get_config(DB_env *const env, char const *const type, void *data) {
	if(!env) return DB_EINVAL;
	if(!type) return DB_EINVAL;
	return db_env_get_config(ENV_INNER(env), type, data);
}
DB_FN int db__env_set_config(DB_env *const env, char const *const type, void *data) {
	if(!env) return DB_EINVAL;
	if(!type) return DB_EINVAL;
	return db_env_set_config(ENV_INNER(env), type, data);
}
DB_FN int db__env_open0(DB_env *const env) {
	if(!env) return DB_EINVAL;
	return db_env_open0(ENV_INNER(env));
}
DB_FN void db__env_destroy(DB_env *const env) {
	if(!env) return;
	db_env_destroy(ENV_INNER(env));
	env->isa = NULL;
	assert_zeroed(env, 1);
}

DB_FN size_t db__txn_size(DB_env *const env) {
	assert(env);
	return sizeof(struct DB_txn)+db_txn_size(ENV_INNER(env));
}
DB_FN int db__txn_begin_init(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn *const txn) {
	if(!env) return DB_EINVAL;
	if(!txn) return DB_EINVAL;
	if(parent && parent->child) return DB_BAD_TXN;
	assert_zeroed(txn, 1);
	int rc = 0;
	txn->isa = db_base_dummy;
	txn->env = env;
	txn->parent = parent;
	txn->child = NULL;

	rc = db_txn_begin_init(ENV_INNER(env), parent ? TXN_INNER(parent) : NULL, flags, TXN_INNER(txn));
	if(rc < 0) goto cleanup;

	if(parent) parent->child = txn;
cleanup:
	if(rc < 0) db_txn_abort_destroy(txn);
	return rc;
}
DB_FN int db__txn_commit_destroy(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	int rc = 0;
	if(txn->child) {
		rc = db_txn_commit(txn->child); txn->child = NULL;
		if(rc < 0) goto cleanup;
	}
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	rc = db_txn_commit_destroy(TXN_INNER(txn));
	if(rc < 0) goto cleanup;
cleanup:
	db_txn_abort_destroy(txn);
	return rc;
}
DB_FN void db__txn_abort_destroy(DB_txn *const txn) {
	if(!txn) return;
	if(txn->child) {
		db_txn_abort(txn->child); txn->child = NULL;
	}
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	db_txn_abort_destroy(TXN_INNER(txn));
	if(txn->parent) txn->parent->child = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->isa = NULL;
	assert_zeroed(txn, 1);
}
DB_FN int db__txn_env(DB_txn *const txn, DB_env **const out) {
	if(!txn) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	*out = txn->env;
	return 0;
}
DB_FN int db__txn_parent(DB_txn *const txn, DB_txn **const out) {
	if(!txn) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	*out = txn->parent;
	return 0;
}
DB_FN int db__txn_get_flags(DB_txn *const txn, unsigned *const flags) {
	if(!txn) return DB_EINVAL;
	return db_txn_get_flags(TXN_INNER(txn), flags);
}
DB_FN int db__txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	assert(txn);
	return db_txn_cmp(TXN_INNER(txn), a, b);
}
DB_FN int db__txn_cursor(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	if(!txn->cursor) {
		int rc = db_cursor_open(txn, &txn->cursor);
		if(rc < 0) return rc;
	}
	*out = txn->cursor;
	return 0;
}

DB_FN int db__get(DB_txn *const txn, DB_val const *const key, DB_val *const data) {
	return db_helper_get(txn, key, data);
}
DB_FN int db__put(DB_txn *const txn, DB_val const *const key, DB_val *const data, unsigned const flags) {
	return db_helper_put(txn, key, data, flags);
}
DB_FN int db__del(DB_txn *const txn, DB_val const *const key, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	return db_helper_del(TXN_INNER(txn), key, flags);
}
DB_FN int db__cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len) {
	return db_helper_cmd(txn, buf, len);
}

DB_FN int db__countr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_countr(txn, range, out);
}
DB_FN int db__delr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_delr(txn, range, out);
}

DB_FN size_t db__cursor_size(DB_txn *const txn) {
	assert(txn);
	return sizeof(struct DB_cursor)+db_cursor_size(TXN_INNER(txn));
}
DB_FN int db__cursor_init(DB_txn *const txn, DB_cursor *const cursor) {
	if(!txn) return DB_EINVAL;
	if(!cursor) return DB_EINVAL;
	assert_zeroed(cursor, 1);
	int rc = 0;
	cursor->isa = db_base_dummy;
	cursor->txn = txn;

	rc = db_cursor_init(TXN_INNER(txn), CURSOR_INNER(cursor));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) db_cursor_destroy(cursor);
	return rc;
}
DB_FN void db__cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	db_cursor_destroy(CURSOR_INNER(cursor));
	cursor->txn = NULL;
	cursor->isa = NULL;
	assert_zeroed(cursor, 1);
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	return db_cursor_clear(CURSOR_INNER(cursor));
}
DB_FN int db__cursor_txn(DB_cursor *const cursor, DB_txn **const out) {
	if(!cursor) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	*out = cursor->txn;
	return 0;
}
DB_FN int db__cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	assert(cursor);
	return db_cursor_cmp(CURSOR_INNER(cursor), a, b);
}

DB_FN int db__cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	return db_cursor_current(CURSOR_INNER(cursor), key, data);
}
DB_FN int db__cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return db_cursor_seek(CURSOR_INNER(cursor), key, data, dir);
}
DB_FN int db__cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return db_cursor_first(CURSOR_INNER(cursor), key, data, dir);
}
DB_FN int db__cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return db_cursor_next(CURSOR_INNER(cursor), key, data, dir);
}

DB_FN int db__cursor_seekr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	return db_helper_cursor_seekr(cursor, range, key, data, dir);
}
DB_FN int db__cursor_firstr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	return db_helper_cursor_firstr(cursor, range, key, data, dir);
}
DB_FN int db__cursor_nextr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	return db_helper_cursor_nextr(cursor, range, key, data, dir);
}

DB_FN int db__cursor_put(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	return db_cursor_put(CURSOR_INNER(cursor), key, data, flags);
}
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	return db_helper_cursor_del(cursor, flags);
}

DB_BASE_V0(dummy)

