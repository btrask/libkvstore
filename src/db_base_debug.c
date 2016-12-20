// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "db_base_internal.h"
#include "common.h"

struct DB_env {
	DB_base const *isa;
	DB_env *env;
	DB_print_data log[1];
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

#define TXN_INNER(txn) ((txn)+1)
#define CURSOR_INNER(cursor) ((cursor)+1)

#define LOG(env, rc) do { \
	if((env)->log->fn) { \
		char const *msg = rc >= 0 ? "OK" : db_strerror((rc)); \
		(env)->log->fn((env)->log->ctx, (env), \
			"db_base_debug %s: %s\n", __PRETTY_FUNCTION__, msg); \
	} \
} while(0)
static void default_log(void *ctx, DB_env *const env, char const *const format, ...) {
	FILE *const output = ctx;
	va_list ap;
	va_start(ap, format);
	vfprintf(output, format, ap);
	va_end(ap);
}

DB_FN size_t db__env_size(void) {
	return sizeof(struct DB_env);
}
DB_FN int db__env_init(DB_env *const env) {
	if(!env) return DB_EINVAL;
	int rc = 0;
	env->isa = db_base_debug;

	rc = db_env_create_base("mdb", &env->env);
	if(rc < 0) goto cleanup;
	*env->log = (DB_print_data){ default_log, stderr };
cleanup:
	if(rc < 0) db_env_destroy(env);
	return 0;
}
DB_FN int db__env_get_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_LOG: *(DB_print_data *)data = *env->log; return 0;
	case DB_CFG_INNERDB: *(DB_env **)data = env->env; return 0;
	default:
		return db_env_get_config(env->env, type, data);
	}
}
DB_FN int db__env_set_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_LOG: *env->log = *(DB_print_data *)data; return 0;
	case DB_CFG_INNERDB:
		db_env_close(env->env);
		env->env = data;
		return 0;
	default:
		return db_env_set_config(env->env, type, data);
	}
}
DB_FN int db__env_open0(DB_env *const env) {
	if(!env) return DB_EINVAL;
	int rc = db_env_open0(env->env);
	LOG(env, rc);
	return rc;
}
DB_FN void db__env_destroy(DB_env *const env) {
	if(!env) return;
	LOG(env, 0);
	db_env_close(env->env); env->env = NULL;
	*env->log = (DB_print_data){0};
	env->isa = NULL;
	assert_zeroed(env, 1);
}

DB_FN size_t db__txn_size(DB_env *const env) {
	assert(env);
	return sizeof(struct DB_txn)+db_txn_size(env->env);
}
DB_FN int db__txn_begin_init(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn *const txn) {
	if(!env) return DB_EINVAL;
	if(!txn) return DB_EINVAL;
	if(parent && parent->child) return DB_BAD_TXN;
	assert_zeroed(txn, 1);
	int rc = 0;
	txn->isa = db_base_debug;

	rc = db_txn_begin_init(env->env, parent ? TXN_INNER(parent) : NULL, flags, TXN_INNER(txn));
	if(rc < 0) goto cleanup;
	txn->env = env;
	txn->parent = parent;
	txn->child = NULL;

	if(parent) parent->child = txn;
cleanup:
	if(rc < 0) db_txn_abort_destroy(txn);
	LOG(env, rc);
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
	LOG(txn->env, rc);
	db_txn_abort_destroy(txn);
	return rc;
}
DB_FN void db__txn_abort_destroy(DB_txn *const txn) {
	if(!txn) return;
	if(txn->child) {
		db_txn_abort(txn->child); txn->child = NULL;
	}
	if(TXN_INNER(txn)->isa) LOG(txn->env, 0); // Don't log abort during commit.
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	db_txn_abort_destroy(TXN_INNER(txn));
	if(txn->parent) txn->parent->child = NULL;
	txn->isa = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	assert_zeroed(txn, 1);
}
DB_FN int db__txn_upgrade(DB_txn *const txn, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	int rc = db_txn_upgrade(TXN_INNER(txn), flags);
	LOG(txn->env, rc);
	return rc;
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
	int rc = db_txn_get_flags(TXN_INNER(txn), flags);
	LOG(txn->env, rc);
	return rc;
}
DB_FN int db__txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	return db_txn_cmp(TXN_INNER(txn), a, b);
}
DB_FN int db__txn_cursor(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	int rc = 0;
	if(!txn->cursor) rc = db_cursor_open(txn, &txn->cursor);
	*out = txn->cursor;
	LOG(txn->env, rc);
	return rc;
}

DB_FN int db__get(DB_txn *const txn, DB_val const *const key, DB_val *const data) {
	if(!txn) return DB_EINVAL;
	int rc = db_get(TXN_INNER(txn), key, data);
	LOG(txn->env, rc);
	return rc;
}
DB_FN int db__put(DB_txn *const txn, DB_val const *const key, DB_val *const data, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	int rc = db_put(TXN_INNER(txn), key, data, flags);
	LOG(txn->env, rc);
	return rc;
}
DB_FN int db__del(DB_txn *const txn, DB_val const *const key, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	int rc = db_del(TXN_INNER(txn), key, flags);
	LOG(txn->env, rc);
	return rc;
}
DB_FN int db__cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len) {
	if(!txn) return DB_EINVAL;
	int rc = db_cmd(TXN_INNER(txn), buf, len);
	LOG(txn->env, rc);
	return rc;
}

DB_FN int db__countr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	if(!txn) return DB_EINVAL;
	int rc = db_countr(TXN_INNER(txn), range, out);
	LOG(txn->env, rc);
	return rc;
}
DB_FN int db__delr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	if(!txn) return DB_EINVAL;
	int rc = db_delr(TXN_INNER(txn), range, out);
	LOG(txn->env, rc);
	return rc;
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
	cursor->isa = db_base_debug;

	rc = db_cursor_init(TXN_INNER(txn), CURSOR_INNER(cursor));
	if(rc < 0) goto cleanup;
	cursor->txn = txn;
cleanup:
	if(rc < 0) db_cursor_destroy(cursor);
	LOG(txn->env, rc);
	return rc;
}
DB_FN void db__cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	LOG(cursor->txn->env, 0);
	db_cursor_destroy(CURSOR_INNER(cursor));
	cursor->isa = NULL;
	cursor->txn = NULL;
	assert_zeroed(cursor, 1);
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_clear(CURSOR_INNER(cursor));
	LOG(cursor->txn->env, rc);
	return rc;
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
	int rc = db_cursor_current(CURSOR_INNER(cursor), key, data);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_seek(CURSOR_INNER(cursor), key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_first(CURSOR_INNER(cursor), key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_next(CURSOR_INNER(cursor), key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}

DB_FN int db__cursor_seekr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_seekr(CURSOR_INNER(cursor), range, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_firstr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_firstr(CURSOR_INNER(cursor), range, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_nextr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_nextr(CURSOR_INNER(cursor), range, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}

DB_FN int db__cursor_put(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_put(CURSOR_INNER(cursor), key, data, flags);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_del(CURSOR_INNER(cursor), flags);
	LOG(cursor->txn->env, rc);
	return rc;
}

DB_BASE_V0(debug)

