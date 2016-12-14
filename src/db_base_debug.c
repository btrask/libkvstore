// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "db_base_internal.h"

struct DB_env {
	DB_base const *isa;
	DB_env *env;
	DB_print_data log[1];
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
	DB_txn *txn;
	DB_cursor *cursor;
};
struct DB_cursor {
	DB_base const *isa;
	DB_txn *txn;
	DB_cursor *cursor;
};

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

DB_FN int db__env_create(DB_env **const out) {
	DB_env *env = NULL;
	DB_env *sub = NULL;
	int rc = db_env_create_base("mdb", &sub);
	if(rc < 0) goto cleanup;
	env = calloc(1, sizeof(DB_env));
	if(!env) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;
	env->isa = db_base_debug;
	env->env = sub; sub = NULL;
	*env->log = (DB_print_data){ default_log, stderr };
	*out = env; env = NULL;
cleanup:
	db_env_close(sub);
	free(env);
	return 0;
}
DB_FN int db__env_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	// TODO: We should have a way of swapping out the inner env.
	// And also a way of getting it to configure directly?
	// Ownership becomes a little bit complex...
	switch(type) {
	case DB_CFG_LOG:
		*env->log = *(DB_print_data *)data;
		return 0;
	default:
		return db_env_config(env->env, type, data);
	}
}
DB_FN int db__env_open(DB_env *const env, char const *const name, unsigned const flags, unsigned const mode) {
	if(!env) return DB_EINVAL;
	int rc = db_env_open(env->env, name, flags, mode);
	LOG(env, rc);
	return rc;
}
DB_FN void db__env_close(DB_env *const env) {
	if(!env) return;
	LOG(env, 0);
	db_env_close(env->env); env->env = NULL;
	env->isa = NULL;
	free(env);
}

DB_FN int db__txn_begin(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn **const out) {
	if(!env) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	DB_txn *txn = NULL;
	DB_txn *sub = NULL;
	int rc = db_txn_begin(env->env, parent ? parent->txn : NULL, flags, &sub);
	if(rc < 0) goto cleanup;
	txn = calloc(1, sizeof(DB_txn));
	if(!txn) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;
	txn->isa = db_base_debug;
	txn->env = env;
	txn->parent = parent;
	txn->txn = sub; sub = NULL;
	*out = txn; txn = NULL;
cleanup:
	db_txn_abort(sub);
	free(txn);
	LOG(env, rc);
	return rc;
}
DB_FN int db__txn_commit(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	LOG(txn->env, 0);
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	int rc = db_txn_commit(txn->txn);
	txn->isa = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->txn = NULL;
	free(txn);
	return rc;
}
DB_FN void db__txn_abort(DB_txn *const txn) {
	if(!txn) return;
	LOG(txn->env, 0);
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	db_txn_abort(txn->txn);
	txn->isa = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->txn = NULL;
	free(txn);
}
DB_FN void db__txn_reset(DB_txn *const txn) {
	if(!txn) return;
	LOG(txn->env, 0);
	db_txn_reset(txn->txn);
}
DB_FN int db__txn_renew(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	int rc = db_txn_renew(txn->txn);
	LOG(txn->env, rc);
	return rc;
}
DB_FN int db__txn_env(DB_txn *const txn, DB_env **const out) {
	if(!txn) return DB_EINVAL;
	if(out) *out = txn->env;
	return 0;
}
DB_FN int db__txn_parent(DB_txn *const txn, DB_txn **const out) {
	if(!txn) return DB_EINVAL;
	if(out) *out = txn->parent;
	return 0;
}
DB_FN int db__txn_get_flags(DB_txn *const txn, unsigned *const flags) {
	if(!txn) return DB_EINVAL;
	int rc = db_txn_get_flags(txn->txn, flags);
	LOG(txn->env, rc);
	return rc;
}
DB_FN int db__txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	return db_txn_cmp(txn->txn, a, b);
}
DB_FN int db__txn_cursor(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	int rc = 0;
	if(!txn->cursor) rc = db_cursor_renew(txn, &txn->cursor);
	if(out) *out = txn->cursor;
	LOG(txn->env, rc);
	return rc;
}

// Use our own cursor for these rather than mdb_get/put
// because otherwise MDB has to construct its own temporary cursor
// on the stack, which is just wasteful if we might need it again.
DB_FN int db__get(DB_txn *const txn, DB_val *const key, DB_val *const data) {
	if(!txn) return DB_EINVAL;
	int rc = db_get(txn->txn, key, data);
	LOG(txn->env, rc);
	return rc;
}
DB_FN int db__put(DB_txn *const txn, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	int rc = db_put(txn->txn, key, data, flags);
	LOG(txn->env, rc);
	return rc;
}
DB_FN int db__del(DB_txn *const txn, DB_val *const key, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	int rc = db_del(txn->txn, key, flags);
	LOG(txn->env, rc);
	return rc;
}
DB_FN int db__cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len) {
	if(!txn) return DB_EINVAL;
	int rc = db_cmd(txn->txn, buf, len);
	LOG(txn->env, rc);
	return rc;
}

DB_FN int db__cursor_open(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	DB_cursor *cursor = NULL;
	DB_cursor *sub = NULL;
	int rc = db_cursor_open(txn->txn, &sub);
	if(rc < 0) goto cleanup;
	cursor = calloc(1, sizeof(DB_cursor));
	if(!cursor) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;
	cursor->isa = db_base_debug;
	cursor->txn = txn;
	cursor->cursor = sub; sub = NULL;
	*out = cursor; cursor = NULL;
cleanup:
	db_cursor_close(sub);
	free(cursor);
	LOG(txn->env, rc);
	return rc;
}
DB_FN void db__cursor_close(DB_cursor *const cursor) {
	if(!cursor) return;
	LOG(cursor->txn->env, 0);
	db_cursor_close(cursor->cursor); cursor->cursor = NULL;
	cursor->isa = NULL;
	cursor->txn = NULL;
	free(cursor);
}
DB_FN void db__cursor_reset(DB_cursor *const cursor) {
	if(!cursor) return;
	LOG(cursor->txn->env, 0);
	// Do nothing?
}
DB_FN int db__cursor_renew(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	int rc = 0;
	if(*out) {
		out[0]->txn = txn;
		rc = db_cursor_renew(txn->txn, &out[0]->cursor);
		LOG(txn->env, rc);
		return rc;
	}
	rc = db_cursor_open(txn, out);
	LOG(txn->env, rc);
	return rc;
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_clear(cursor->cursor);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_txn(DB_cursor *const cursor, DB_txn **const out) {
	if(!cursor) return DB_EINVAL;
	if(out) *out = cursor->txn;
	return 0;
}
DB_FN int db__cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	assert(cursor);
	return db_cursor_cmp(cursor->cursor, a, b);
}

DB_FN int db__cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_current(cursor->cursor, key, data);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_seek(cursor->cursor, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_first(cursor->cursor, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_next(cursor->cursor, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}

DB_FN int db__cursor_seekr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_seekr(cursor->cursor, range, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_firstr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_firstr(cursor->cursor, range, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_nextr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_nextr(cursor->cursor, range, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}

DB_FN int db__cursor_put(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_put(cursor->cursor, key, data, flags);
	LOG(cursor->txn->env, rc);
	return rc;
}
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_del(cursor->cursor, flags);
	LOG(cursor->txn->env, rc);
	return rc;
}

DB_BASE_V0(debug)

