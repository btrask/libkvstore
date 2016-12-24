// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kvs_base_custom.h"
#include "common.h"

struct KVS_env {
	KVS_base const *isa;
	KVS_env *env;
	KVS_print_data log[1];
};
struct KVS_txn {
	KVS_base const *isa;
	KVS_env *env;
	KVS_txn *parent;
	KVS_txn *child;
	KVS_cursor *cursor;
	// Inner txn
};
struct KVS_cursor {
	KVS_base const *isa;
	KVS_txn *txn;
	// Inner cursor
};

#define TXN_INNER(txn) ((txn)+1)
#define CURSOR_INNER(cursor) ((cursor)+1)

#define LOG(env, rc) do { \
	if((env)->log->fn) { \
		char const *msg = rc >= 0 ? "OK" : kvs_strerror((rc)); \
		(env)->log->fn((env)->log->ctx, (env), \
			"kvs_base_debug %s: %s\n", __PRETTY_FUNCTION__, msg); \
	} \
} while(0)
static void default_log(void *ctx, KVS_env *const env, char const *const format, ...) {
	FILE *const output = ctx;
	va_list ap;
	va_start(ap, format);
	vfprintf(output, format, ap);
	va_end(ap);
}

KVS_FN size_t kvs__env_size(void) {
	return sizeof(struct KVS_env);
}
KVS_FN int kvs__env_init(KVS_env *const env) {
	if(!env) return KVS_EINVAL;
	int rc = 0;
	env->isa = kvs_base_debug;

	rc = kvs_env_create_base("mdb", &env->env);
	if(rc < 0) goto cleanup;
	*env->log = (KVS_print_data){ default_log, stderr };
cleanup:
	if(rc < 0) kvs_env_destroy(env);
	return 0;
}
KVS_FN int kvs__env_get_config(KVS_env *const env, char const *const type, void *data) {
	if(!env) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	if(0 == strcmp(type, KVS_CFG_LOG)) {
		*(KVS_print_data *)data = *env->log; return 0;
	} else if(0 == strcmp(type, KVS_CFG_INNERDB)) {
		*(KVS_env **)data = env->env; return 0;
	} else {
		return kvs_env_get_config(env->env, type, data);
	}
}
KVS_FN int kvs__env_set_config(KVS_env *const env, char const *const type, void *data) {
	if(!env) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	if(0 == strcmp(type, KVS_CFG_LOG)) {
		*env->log = *(KVS_print_data *)data; return 0;
	} else if(0 == strcmp(type, KVS_CFG_INNERDB)) {
		kvs_env_close(env->env);
		env->env = data;
		return 0;
	} else {
		return kvs_env_set_config(env->env, type, data);
	}
}
KVS_FN int kvs__env_open0(KVS_env *const env) {
	if(!env) return KVS_EINVAL;
	int rc = kvs_env_open0(env->env);
	LOG(env, rc);
	return rc;
}
KVS_FN void kvs__env_destroy(KVS_env *const env) {
	if(!env) return;
	LOG(env, 0);
	kvs_env_close(env->env); env->env = NULL;
	*env->log = (KVS_print_data){0};
	env->isa = NULL;
	assert_zeroed(env, 1);
}

KVS_FN size_t kvs__txn_size(KVS_env *const env) {
	assert(env);
	return sizeof(struct KVS_txn)+kvs_txn_size(env->env);
}
KVS_FN int kvs__txn_begin_init(KVS_env *const env, KVS_txn *const parent, unsigned const flags, KVS_txn *const txn) {
	if(!env) return KVS_EINVAL;
	if(!txn) return KVS_EINVAL;
	if(parent && parent->child) return KVS_BAD_TXN;
	assert_zeroed(txn, 1);
	int rc = 0;
	txn->isa = kvs_base_debug;
	txn->env = env;
	txn->parent = parent;
	txn->child = NULL;

	rc = kvs_txn_begin_init(env->env, parent ? TXN_INNER(parent) : NULL, flags, TXN_INNER(txn));
	if(rc < 0) goto cleanup;

	if(parent) parent->child = txn;
cleanup:
	if(rc < 0) kvs_txn_abort_destroy(txn);
	LOG(env, rc);
	return rc;
}
KVS_FN int kvs__txn_commit_destroy(KVS_txn *const txn) {
	if(!txn) return KVS_EINVAL;
	int rc = 0;
	if(txn->child) {
		rc = kvs_txn_commit(txn->child); txn->child = NULL;
		if(rc < 0) goto cleanup;
	}
	kvs_cursor_close(txn->cursor); txn->cursor = NULL;
	rc = kvs_txn_commit_destroy(TXN_INNER(txn));
	if(rc < 0) goto cleanup;
cleanup:
	LOG(txn->env, rc);
	kvs_txn_abort_destroy(txn);
	return rc;
}
KVS_FN void kvs__txn_abort_destroy(KVS_txn *const txn) {
	if(!txn) return;
	if(txn->child) {
		kvs_txn_abort(txn->child); txn->child = NULL;
	}
	if(TXN_INNER(txn)->isa) LOG(txn->env, 0); // Don't log abort during commit.
	kvs_cursor_close(txn->cursor); txn->cursor = NULL;
	kvs_txn_abort_destroy(TXN_INNER(txn));
	if(txn->parent) txn->parent->child = NULL;
	txn->isa = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	assert_zeroed(txn, 1);
}
KVS_FN int kvs__txn_env(KVS_txn *const txn, KVS_env **const out) {
	if(!txn) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	*out = txn->env;
	return 0;
}
KVS_FN int kvs__txn_parent(KVS_txn *const txn, KVS_txn **const out) {
	if(!txn) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	*out = txn->parent;
	return 0;
}
KVS_FN int kvs__txn_get_flags(KVS_txn *const txn, unsigned *const flags) {
	if(!txn) return KVS_EINVAL;
	int rc = kvs_txn_get_flags(TXN_INNER(txn), flags);
	LOG(txn->env, rc);
	return rc;
}
KVS_FN int kvs__txn_cmp(KVS_txn *const txn, KVS_val const *const a, KVS_val const *const b) {
	assert(txn);
	return kvs_txn_cmp(TXN_INNER(txn), a, b);
}
KVS_FN int kvs__txn_cursor(KVS_txn *const txn, KVS_cursor **const out) {
	if(!txn) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	int rc = 0;
	if(!txn->cursor) rc = kvs_cursor_open(txn, &txn->cursor);
	*out = txn->cursor;
	LOG(txn->env, rc);
	return rc;
}

KVS_FN int kvs__get(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data) {
	if(!txn) return KVS_EINVAL;
	int rc = kvs_get(TXN_INNER(txn), key, data);
	LOG(txn->env, rc);
	return rc;
}
KVS_FN int kvs__put(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data, unsigned const flags) {
	if(!txn) return KVS_EINVAL;
	int rc = kvs_put(TXN_INNER(txn), key, data, flags);
	LOG(txn->env, rc);
	return rc;
}
KVS_FN int kvs__del(KVS_txn *const txn, KVS_val const *const key, unsigned const flags) {
	if(!txn) return KVS_EINVAL;
	int rc = kvs_del(TXN_INNER(txn), key, flags);
	LOG(txn->env, rc);
	return rc;
}
KVS_FN int kvs__cmd(KVS_txn *const txn, unsigned char const *const buf, size_t const len) {
	int rc = kvs_helper_cmd(txn, buf, len);
	LOG(txn->env, rc);
	return rc;
}

KVS_FN int kvs__countr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	if(!txn) return KVS_EINVAL;
	int rc = kvs_countr(TXN_INNER(txn), range, out);
	LOG(txn->env, rc);
	return rc;
}
KVS_FN int kvs__delr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	if(!txn) return KVS_EINVAL;
	int rc = kvs_delr(TXN_INNER(txn), range, out);
	LOG(txn->env, rc);
	return rc;
}

KVS_FN size_t kvs__cursor_size(KVS_txn *const txn) {
	assert(txn);
	return sizeof(struct KVS_cursor)+kvs_cursor_size(TXN_INNER(txn));
}
KVS_FN int kvs__cursor_init(KVS_txn *const txn, KVS_cursor *const cursor) {
	if(!txn) return KVS_EINVAL;
	if(!cursor) return KVS_EINVAL;
	assert_zeroed(cursor, 1);
	int rc = 0;
	cursor->isa = kvs_base_debug;

	rc = kvs_cursor_init(TXN_INNER(txn), CURSOR_INNER(cursor));
	if(rc < 0) goto cleanup;
	cursor->txn = txn;
cleanup:
	if(rc < 0) kvs_cursor_destroy(cursor);
	LOG(txn->env, rc);
	return rc;
}
KVS_FN void kvs__cursor_destroy(KVS_cursor *const cursor) {
	if(!cursor) return;
	LOG(cursor->txn->env, 0);
	kvs_cursor_destroy(CURSOR_INNER(cursor));
	cursor->isa = NULL;
	cursor->txn = NULL;
	assert_zeroed(cursor, 1);
}
KVS_FN int kvs__cursor_clear(KVS_cursor *const cursor) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_clear(CURSOR_INNER(cursor));
	LOG(cursor->txn->env, rc);
	return rc;
}
KVS_FN int kvs__cursor_txn(KVS_cursor *const cursor, KVS_txn **const out) {
	if(!cursor) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	*out = cursor->txn;
	return 0;
}
KVS_FN int kvs__cursor_cmp(KVS_cursor *const cursor, KVS_val const *const a, KVS_val const *const b) {
	assert(cursor);
	return kvs_cursor_cmp(CURSOR_INNER(cursor), a, b);
}

KVS_FN int kvs__cursor_current(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_current(CURSOR_INNER(cursor), key, data);
	LOG(cursor->txn->env, rc);
	return rc;
}
KVS_FN int kvs__cursor_seek(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_seek(CURSOR_INNER(cursor), key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
KVS_FN int kvs__cursor_first(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_first(CURSOR_INNER(cursor), key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
KVS_FN int kvs__cursor_next(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_next(CURSOR_INNER(cursor), key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}

KVS_FN int kvs__cursor_seekr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_seekr(CURSOR_INNER(cursor), range, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
KVS_FN int kvs__cursor_firstr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_firstr(CURSOR_INNER(cursor), range, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}
KVS_FN int kvs__cursor_nextr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_nextr(CURSOR_INNER(cursor), range, key, data, dir);
	LOG(cursor->txn->env, rc);
	return rc;
}

KVS_FN int kvs__cursor_put(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_put(CURSOR_INNER(cursor), key, data, flags);
	LOG(cursor->txn->env, rc);
	return rc;
}
KVS_FN int kvs__cursor_del(KVS_cursor *const cursor, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_del(CURSOR_INNER(cursor), flags);
	LOG(cursor->txn->env, rc);
	return rc;
}

KVS_BASE_V0(debug)

