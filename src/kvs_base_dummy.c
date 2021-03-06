// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include "kvs_helper.h"
#include "common.h"

// kvs_base_dummy.c
// There purpose of this back-end is two-fold. First is to demonstrate and
// document the minimum possible implementation, for developers wishing to
// create their own. Second is to measure the incidental complexity/overhead
// of creating a new back-end.
// For both of these reasons, this back-end tries to be as small as possible,
// taking full advantage of the provided "helpers."
// As you can see, there is still some unnecessary complexity left, especially
// in the init/destruction of transactions and cursors.

struct KVS_env {
	KVS_base const *isa;
	// Inner env
};
struct KVS_txn {
	KVS_base const *isa;
	KVS_helper_txn helper[1];
	// Inner txn
};
struct KVS_cursor {
	KVS_base const *isa;
	KVS_txn *txn;
	// Inner cursor
};
#define ENV_INNER(env) ((env)+1)
#define TXN_INNER(txn) ((txn)+1)
#define CURSOR_INNER(cursor) ((cursor)+1)

KVS_FN size_t kvs__env_size(void) {
	return sizeof(struct KVS_env)+kvs_env_size(kvs_base_default);
}
KVS_FN int kvs__env_init(KVS_env *const env) {
	if(!env) return KVS_EINVAL;
	int rc = 0;
	env->isa = kvs_base_dummy;
	rc = kvs_env_init_custom(kvs_base_default, ENV_INNER(env));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) kvs_env_destroy(env);
	return 0;
}
KVS_FN int kvs__env_get_config(KVS_env *const env, char const *const type, void *data) {
	if(!env) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	return kvs_env_get_config(ENV_INNER(env), type, data);
}
KVS_FN int kvs__env_set_config(KVS_env *const env, char const *const type, void *data) {
	if(!env) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	return kvs_env_set_config(ENV_INNER(env), type, data);
}
KVS_FN int kvs__env_open0(KVS_env *const env) {
	if(!env) return KVS_EINVAL;
	return kvs_env_open0(ENV_INNER(env));
}
KVS_FN void kvs__env_destroy(KVS_env *const env) {
	if(!env) return;
	kvs_env_destroy(ENV_INNER(env));
	env->isa = NULL;
	assert_zeroed(env, 1);
}

KVS_FN size_t kvs__txn_size(KVS_env *const env) {
	if(!env) return 0;
	return sizeof(struct KVS_txn)+kvs_txn_size(ENV_INNER(env));
}
KVS_FN int kvs__txn_init(KVS_env *const env, KVS_txn *const txn) {
	if(!env) return KVS_EINVAL;
	if(!txn) return KVS_EINVAL;
	assert_zeroed(txn, 1);
	txn->isa = kvs_base_dummy;
	txn->helper->env = env;
	return 0;
}
KVS_FN int kvs__txn_get_config(KVS_txn *const txn, char const *const type, void *data) {
	if(!txn) return KVS_EINVAL;
	return kvs_helper_txn_get_config(txn, txn->helper, type, data);
}
KVS_FN int kvs__txn_set_config(KVS_txn *const txn, char const *const type, void *data) {
	if(!txn) return KVS_EINVAL;
	return kvs_helper_txn_set_config(txn, txn->helper, type, data);
}
KVS_FN int kvs__txn_begin0(KVS_txn *const txn) {
	if(!txn) return KVS_EINVAL;
	if(!txn->helper->env) return KVS_EINVAL;
	if(txn->helper->parent && txn->helper->parent->helper->child) return KVS_BAD_TXN;
	int rc = kvs_txn_begin_init(ENV_INNER(txn->helper->env),
		txn->helper->parent ? TXN_INNER(txn->helper->parent) : NULL,
		txn->helper->flags, TXN_INNER(txn));
	if(rc < 0) goto cleanup;
	if(txn->helper->parent) txn->helper->parent->helper->child = txn;
cleanup:
	if(rc < 0) kvs_txn_abort_destroy(txn);
	return rc;
}
KVS_FN int kvs__txn_commit_destroy(KVS_txn *const txn) {
	if(!txn) return KVS_EINVAL;
	int rc = kvs_helper_txn_commit(txn->helper);
	if(rc < 0) goto cleanup;
	rc = kvs_txn_commit_destroy(TXN_INNER(txn));
	if(rc < 0) goto cleanup;
cleanup:
	kvs_txn_abort_destroy(txn);
	return rc;
}
KVS_FN void kvs__txn_abort_destroy(KVS_txn *const txn) {
	if(!txn) return;
	kvs_helper_txn_abort(txn->helper);
	kvs_txn_abort_destroy(TXN_INNER(txn));
	txn->isa = NULL;
	assert_zeroed(txn, 1);
}
KVS_FN int kvs__txn_cmp(KVS_txn *const txn, KVS_val const *const a, KVS_val const *const b) {
	assert(txn);
	return kvs_txn_cmp(TXN_INNER(txn), a, b);
}

KVS_FN int kvs__get(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data) {
	return kvs_helper_get(txn, key, data);
}
KVS_FN int kvs__put(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data, unsigned const flags) {
	return kvs_helper_put(txn, key, data, flags);
}
KVS_FN int kvs__del(KVS_txn *const txn, KVS_val const *const key, unsigned const flags) {
	if(!txn) return KVS_EINVAL;
	return kvs_helper_del(TXN_INNER(txn), key, flags);
}
KVS_FN int kvs__cmd(KVS_txn *const txn, unsigned char const *const buf, size_t const len) {
	return kvs_helper_cmd(txn, buf, len);
}

KVS_FN int kvs__countr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	return kvs_helper_countr(txn, range, out);
}
KVS_FN int kvs__delr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	return kvs_helper_delr(txn, range, out);
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
	cursor->isa = kvs_base_dummy;
	cursor->txn = txn;

	rc = kvs_cursor_init(TXN_INNER(txn), CURSOR_INNER(cursor));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) kvs_cursor_destroy(cursor);
	return rc;
}
KVS_FN void kvs__cursor_destroy(KVS_cursor *const cursor) {
	if(!cursor) return;
	kvs_cursor_destroy(CURSOR_INNER(cursor));
	cursor->txn = NULL;
	cursor->isa = NULL;
	assert_zeroed(cursor, 1);
}
KVS_FN int kvs__cursor_clear(KVS_cursor *const cursor) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_clear(CURSOR_INNER(cursor));
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
	return kvs_cursor_current(CURSOR_INNER(cursor), key, data);
}
KVS_FN int kvs__cursor_seek(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_seek(CURSOR_INNER(cursor), key, data, dir);
}
KVS_FN int kvs__cursor_first(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_first(CURSOR_INNER(cursor), key, data, dir);
}
KVS_FN int kvs__cursor_next(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_next(CURSOR_INNER(cursor), key, data, dir);
}

KVS_HELPER_CURSOR_RANGE_FUNCS(kvs__cursor)

KVS_FN int kvs__cursor_put(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_put(CURSOR_INNER(cursor), key, data, flags);
}
KVS_FN int kvs__cursor_del(KVS_cursor *const cursor, unsigned const flags) {
	return kvs_helper_cursor_del(cursor, flags);
}

KVS_BASE_V0(dummy)

