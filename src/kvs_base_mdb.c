// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "liblmdb/lmdb.h"
#include "kvs_base_custom.h"
#include "common.h"

// MDB private definition but seems unlikely to change.
// We double check it at run time and return an error if it's different.
#define MDB_MAIN_DBI 1

struct KVS_env {
	KVS_base const *isa;
	MDB_env *env;
	KVS_cmp_data cmp[1];
	KVS_cmd_data cmd[1];
	char *path;
	int mode;
};
struct KVS_txn {
	KVS_base const *isa;
	KVS_env *env;
	KVS_txn *parent;
	KVS_txn *child;
	MDB_txn *txn;
	unsigned flags;
	KVS_cursor *cursor;
};
struct KVS_cursor {
	KVS_base const *isa;
	KVS_txn *txn;
	MDB_cursor *cursor;
};

static int mdberr(int const rc) {
	return rc <= 0 ? rc : -rc;
}

KVS_FN size_t kvs__env_size(void) {
	return sizeof(struct KVS_env);
}
KVS_FN int kvs__env_init(KVS_env *const env) {
	if(!env) return KVS_EINVAL;
	assert_zeroed(env, 1);
	int rc = 0;
	env->isa = kvs_base_mdb;
	rc = mdberr(mdb_env_create(&env->env));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) kvs_env_destroy(env);
	return rc;
}
KVS_FN int kvs__env_get_config(KVS_env *const env, char const *const type, void *data) {
	if(!env) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	if(0 == strcmp(type, KVS_CFG_MAPSIZE)) {
		MDB_envinfo x[1];
		int rc = mdberr(mdb_env_info(env->env, x));
		if(rc < 0) return rc;
		*(size_t *)data = x->me_mapsize;
		return 0;
	} else if(0 == strcmp(type, KVS_CFG_COMMAND)) {
		*(KVS_cmd_data *)data = *env->cmd; return 0;
	} else if(0 == strcmp(type, KVS_CFG_KEYSIZE)) {
		*(size_t *)data = mdb_env_get_maxkeysize(env->env);
		return 0;
	} else if(0 == strcmp(type, KVS_CFG_FLAGS)) {
		return mdberr(mdb_env_get_flags(env->env, data));
	} else if(0 == strcmp(type, KVS_CFG_FILENAME)) {
		*(char const **)data = env->path; return 0;
	} else if(0 == strcmp(type, KVS_CFG_FILEMODE)) {
		*(int *)data = env->mode; return 0;
	} else {
		return KVS_ENOTSUP;
	}
}
KVS_FN int kvs__env_set_config(KVS_env *const env, char const *const type, void *data) {
	if(!env) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	if(0 == strcmp(type, KVS_CFG_MAPSIZE)) {
		size_t *const sp = data;
		return mdberr(mdb_env_set_mapsize(env->env, *sp));
	} else if(0 == strcmp(type, KVS_CFG_COMPARE)) {
		return KVS_ENOTSUP; //*env->cmp = *(KVS_cmp_data *)data; return 0;
	} else if(0 == strcmp(type, KVS_CFG_COMMAND)) {
		*env->cmd = *(KVS_cmd_data *)data; return 0;
	} else if(0 == strcmp(type, KVS_CFG_FLAGS)) {
		unsigned const valid = MDB_NOSYNC;
		unsigned flags = *(unsigned *)data;
		int rc;
		rc = mdberr(mdb_env_set_flags(env->env, valid & flags, 1));
		if(rc < 0) return rc;
		rc = mdberr(mdb_env_set_flags(env->env, valid & ~flags, 0));
		if(rc < 0) return rc;
		return 0;
	} else if(0 == strcmp(type, KVS_CFG_FILENAME)) {
		free(env->path);
		env->path = data ? strdup(data) : NULL;
		if(data && !env->path) return KVS_ENOMEM;
		return 0;
	} else if(0 == strcmp(type, KVS_CFG_FILEMODE)) {
		env->mode = *(int *)data; return 0;
	} else {
		return KVS_ENOTSUP;
	}
}
KVS_FN int kvs__env_open0(KVS_env *const env) {
	if(!env) return KVS_EINVAL;
	// Flags set with mdb_env_set_flags stay set.
	int rc = mdberr(mdb_env_open(env->env, env->path, MDB_NOSUBDIR, env->mode));
	if(rc < 0) return rc;
	MDB_txn *txn = NULL;
	MDB_dbi dbi;
	rc = mdberr(mdb_txn_begin(env->env, NULL, 0, &txn));
	if(rc < 0) goto cleanup;
	rc = mdberr(mdb_dbi_open(txn, NULL, 0, &dbi));
	if(rc < 0) goto cleanup;
	if(env->cmp->fn) {
		rc = mdberr(mdb_set_compare(txn, dbi, (MDB_cmp_func *)env->cmp->fn));
		if(rc < 0) goto cleanup;
	}
	rc = mdberr(mdb_txn_commit(txn)); txn = NULL;
	if(rc < 0) goto cleanup;
	if(MDB_MAIN_DBI != dbi) return KVS_PANIC;
cleanup:
	mdb_txn_abort(txn); txn = NULL;
	return rc;
}
KVS_FN void kvs__env_destroy(KVS_env *const env) {
	if(!env) return;
	mdb_env_close(env->env); env->env = NULL;
	env->isa = NULL;
	env->env = NULL;
	env->cmp->fn = NULL;
	env->cmp->ctx = NULL;
	env->cmd->fn = NULL;
	env->cmd->ctx = NULL;
	free(env->path); env->path = NULL;
	env->mode = 0;
	assert_zeroed(env, 1);
}

KVS_FN size_t kvs__txn_size(KVS_env *const env) {
	return sizeof(struct KVS_txn);
}
KVS_FN int kvs__txn_begin_init(KVS_env *const env, KVS_txn *const parent, unsigned const flags, KVS_txn *const txn) {
	if(!env) return KVS_EINVAL;
	if(!txn) return KVS_EINVAL;
	if(parent && parent->child) return KVS_BAD_TXN;
	assert_zeroed(txn, 1);
	int rc = 0;
	txn->isa = kvs_base_mdb;

	rc = mdberr(mdb_txn_begin(env->env, parent ? parent->txn : NULL, flags, &txn->txn));
	if(rc < 0) goto cleanup;
	txn->env = env;
	txn->parent = parent;
	txn->child = NULL;
	txn->flags = flags;
	txn->cursor = NULL;

	if(parent) parent->child = txn;
cleanup:
	if(rc < 0) kvs_txn_abort_destroy(txn);
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
	rc = mdberr(mdb_txn_commit(txn->txn)); txn->txn = NULL;
	if(rc < 0) goto cleanup;
cleanup:
	kvs_txn_abort_destroy(txn);
	return rc;
}
KVS_FN void kvs__txn_abort_destroy(KVS_txn *const txn) {
	if(!txn) return;
	if(txn->child) {
		kvs_txn_abort(txn->child); txn->child = NULL;
	}
	kvs_cursor_close(txn->cursor); txn->cursor = NULL;
	mdb_txn_abort(txn->txn); txn->txn = NULL;
	if(txn->parent) txn->parent->child = NULL;
	txn->isa = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->flags = 0;
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
	if(!flags) return KVS_EINVAL;
	*flags = txn->flags;
	return 0;
}
KVS_FN int kvs__txn_cmp(KVS_txn *const txn, KVS_val const *const a, KVS_val const *const b) {
	return mdb_cmp(txn->txn, MDB_MAIN_DBI, (MDB_val *)a, (MDB_val *)b);
}
KVS_FN int kvs__txn_cursor(KVS_txn *const txn, KVS_cursor **const out) {
	if(!txn) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	if(!txn->cursor) {
		int rc = kvs_cursor_open(txn, &txn->cursor);
		if(rc < 0) return rc;
	}
	*out = txn->cursor;
	return 0;
}

// Use our own cursor for these rather than mdb_get/put
// because otherwise MDB has to construct its own temporary cursor
// on the stack, which is just wasteful if we might need it again.
KVS_FN int kvs__get(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data) {
	return kvs_helper_get(txn, key, data);
}
KVS_FN int kvs__put(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data, unsigned const flags) {
	return kvs_helper_put(txn, key, data, flags);
}
KVS_FN int kvs__del(KVS_txn *const txn, KVS_val const *const key, unsigned const flags) {
	return kvs_helper_del(txn, key, flags);
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
	return sizeof(struct KVS_cursor);
}
KVS_FN int kvs__cursor_init(KVS_txn *const txn, KVS_cursor *const cursor) {
	if(!txn) return KVS_EINVAL;
	if(!cursor) return KVS_EINVAL;
	assert_zeroed(cursor, 1);
	int rc = 0;
	cursor->isa = kvs_base_mdb;

	rc = mdberr(mdb_cursor_open(txn->txn, MDB_MAIN_DBI, &cursor->cursor));
	if(rc < 0) goto cleanup;
	cursor->txn = txn;
cleanup:
	if(rc < 0) kvs_cursor_destroy(cursor);
	return rc;
}
KVS_FN void kvs__cursor_destroy(KVS_cursor *const cursor) {
	if(!cursor) return;
	mdb_cursor_close(cursor->cursor); cursor->cursor = NULL;
	cursor->isa = NULL;
	cursor->txn = NULL;
	assert_zeroed(cursor, 1);
}
KVS_FN int kvs__cursor_clear(KVS_cursor *const cursor) {
	if(!cursor) return KVS_EINVAL;
	MDB_cursor *const c = cursor->cursor;
	int rc = mdberr(mdb_cursor_renew(mdb_cursor_txn(c), c));
	if(KVS_EINVAL == rc) rc = 0;
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
	return mdb_cmp(mdb_cursor_txn(cursor->cursor), MDB_MAIN_DBI, (MDB_val const *)a, (MDB_val const *)b);
}

KVS_FN int kvs__cursor_current(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data) {
	if(!cursor) return KVS_EINVAL;
	int rc = mdberr(mdb_cursor_get(cursor->cursor, (MDB_val *)key, (MDB_val *)data, MDB_GET_CURRENT));
	if(KVS_EINVAL == rc) return KVS_NOTFOUND;
	return rc;
}
KVS_FN int kvs__cursor_seek(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	if(!key) return KVS_EINVAL;
	MDB_cursor *const c = cursor->cursor;
	MDB_val *const k = (MDB_val *)key;
	MDB_val *const d = (MDB_val *)data;
	MDB_val const orig = *k;
	MDB_cursor_op const op = 0 == dir ? MDB_SET : MDB_SET_RANGE;
	int rc = mdberr(mdb_cursor_get(c, k, d, op));
	if(dir >= 0) return rc;
	if(rc >= 0) {
		MDB_txn *const txn = mdb_cursor_txn(c);
		if(0 == mdb_cmp(txn, MDB_MAIN_DBI, &orig, k)) return rc;
		return mdb_cursor_get(c, k, d, MDB_PREV);
	} else if(KVS_NOTFOUND == rc) {
		return mdberr(mdb_cursor_get(c, k, d, MDB_LAST));
	} else return rc;
}
KVS_FN int kvs__cursor_first(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	if(0 == dir) return KVS_EINVAL;
	MDB_cursor_op const op = dir < 0 ? MDB_LAST : MDB_FIRST;
	MDB_val _k[1], _d[1];
	MDB_val *const k = key ? (MDB_val *)key : _k;
	MDB_val *const d = data ? (MDB_val *)data : _d;
	return mdberr(mdb_cursor_get(cursor->cursor, (MDB_val *)k, (MDB_val *)d, op));
}
KVS_FN int kvs__cursor_next(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	if(0 == dir) return KVS_EINVAL;
	MDB_cursor_op const op = dir < 0 ? MDB_PREV : MDB_NEXT;
	MDB_val _k[1], _d[1];
	MDB_val *const k = key ? (MDB_val *)key : _k;
	MDB_val *const d = data ? (MDB_val *)data : _d;
	return mdberr(mdb_cursor_get(cursor->cursor, (MDB_val *)k, (MDB_val *)d, op));
}

KVS_FN int kvs__cursor_seekr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	return kvs_helper_cursor_seekr(cursor, range, key, data, dir);
}
KVS_FN int kvs__cursor_firstr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	return kvs_helper_cursor_firstr(cursor, range, key, data, dir);
}
KVS_FN int kvs__cursor_nextr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	return kvs_helper_cursor_nextr(cursor, range, key, data, dir);
}

KVS_FN int kvs__cursor_put(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	MDB_val null = { 0, NULL };
	MDB_val *const k = (MDB_val *)key;
	MDB_val *const d = data ? (MDB_val *)data : &null;
	return mdberr(mdb_cursor_put(cursor->cursor, k, d, flags));
}
KVS_FN int kvs__cursor_del(KVS_cursor *const cursor, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	if(flags) return KVS_EINVAL;
	return mdberr(mdb_cursor_del(cursor->cursor, 0));
}

KVS_BASE_V0(mdb)

