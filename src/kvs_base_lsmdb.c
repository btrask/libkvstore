// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "lsmdb/lsmdb.h"
#include "kvs_helper.h"
#include "common.h"

struct KVS_env {
	KVS_base const *isa;
	LSMDB_env *env;
	KVS_cmd_data cmd[1];
	unsigned flags;
	char *path;
	int mode;
};
struct KVS_txn {
	KVS_base const *isa;
	KVS_helper_txn helper[1];
	LSMDB_txn *txn;
};
struct KVS_cursor {
	KVS_base const *isa;
	KVS_txn *txn;
	LSMDB_cursor *cursor;
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
	env->isa = kvs_base_lsmdb;

	int rc = mdberr(lsmdb_env_create(&env->env));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) kvs_env_destroy(env);
	return rc;
}
KVS_FN int kvs__env_get_config(KVS_env *const env, char const *const type, void *data) {
	if(!env) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	if(0 == strcmp(type, KVS_CFG_FLAGS)) {
		*(unsigned *)data = env->flags; return 0;
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
		return mdberr(lsmdb_env_set_mapsize(env->env, *sp));
	} else if(0 == strcmp(type, KVS_CFG_COMPARE)) {
		return KVS_ENOTSUP;
	} else if(0 == strcmp(type, KVS_CFG_COMMAND)) {
		*env->cmd = *(KVS_cmd_data *)data; return 0;
	} else if(0 == strcmp(type, KVS_CFG_TXNSIZE)) {
		return 0;
	} else if(0 == strcmp(type, KVS_CFG_FLAGS)) {
		env->flags = *(unsigned *)data; return 0;
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
	return mdberr(lsmdb_env_open(env->env, env->path, env->flags | MDB_NOSUBDIR, env->mode));
}
KVS_FN void kvs__env_destroy(KVS_env *const env) {
	if(!env) return;
	lsmdb_env_close(env->env); env->env = NULL;
	env->isa = NULL;
	env->cmd->fn = NULL;
	env->cmd->ctx = NULL;
	env->flags = 0;
	free(env->path); env->path = NULL;
	env->mode = 0;
	assert_zeroed(env, 1);
}

KVS_FN size_t kvs__txn_size(KVS_env *const env) {
	if(!env) return 0;
	return sizeof(struct KVS_txn);
}
KVS_FN int kvs__txn_init(KVS_env *const env, KVS_txn *const txn) {
	if(!env) return KVS_EINVAL;
	if(!txn) return KVS_EINVAL;
	assert_zeroed(txn, 1);
	txn->isa = kvs_base_lsmdb;
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
	int rc = mdberr(lsmdb_txn_begin(txn->helper->->env,
		txn->helper->parent ? txn->helper->parent->txn : NULL,
		txn->helper->flags, &txn->txn));
	if(rc < 0) goto cleanup;

	if(txn->helper->parent) txn->helper->parent->helper->child = txn;
cleanup:
	if(rc < 0) kvs_txn_abort_destroy(txn);
	return 0;
}
KVS_FN int kvs__txn_commit_destroy(KVS_txn *const txn) {
	if(!txn) return KVS_EINVAL;
	int rc = kvs_helper_txn_commit(txn);
	if(rc < 0) goto cleanup;
	rc = mdberr(lsmdb_autocompact(txn->txn));
	if(rc < 0) goto cleanup;
	rc = mdberr(lsmdb_txn_commit(txn->txn)); txn->txn = NULL;
	if(rc < 0) goto cleanup;
cleanup:
	kvs_txn_abort_destroy(txn);
	return rc;
}
KVS_FN void kvs__txn_abort_destroy(KVS_txn *const txn) {
	if(!txn) return;
	kvs_helper_txn_abort(txn->helper);
	lsmdb_txn_abort(txn->txn); txn->txn = NULL;
	txn->isa = NULL;
	assert_zeroed(txn, 1);
}
KVS_FN int kvs__txn_cmp(KVS_txn *const txn, KVS_val const *const a, KVS_val const *const b) {
	if(!txn) return KVS_EINVAL;
	return lsmdb_cmp(txn->txn, (MDB_val *)a, (MDB_val *)b);
}

KVS_FN int kvs__get(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data) {
	if(!txn) return KVS_EINVAL;
	return mdberr(lsmdb_get(txn->txn, (MDB_val *)key, (MDB_val *)data));
}
KVS_FN int kvs__put(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data, unsigned const flags) {
	if(!txn) return KVS_EINVAL;
	MDB_val null = { 0, NULL };
	MDB_val *const k = (MDB_val *)key;
	MDB_val *const d = data ? (MDB_val *)data : &null;
	return mdberr(lsmdb_put(txn->txn, k, d, flags));
}
KVS_FN int kvs__del(KVS_txn *const txn, KVS_val const *const key, unsigned const flags) {
	if(!txn) return KVS_EINVAL;
	return mdberr(lsmdb_del(txn->txn, (MDB_val *)key, flags));
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
	cursor->isa = kvs_base_lsmdb;
	cursor->txn = txn;
	rc = mdberr(lsmdb_cursor_open(txn->txn, &cursor->cursor));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) kvs_cursor_destroy(cursor);
	return rc;
}
KVS_FN void kvs__cursor_destroy(KVS_cursor *const cursor) {
	if(!cursor) return;
	lsmdb_cursor_close(cursor->cursor); cursor->cursor = NULL;
	cursor->isa = NULL;
	cursor->txn = NULL;
	cursor->cursor = NULL;
	assert_zeroed(cursor, 1);
}
KVS_FN int kvs__cursor_clear(KVS_cursor *const cursor) {
	if(!cursor) return KVS_EINVAL;
	return mdberr(lsmdb_cursor_clear(cursor->cursor));
}
KVS_FN int kvs__cursor_txn(KVS_cursor *const cursor, KVS_txn **const out) {
	if(!cursor) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	*out = cursor->txn;
	return 0;
}
KVS_FN int kvs__cursor_cmp(KVS_cursor *const cursor, KVS_val const *const a, KVS_val const *const b) {
	if(!cursor) return KVS_EINVAL;
	return lsmdb_cmp(lsmdb_cursor_txn(cursor->cursor), (MDB_val *)a, (MDB_val *)b);
}

KVS_FN int kvs__cursor_current(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data) {
	if(!cursor) return KVS_EINVAL;
	return mdberr(lsmdb_cursor_current(cursor->cursor, (MDB_val *)key, (MDB_val *)data));
}
KVS_FN int kvs__cursor_seek(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	return mdberr(lsmdb_cursor_seek(cursor->cursor, (MDB_val *)key, (MDB_val *)data, dir));
}
KVS_FN int kvs__cursor_first(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	return mdberr(lsmdb_cursor_first(cursor->cursor, (MDB_val *)key, (MDB_val *)data, dir));
}
KVS_FN int kvs_cursor_next(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	return mdberr(lsmdb_cursor_next(cursor->cursor, (MDB_val *)key, (MDB_val *)data, dir));
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
	return mdberr(lsmdb_cursor_put(cursor->cursor, k, d, flags));
}
KVS_FN int kvs__cursor_del(KVS_cursor *const cursor, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	if(flags) return KVS_EINVAL;
	return mdberr(lsmdb_cursor_del(cursor->cursor));
}

