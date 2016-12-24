// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "liblmdb/lmdb.h"
#include "db_base_internal.h"
#include "common.h"

// MDB private definition but seems unlikely to change.
// We double check it at run time and return an error if it's different.
#define MDB_MAIN_DBI 1

struct DB_env {
	DB_base const *isa;
	MDB_env *env;
	DB_cmp_data cmp[1];
	DB_cmd_data cmd[1];
	char *path;
	int mode;
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
	DB_txn *child;
	MDB_txn *txn;
	unsigned flags;
	DB_cursor *cursor;
};
struct DB_cursor {
	DB_base const *isa;
	DB_txn *txn;
	MDB_cursor *cursor;
};

static int mdberr(int const rc) {
	return rc <= 0 ? rc : -rc;
}

DB_FN size_t db__env_size(void) {
	return sizeof(struct DB_env);
}
DB_FN int db__env_init(DB_env *const env) {
	if(!env) return DB_EINVAL;
	assert_zeroed(env, 1);
	int rc = 0;
	env->isa = db_base_mdb;
	rc = mdberr(mdb_env_create(&env->env));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) db_env_destroy(env);
	return rc;
}
DB_FN int db__env_get_config(DB_env *const env, char const *const type, void *data) {
	if(!env) return DB_EINVAL;
	if(!type) return DB_EINVAL;
	if(0 == strcmp(type, DB_CFG_MAPSIZE)) {
		MDB_envinfo x[1];
		int rc = mdberr(mdb_env_info(env->env, x));
		if(rc < 0) return rc;
		*(size_t *)data = x->me_mapsize;
		return 0;
	} else if(0 == strcmp(type, DB_CFG_COMMAND)) {
		*(DB_cmd_data *)data = *env->cmd; return 0;
	} else if(0 == strcmp(type, DB_CFG_KEYSIZE)) {
		*(size_t *)data = mdb_env_get_maxkeysize(env->env);
		return 0;
	} else if(0 == strcmp(type, DB_CFG_FLAGS)) {
		return mdberr(mdb_env_get_flags(env->env, data));
	} else if(0 == strcmp(type, DB_CFG_FILENAME)) {
		*(char const **)data = env->path; return 0;
	} else if(0 == strcmp(type, DB_CFG_FILEMODE)) {
		*(int *)data = env->mode; return 0;
	} else {
		return DB_ENOTSUP;
	}
}
DB_FN int db__env_set_config(DB_env *const env, char const *const type, void *data) {
	if(!env) return DB_EINVAL;
	if(!type) return DB_EINVAL;
	if(0 == strcmp(type, DB_CFG_MAPSIZE)) {
		size_t *const sp = data;
		return mdberr(mdb_env_set_mapsize(env->env, *sp));
	} else if(0 == strcmp(type, DB_CFG_COMPARE)) {
		return DB_ENOTSUP; //*env->cmp = *(DB_cmp_data *)data; return 0;
	} else if(0 == strcmp(type, DB_CFG_COMMAND)) {
		*env->cmd = *(DB_cmd_data *)data; return 0;
	} else if(0 == strcmp(type, DB_CFG_FLAGS)) {
		unsigned const valid = MDB_NOSYNC;
		unsigned flags = *(unsigned *)data;
		int rc;
		rc = mdberr(mdb_env_set_flags(env->env, valid & flags, 1));
		if(rc < 0) return rc;
		rc = mdberr(mdb_env_set_flags(env->env, valid & ~flags, 0));
		if(rc < 0) return rc;
		return 0;
	} else if(0 == strcmp(type, DB_CFG_FILENAME)) {
		free(env->path);
		env->path = data ? strdup(data) : NULL;
		if(data && !env->path) return DB_ENOMEM;
		return 0;
	} else if(0 == strcmp(type, DB_CFG_FILEMODE)) {
		env->mode = *(int *)data; return 0;
	} else {
		return DB_ENOTSUP;
	}
}
DB_FN int db__env_open0(DB_env *const env) {
	if(!env) return DB_EINVAL;
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
	if(MDB_MAIN_DBI != dbi) return DB_PANIC;
cleanup:
	mdb_txn_abort(txn); txn = NULL;
	return rc;
}
DB_FN void db__env_destroy(DB_env *const env) {
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

DB_FN size_t db__txn_size(DB_env *const env) {
	return sizeof(struct DB_txn);
}
DB_FN int db__txn_begin_init(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn *const txn) {
	if(!env) return DB_EINVAL;
	if(!txn) return DB_EINVAL;
	if(parent && parent->child) return DB_BAD_TXN;
	assert_zeroed(txn, 1);
	int rc = 0;
	txn->isa = db_base_mdb;

	rc = mdberr(mdb_txn_begin(env->env, parent ? parent->txn : NULL, flags, &txn->txn));
	if(rc < 0) goto cleanup;
	txn->env = env;
	txn->parent = parent;
	txn->child = NULL;
	txn->flags = flags;
	txn->cursor = NULL;

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
	rc = mdberr(mdb_txn_commit(txn->txn)); txn->txn = NULL;
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
	mdb_txn_abort(txn->txn); txn->txn = NULL;
	if(txn->parent) txn->parent->child = NULL;
	txn->isa = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->flags = 0;
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
	if(!flags) return DB_EINVAL;
	*flags = txn->flags;
	return 0;
}
DB_FN int db__txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	return mdb_cmp(txn->txn, MDB_MAIN_DBI, (MDB_val *)a, (MDB_val *)b);
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

// Use our own cursor for these rather than mdb_get/put
// because otherwise MDB has to construct its own temporary cursor
// on the stack, which is just wasteful if we might need it again.
DB_FN int db__get(DB_txn *const txn, DB_val const *const key, DB_val *const data) {
	return db_helper_get(txn, key, data);
}
DB_FN int db__put(DB_txn *const txn, DB_val const *const key, DB_val *const data, unsigned const flags) {
	return db_helper_put(txn, key, data, flags);
}
DB_FN int db__del(DB_txn *const txn, DB_val const *const key, unsigned const flags) {
	return db_helper_del(txn, key, flags);
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
	return sizeof(struct DB_cursor);
}
DB_FN int db__cursor_init(DB_txn *const txn, DB_cursor *const cursor) {
	if(!txn) return DB_EINVAL;
	if(!cursor) return DB_EINVAL;
	assert_zeroed(cursor, 1);
	int rc = 0;
	cursor->isa = db_base_mdb;

	rc = mdberr(mdb_cursor_open(txn->txn, MDB_MAIN_DBI, &cursor->cursor));
	if(rc < 0) goto cleanup;
	cursor->txn = txn;
cleanup:
	if(rc < 0) db_cursor_destroy(cursor);
	return rc;
}
DB_FN void db__cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	mdb_cursor_close(cursor->cursor); cursor->cursor = NULL;
	cursor->isa = NULL;
	cursor->txn = NULL;
	assert_zeroed(cursor, 1);
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	MDB_cursor *const c = cursor->cursor;
	int rc = mdberr(mdb_cursor_renew(mdb_cursor_txn(c), c));
	if(DB_EINVAL == rc) rc = 0;
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
	return mdb_cmp(mdb_cursor_txn(cursor->cursor), MDB_MAIN_DBI, (MDB_val const *)a, (MDB_val const *)b);
}

DB_FN int db__cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	int rc = mdberr(mdb_cursor_get(cursor->cursor, (MDB_val *)key, (MDB_val *)data, MDB_GET_CURRENT));
	if(DB_EINVAL == rc) return DB_NOTFOUND;
	return rc;
}
DB_FN int db__cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(!key) return DB_EINVAL;
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
	} else if(DB_NOTFOUND == rc) {
		return mdberr(mdb_cursor_get(c, k, d, MDB_LAST));
	} else return rc;
}
DB_FN int db__cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(0 == dir) return DB_EINVAL;
	MDB_cursor_op const op = dir < 0 ? MDB_LAST : MDB_FIRST;
	MDB_val _k[1], _d[1];
	MDB_val *const k = key ? (MDB_val *)key : _k;
	MDB_val *const d = data ? (MDB_val *)data : _d;
	return mdberr(mdb_cursor_get(cursor->cursor, (MDB_val *)k, (MDB_val *)d, op));
}
DB_FN int db__cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(0 == dir) return DB_EINVAL;
	MDB_cursor_op const op = dir < 0 ? MDB_PREV : MDB_NEXT;
	MDB_val _k[1], _d[1];
	MDB_val *const k = key ? (MDB_val *)key : _k;
	MDB_val *const d = data ? (MDB_val *)data : _d;
	return mdberr(mdb_cursor_get(cursor->cursor, (MDB_val *)k, (MDB_val *)d, op));
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
	MDB_val null = { 0, NULL };
	MDB_val *const k = (MDB_val *)key;
	MDB_val *const d = data ? (MDB_val *)data : &null;
	return mdberr(mdb_cursor_put(cursor->cursor, k, d, flags));
}
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	if(flags) return DB_EINVAL;
	return mdberr(mdb_cursor_del(cursor->cursor, 0));
}

DB_BASE_V0(mdb)

