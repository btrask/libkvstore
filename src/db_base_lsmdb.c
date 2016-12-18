// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "lsmdb/lsmdb.h"
#include "db_base_internal.h"
#include "common.h"

struct DB_env {
	DB_base const *isa;
	LSMDB_env *env;
	DB_cmd_data cmd[1];
	unsigned flags;
	char *path;
	int mode;
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
	DB_txn *child;
	LSMDB_txn *txn;
	DB_cursor *cursor;
};
struct DB_cursor {
	DB_base const *isa;
	DB_txn *txn;
	LSMDB_cursor *cursor;
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
	env->isa = db_base_lsmdb;

	int rc = mdberr(lsmdb_env_create(&env->env));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) db_env_destroy(env);
	return rc;
}
DB_FN int db__env_get_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_FLAGS: *(unsigned *)data = env->flags; return 0;
	case DB_CFG_FILENAME: *(char const **)data = env->path; return 0;
	case DB_CFG_FILEMODE: *(int *)data = env->mode; return 0;
	default: return DB_ENOTSUP;
	}
}
DB_FN int db__env_set_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_MAPSIZE: {
		size_t *const sp = data;
		return mdberr(lsmdb_env_set_mapsize(env->env, *sp));
	} case DB_CFG_COMPARE: return DB_ENOTSUP;
	case DB_CFG_COMMAND: *env->cmd = *(DB_cmd_data *)data; return 0;
	case DB_CFG_TXNSIZE: return 0;
	case DB_CFG_FLAGS: env->flags = *(unsigned *)data; return 0;
	case DB_CFG_FILENAME:
		free(env->path);
		env->path = data ? strdup(data) : NULL;
		if(data && !env->path) return DB_ENOMEM;
		return 0;
	case DB_CFG_FILEMODE: env->mode = *(int *)data; return 0;
	default: return DB_ENOTSUP;
	}
}
DB_FN int db__env_open0(DB_env *const env) {
	if(!env) return DB_EINVAL;
	return mdberr(lsmdb_env_open(env->env, env->path, env->flags | MDB_NOSUBDIR, env->mode));
}
DB_FN void db__env_destroy(DB_env *const env) {
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

DB_FN size_t db__txn_size(DB_env *const env) {
	return sizeof(struct DB_txn);
}
DB_FN int db__txn_begin_init(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn *const txn) {
	if(!env) return DB_EINVAL;
	if(!txn) return DB_EINVAL;
	if(parent && parent->child) return DB_BAD_TXN;
	assert_zeroed(txn, 1);
	int rc = 0;
	txn->isa = db_base_lsmdb;

	rc = mdberr(lsmdb_txn_begin(env->env, parent ? parent->txn : NULL, flags, &txn->txn));
	if(rc < 0) goto cleanup;
	txn->env = env;
	txn->parent = parent;
	txn->child = NULL;

	if(parent) parent->child = txn;
cleanup:
	if(rc < 0) db_txn_abort_destroy(txn);
	return 0;
}
DB_FN int db__txn_commit_destroy(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	int rc = 0;
	if(txn->child) {
		rc = db_txn_commit(txn->child); txn->child = NULL;
		if(rc < 0) goto cleanup;
	}
	rc = mdberr(lsmdb_autocompact(txn->txn));
	if(rc < 0) goto cleanup;
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	rc = mdberr(lsmdb_txn_commit(txn->txn)); txn->txn = NULL;
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
	lsmdb_txn_abort(txn->txn); txn->txn = NULL;
	if(txn->parent) txn->parent->child = NULL;
	txn->isa = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->txn = NULL;
	assert_zeroed(txn, 1);
}
DB_FN int db__txn_upgrade(DB_txn *const txn, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	return DB_ENOTSUP;
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
	return mdberr(lsmdb_txn_get_flags(txn->txn, flags));
}
DB_FN int db__txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	if(!txn) return DB_EINVAL;
	return lsmdb_cmp(txn->txn, (MDB_val *)a, (MDB_val *)b);
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

DB_FN int db__get(DB_txn *const txn, DB_val *const key, DB_val *const data) {
	if(!txn) return DB_EINVAL;
	return mdberr(lsmdb_get(txn->txn, (MDB_val *)key, (MDB_val *)data));
}
DB_FN int db__put(DB_txn *const txn, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	MDB_val null = { 0, NULL };
	MDB_val *const k = (MDB_val *)key;
	MDB_val *const d = data ? (MDB_val *)data : &null;
	return mdberr(lsmdb_put(txn->txn, k, d, flags));
}
DB_FN int db__del(DB_txn *const txn, DB_val *const key, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	return mdberr(lsmdb_del(txn->txn, (MDB_val *)key, flags));
}
DB_FN int db__cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len) {
	if(!txn) return DB_EINVAL;
	if(!txn->env->cmd->fn) return DB_EINVAL;
	return txn->env->cmd->fn(txn->env->cmd->ctx, txn, buf, len);
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
	cursor->isa = db_base_lsmdb;
	cursor->txn = txn;
	rc = mdberr(lsmdb_cursor_open(txn->txn, &cursor->cursor));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) db_cursor_destroy(cursor);
	return rc;
}
DB_FN void db__cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	lsmdb_cursor_close(cursor->cursor); cursor->cursor = NULL;
	cursor->isa = NULL;
	cursor->txn = NULL;
	cursor->cursor = NULL;
	assert_zeroed(cursor, 1);
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	return mdberr(lsmdb_cursor_clear(cursor->cursor));
}
DB_FN int db__cursor_txn(DB_cursor *const cursor, DB_txn **const out) {
	if(!cursor) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	*out = cursor->txn;
	return 0;
}
DB_FN int db__cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	if(!cursor) return DB_EINVAL;
	return lsmdb_cmp(lsmdb_cursor_txn(cursor->cursor), (MDB_val *)a, (MDB_val *)b);
}

DB_FN int db__cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	return mdberr(lsmdb_cursor_current(cursor->cursor, (MDB_val *)key, (MDB_val *)data));
}
DB_FN int db__cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return mdberr(lsmdb_cursor_seek(cursor->cursor, (MDB_val *)key, (MDB_val *)data, dir));
}
DB_FN int db__cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return mdberr(lsmdb_cursor_first(cursor->cursor, (MDB_val *)key, (MDB_val *)data, dir));
}
DB_FN int db_cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return mdberr(lsmdb_cursor_next(cursor->cursor, (MDB_val *)key, (MDB_val *)data, dir));
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
	return mdberr(lsmdb_cursor_put(cursor->cursor, k, d, flags));
}
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	if(flags) return DB_EINVAL;
	return mdberr(lsmdb_cursor_del(cursor->cursor));
}

