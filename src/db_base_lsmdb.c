// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdlib.h>
#include "db_base_internal.h"
#include "lsmdb/lsmdb.h"

struct DB_env {
	DB_base const *isa;
	LSMDB_env *env;
	DB_cmd_data cmd[1];
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
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

DB_FN int db__env_create(DB_env **const out) {
	if(!out) return DB_EINVAL;
	int rc = 0;
	DB_env *env = calloc(1, sizeof(DB_env));
	if(!env) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;
	env->isa = db_base_lsmdb;

	int rc = mdberr(lsmdb_env_create(&env->env));
	if(rc < 0) goto cleanup;
	*out = env; env = NULL;
cleanup:
	db_env_close(env); env = NULL;
	return rc;
}
DB_FN int db__env_get_config(DB_env *const env, unsigned const type, void *data) {
	return DB_ENOTSUP; // TODO
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
	default: return DB_ENOTSUP;
	}
}
DB_FN int db__env_open(DB_env *const env, char const *const name, unsigned const flags, unsigned const mode) {
	if(!env) return DB_EINVAL;
	return mdberr(lsmdb_env_open(env->env, name, flags | MDB_NOSUBDIR, mode));
}
DB_FN void db__env_close(DB_env *env) {
	if(!env) return;
	lsmdb_env_close(env->env); env->env = NULL;
	env->isa = NULL;
	env->cmd->fn = NULL;
	env->cmd->ctx = NULL;
	free(env); env = NULL;
}

DB_FN int db__txn_begin(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn **const out) {
	if(!env) return DB_EINVAL;
	int rc = 0;
	DB_txn *txn = calloc(1, sizeof(DB_txn));
	if(!txn) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;
	txn->isa = db_base_lsmdb;

	rc = mdberr(lsmdb_txn_begin(env->env, parent ? parent->txn : NULL, flags, &txn->txn));
	if(rc < 0) goto cleanup;
	txn->env = env;
	txn->parent = parent;
	*out = txn; txn = NULL;
cleanup:
	db_txn_abort(txn); txn = NULL;
	return 0;
}
DB_FN int db__txn_commit(DB_txn *txn) {
	if(!txn) return DB_EINVAL;
	int rc = mdberr(lsmdb_autocompact(txn->txn));
	if(rc < 0) {
		db_txn_abort(txn); txn = NULL;
		return rc;
	}
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	rc = mdberr(lsmdb_txn_commit(txn->txn));
	txn->isa = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->txn = NULL;
	free(txn); txn = NULL;
	return rc;
}
DB_FN void db__txn_abort(DB_txn *txn) {
	if(!txn) return;
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	lsmdb_txn_abort(txn->txn); txn->txn = NULL;
	txn->isa = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->txn = NULL;
	free(txn); txn = NULL;
}
DB_FN void db__txn_reset(DB_txn *const txn) {
	if(!txn) return;
	lsmdb_txn_reset(txn->txn);
}
DB_FN int db__txn_renew(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	return mdberr(lsmdb_txn_renew(txn->txn));
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
	if(txn->parent) return db_txn_cursor(txn->parent, out);
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

DB_FN int db__cursor_open(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	int rc = 0;
	DB_cursor *cursor = calloc(1, sizeof(DB_cursor));
	if(!cursor) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;
	cursor->isa = db_base_lsmdb;

	rc = mdberr(lsmdb_cursor_open(txn->txn, c));
	if(rc < 0) goto cleanup;
	cursor->txn = txn;
	cursor->cursor = c;
	*out = cursor; cursor = NULL;
cleanup:
	db_cursor_close(cursor); cursor = NULL;
	return rc;
}
DB_FN void db__cursor_close(DB_cursor *cursor) {
	if(!cursor) return;
	lsmdb_cursor_close(cursor->cursor); cursor->cursor = NULL;
	cursor->isa = NULL;
	cursor->txn = NULL;
	cursor->cursor = NULL;
	free(cursor); cursor = NULL;
}
DB_FN void db__cursor_reset(DB_cursor *const cursor) {
	// Do nothing.
}
DB_FN int db__cursor_renew(DB_txn *const txn, DB_cursor **const out) {
	if(!cursor) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	if(*out) {
		out[0]->txn = txn;
		return mdberr(lsmdb_cursor_renew(txn->txn, out[0]->cursor));
	}
	return db_cursor_open(txn, out);
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

