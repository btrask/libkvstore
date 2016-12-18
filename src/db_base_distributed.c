// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "liblmdb/lmdb.h"
#include "db_base_internal.h"
#include "db_wrbuf.h"
#include "common.h"

struct DB_env {
	DB_base const *isa;
	DB_env *main;
	DB_env *temp;
	DB_cmd_data cmd[1];
	DB_commit_data commit[1];
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
	DB_txn *child;
	DB_txn *main;
	DB_txn *temp;
	DB_cursor *cursor;
};
struct DB_cursor {
	DB_base const *isa;
	DB_txn *txn;
	DB_wrbuf wrbuf[1];
};

DB_FN size_t db__env_size(void) {
	return sizeof(struct DB_env);
}
DB_FN int db__env_init(DB_env *const env) {
	if(!env) return DB_EINVAL;
	assert_zeroed(env, 1);
	int rc = 0;
	env->isa = db_base_distributed;

	rc = db_env_create_base("mdb", &env->main);
	if(rc < 0) goto cleanup;
	rc = db_env_create_base("mdb", &env->temp);
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) db_env_destroy(env);
	return rc;
}
DB_FN int db__env_get_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_COMMAND: *(DB_cmd_data *)data = *env->cmd; return 0;
	case DB_CFG_INNERDB: *(DB_env **)data = env->main; return 0;
	case DB_CFG_COMMIT: *(DB_commit_data *)data = *env->commit; return 0;
	default: return db_env_get_config(env->main, type, data);
	}
}
DB_FN int db__env_set_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	// TODO: We should have a way of swapping out the inner env.
	// And also a way of getting it to configure directly?
	// Ownership becomes a little bit complex...
	switch(type) {
	case DB_CFG_TXNSIZE: return DB_ENOTSUP; // TODO
	case DB_CFG_COMMAND: *env->cmd = *(DB_cmd_data *)data; return 0;
	case DB_CFG_INNERDB:
		db_env_close(env->main);
		env->main = (DB_env *)data;
		return 0;
	case DB_CFG_COMMIT: *env->commit = *(DB_commit_data *)data; return 0;
	default: return db_env_set_config(env->main, type, data);
	}
}
DB_FN int db__env_open0(DB_env *const env) {
	if(!env) return DB_EINVAL;
	char const *path = NULL;
	char sub[1023+1];
	int mode;
	int rc;
	rc = db_env_open0(env->main);
	if(rc < 0) goto cleanup;

	rc = db_env_get_config(env->main, DB_CFG_FILENAME, &path);
	if(rc < 0) goto cleanup;
	if(!path) rc = DB_EINVAL;
	if(rc < 0) goto cleanup;

	rc = db_env_get_config(env->main, DB_CFG_FILEMODE, &mode);
	if(rc < 0) mode = 0600;

	rc = snprintf(sub, sizeof(sub), "%s/tmp.db", path);
	if(rc < 0 || rc >= sizeof(sub)) rc = DB_EIO;
	if(rc < 0) goto cleanup;
	rc = db_env_open(env->temp, sub, 0, mode);
	if(rc < 0) goto cleanup;
cleanup:
	path = NULL;
	return rc;
}
DB_FN void db__env_destroy(DB_env *const env) {
	if(!env) return;
	db_env_close(env->main); env->main = NULL;
	db_env_close(env->temp); env->temp = NULL;
	env->isa = NULL;
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
	txn->isa = db_base_distributed;
	txn->env = env;
	txn->parent = parent;
	txn->child = NULL;

	rc = db_txn_begin(env->main, parent ? parent->main : NULL, DB_RDONLY, &txn->main);
	if(rc < 0) goto cleanup;
	if(!(DB_RDONLY & flags)) {
		rc = db_txn_begin(env->temp, parent ? parent->temp : NULL, flags, &txn->temp);
		if(rc < 0) goto cleanup;
	}

	if(parent) parent->child = txn;
cleanup:
	if(rc < 0) db_txn_abort_destroy(txn);
	return rc;
}
DB_FN int db__txn_commit_destroy(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	int rc = 0;
	if(!txn->temp) goto cleanup; // DB_RDONLY
	if(txn->child) {
		rc = db_txn_commit(txn->child); txn->child = NULL;
		if(rc < 0) goto cleanup;
	}

	if(txn->parent) {
		db_cursor_close(txn->cursor); txn->cursor = NULL;
		rc = db_txn_commit(txn->temp); txn->temp = NULL;
		goto cleanup;
	}

	if(!txn->env->commit->fn) rc = DB_PANIC;
	if(rc < 0) goto cleanup;
	// TODO: How do we report puts and dels to the cb?
	rc = txn->env->commit->fn(txn->env->commit->ctx, txn->env, NULL);
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
	db_txn_abort(txn->main); txn->main = NULL;
	db_txn_abort(txn->temp); txn->temp = NULL;
	if(txn->parent) txn->parent->child = NULL;
	txn->isa = NULL;
	txn->env = NULL;
	txn->parent = NULL;
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
	return db_txn_get_flags(txn->temp, flags);
}
DB_FN int db__txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	return db_txn_cmp(txn->temp, a, b);
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
	return db_helper_get(txn, key, data);
}
DB_FN int db__put(DB_txn *const txn, DB_val *const key, DB_val *const data, unsigned const flags) {
	return db_helper_put(txn, key, data, flags); // TODO
}
DB_FN int db__del(DB_txn *const txn, DB_val *const key, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	return db_wrbuf_del_direct(txn->temp, key, flags); // TODO
}
DB_FN int db__cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len) {
	if(!txn) return DB_EINVAL;
	if(!txn->env->cmd->fn) return DB_EINVAL;
	int rc = txn->env->cmd->fn(txn->env->cmd->ctx, txn, buf, len); // TODO
	assert(txn->isa); // Simple check that we weren't committed/aborted.
	return rc;
}

DB_FN int db__countr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_countr(txn, range, out);
}
DB_FN int db__delr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_delr(txn, range, out); // TODO
}

DB_FN size_t db__cursor_size(DB_txn *const txn) {
	return sizeof(struct DB_cursor);
}
DB_FN int db__cursor_init(DB_txn *const txn, DB_cursor *const cursor) {
	if(!txn) return DB_EINVAL;
	if(!cursor) return DB_EINVAL;
	assert_zeroed(cursor, 1);
	DB_cursor *t = NULL;
	DB_cursor *m = NULL;
	int rc = 0;
	cursor->isa = db_base_distributed;
	cursor->txn = txn; // TODO: Open on root txn?

	rc = db_cursor_open(txn->temp, &t);
	if(rc < 0) goto cleanup;
	rc = db_cursor_open(txn->main, &m);
	if(rc < 0) goto cleanup;
	rc = db_wrbuf_init(cursor->wrbuf, t, m);
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) {
		db_cursor_close(t); t = NULL;
		db_cursor_close(m); m = NULL;
		db_cursor_destroy(cursor);
	}
	return rc;
}
DB_FN void db__cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	db_wrbuf_destroy(cursor->wrbuf);
	cursor->isa = NULL;
	cursor->txn = NULL;
	assert_zeroed(cursor, 1);
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_clear(cursor->wrbuf);
}
DB_FN int db__cursor_txn(DB_cursor *const cursor, DB_txn **const out) {
	if(!cursor) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	*out = cursor->txn;
	return 0;
}
DB_FN int db__cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	assert(cursor);
	return db_cursor_cmp(cursor->wrbuf->main, a, b);
}

DB_FN int db__cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_current(cursor->wrbuf, key, data);
}
DB_FN int db__cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_seek(cursor->wrbuf, key, data, dir);
}
DB_FN int db__cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_first(cursor->wrbuf, key, data, dir);
}
DB_FN int db__cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_next(cursor->wrbuf, key, data, dir);
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
	return db_wrbuf_put(cursor->wrbuf, key, data, flags); // TODO
}
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_del(cursor->wrbuf, flags); // TODO
}

DB_BASE_V0(distributed)

