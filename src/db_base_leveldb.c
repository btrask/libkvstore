// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#ifdef LEVELDB_AS_ROCKSDB
#include "rocks_wrapper.h"
#else
#include <leveldb/c.h>
#endif

#include "liblmdb/lmdb.h"
#include "db_base_internal.h"
#include "db_wrbuf.h"
#include "common.h"

struct DB_env {
	DB_base const *isa;
	leveldb_options_t *opts;
	leveldb_filterpolicy_t *filterpolicy;
	leveldb_comparator_t *comparator;
	leveldb_t *db;
	DB_env *tmpenv;
	leveldb_writeoptions_t *wopts;
	DB_cmp_data cmp[1];
	DB_cmd_data cmd[1];
	unsigned flags;
	char *path;
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
	DB_txn *child;
	unsigned flags;
	leveldb_readoptions_t *ropts;
	leveldb_snapshot_t const *snapshot; // For DB_RDONLY
	DB_txn *tmptxn; // For DB_RDWR
	DB_cursor *cursor;
};
struct DB_cursor {
	DB_base const *isa;
	DB_txn *txn;
	DB_wrbuf wrbuf[1];
};


// DEBUG
static char *tohex(DB_val const *const x) {
	char const *const map = "0123456789abcdef";
	char const *const buf = x->data;
	char *const hex = calloc(x->size*2+1, 1);
	if(!hex) return NULL;
	for(size_t i = 0; i < x->size; ++i) {
		hex[i*2+0] = map[0xf & (buf[i] >> 4)];
		hex[i*2+1] = map[0xf & (buf[i] >> 0)];
	}
	return hex;
}


static int cmp_default(DB_val const *const a, DB_val const *const b) {
	int x = memcmp(a->data, b->data, MIN(a->size, b->size));
	if(0 != x) return x;
	if(a->size < b->size) return -1;
	if(a->size > b->size) return +1;
	return 0;
}
static int cmp_internal(DB_env *const env, DB_val const *const a, DB_val const *const b) {
	assert(env);
//	DB_cmp_func_bad cmp = env->cmp->fn;
//	if(!cmp) cmp = cmp_default;
	return cmp_default(a, b);
}
static int cmp_wrap(void *ctx, char const *a, size_t alen, char const *b, size_t blen) {
	DB_env *env = ctx;
	DB_val const aval = {alen, (void *)a};
	DB_val const bval = {blen, (void *)b};
	return cmp_internal(env, &aval, &bval);
}
static char const *cmp_name(void *ctx) {
	return "leveldb.BytewiseComparator"; // For compatibility with existing databases.
}
static void cmp_destructor(void *ctx) {
	// Do nothing
}


struct storage {
	struct storage *next;
	size_t size;
	unsigned char data[0];
};
static void storage_free(struct storage *const head) {
	struct storage *cur = head;
	while(cur) {
		struct storage *const tmp = cur->next;
		free(cur);
		cur = tmp;
	}
}

static DB_base const db_base_leveldb_internal[1];

typedef struct {
	DB_base const *isa;
	leveldb_t *db;
	leveldb_readoptions_t *ropts;
	DB_cmp_data cmp[1];
} LDB_txn;
typedef struct {
	DB_base const *isa;
	leveldb_iterator_t *iter;
	DB_cmp_data cmp[1];
	bool valid;
	bool storage_current;
	struct storage *keys;
	struct storage *vals;
} LDB_cursor;
static size_t ldb_cursor_size(DB_txn *const txn) {
	return sizeof(LDB_cursor);
}
static void ldb_cursor_destroy(LDB_cursor *const cursor);
static int ldb_cursor_init(LDB_txn *const txn, LDB_cursor *const cursor) {
	if(!txn) return DB_EINVAL;
	if(!cursor) return DB_EINVAL;
	int rc = 0;
	cursor->isa = db_base_leveldb_internal;
	cursor->iter = leveldb_create_iterator(txn->db, txn->ropts);
	if(!cursor->iter) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;

	*cursor->cmp = *txn->cmp;
	cursor->valid = false;

	cursor->storage_current = false;
	cursor->keys = NULL;
	cursor->vals = NULL;
cleanup:
	if(rc < 0) ldb_cursor_destroy(cursor);
	return rc;
}
static void ldb_cursor_storage_invalidate(LDB_cursor *const cursor) {
	if(!cursor) return;
	cursor->storage_current = false;
	storage_free(cursor->keys); cursor->keys = NULL;
	storage_free(cursor->vals); cursor->vals = NULL;
}
static void ldb_cursor_destroy(LDB_cursor *const cursor) {
	if(!cursor) return;
	cursor->valid = false;
	ldb_cursor_storage_invalidate(cursor);
	leveldb_iter_destroy(cursor->iter); cursor->iter = NULL;
	cursor->cmp->fn = NULL;
	cursor->cmp->ctx = NULL;
	cursor->isa = NULL;
	assert_zeroed(cursor, 1);
}
static int ldb_cursor_clear(LDB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	cursor->valid = false;
	ldb_cursor_storage_invalidate(cursor);
	return 0;
}
static int ldb_cursor_cmp(LDB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	assert(cursor);
//	DB_cmp_func_bad cmp = cursor->cmp->fn;
//	if(!cmp) cmp = cmp_default;
	return cmp_default((DB_val const *)a, (DB_val const *)b);
}
static int ldb_cursor_current(LDB_cursor *const cursor, DB_val *const key, DB_val *const val) {
	if(!cursor) return DB_EINVAL;
	if(!cursor->valid) return DB_NOTFOUND;
	if(!key && !val) return 0;

	if(!cursor->storage_current) {
		size_t size = 0;
		unsigned char const *data = NULL;
		struct storage *k = NULL;
		struct storage *v = NULL;

		data = (unsigned char const *)leveldb_iter_key(cursor->iter, &size);
		assert(data);
		k = malloc(sizeof(struct storage)+size);
		if(!k) {
			FREE(&k);
			FREE(&v);
			return DB_ENOMEM;
		}
		k->next = cursor->keys;
		k->size = size;
		memcpy(k->data, data, size);

		data = (unsigned char const *)leveldb_iter_value(cursor->iter, &size);
		assert(data);
		v = malloc(sizeof(struct storage)+size);
		if(!v) {
			FREE(&k);
			FREE(&v);
			return DB_ENOMEM;
		}
		v->next = cursor->vals;
		v->size = size;
		memcpy(v->data, data, size);

		cursor->keys = k;
		cursor->vals = v;
		cursor->storage_current = true;
	}

	assert(cursor->storage_current);
	assert(cursor->keys);
	assert(cursor->vals);
	if(key) *key = (DB_val){ cursor->keys->size, cursor->keys->data };
	if(val) *val = (DB_val){ cursor->vals->size, cursor->vals->data };
	return 0;
}
static int ldb_cursor_seek(LDB_cursor *const cursor, DB_val *const key, DB_val *const val, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(!key) return DB_EINVAL;
	DB_val const orig[1] = { *key };
	leveldb_iter_seek(cursor->iter, key->data, key->size);
	cursor->valid = !!leveldb_iter_valid(cursor->iter);
	cursor->storage_current = false;
	int rc = ldb_cursor_current(cursor, key, val);
	if(dir > 0) return rc;
	if(dir < 0) {
		if(rc < 0) {
			leveldb_iter_seek_to_last(cursor->iter);
		} else if(0 != ldb_cursor_cmp(cursor, key, orig)) {
			leveldb_iter_prev(cursor->iter);
		} else return rc;
		cursor->valid = !!leveldb_iter_valid(cursor->iter);
		cursor->storage_current = false;
		return ldb_cursor_current(cursor, key, val);
	}
	if(rc < 0) return rc;
	if(0 == ldb_cursor_cmp(cursor, key, orig)) return rc;
	cursor->valid = 0;
	return DB_NOTFOUND;
}
static int ldb_cursor_first(LDB_cursor *const cursor, DB_val *const key, DB_val *const val, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(0 == dir) return DB_EINVAL;
	if(dir > 0) leveldb_iter_seek_to_first(cursor->iter);
	if(dir < 0) leveldb_iter_seek_to_last(cursor->iter);
	cursor->valid = !!leveldb_iter_valid(cursor->iter);
	cursor->storage_current = false;
	return ldb_cursor_current(cursor, key, val);
}
static int ldb_cursor_next(LDB_cursor *const cursor, DB_val *const key, DB_val *const val, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(!cursor->valid) return ldb_cursor_first(cursor, key, val, dir);
	if(0 == dir) return DB_EINVAL;
	if(dir > 0) leveldb_iter_next(cursor->iter);
	if(dir < 0) leveldb_iter_prev(cursor->iter);
	cursor->valid = !!leveldb_iter_valid(cursor->iter);
	cursor->storage_current = false;
	return ldb_cursor_current(cursor, key, val);
}


DB_FN size_t db__env_size(void) {
	return sizeof(struct DB_env);
}
DB_FN int db__env_init(DB_env *const env) {
	if(!env) return DB_EINVAL;
	assert_zeroed(env, 1);
	env->isa = db_base_leveldb;

	env->opts = leveldb_options_create();
	if(!env->opts) {
		db_env_destroy(env);
		return DB_ENOMEM;
	}

	leveldb_options_set_create_if_missing(env->opts, 1);
	leveldb_options_set_compression(env->opts, leveldb_snappy_compression);

	// TODO: Make this configurable?
	// We should probably have a single general config function
	// rather than a function per option, so that adding new options
	// doesn't require changes to existing back-ends.
	leveldb_options_set_block_size(env->opts, 1024*16);

	int maxfiles = 100; // Safe default
//#ifdef __POSIX__
	struct rlimit lim[1];
	getrlimit(RLIMIT_NOFILE, lim);
	maxfiles = lim->rlim_cur / 3;
//#endif
	leveldb_options_set_max_open_files(env->opts, maxfiles);

	env->filterpolicy = leveldb_filterpolicy_create_bloom(10);
	if(!env->filterpolicy) {
		db_env_destroy(env);
		return DB_ENOMEM;
	}
	leveldb_options_set_filter_policy(env->opts, env->filterpolicy);
	env->comparator = leveldb_comparator_create(env, cmp_destructor, cmp_wrap, cmp_name);
	if(!env->comparator) {
		db_env_destroy(env);
		return DB_ENOMEM;
	}
	leveldb_options_set_comparator(env->opts, env->comparator);
	env->cmp->fn = NULL;
	env->cmp->ctx = NULL;
	env->flags = 0;
	env->path = NULL;

	int rc = db_env_create_base("mdb", &env->tmpenv);
	if(rc < 0) {
		db_env_destroy(env);
		return rc;
	}

	env->wopts = leveldb_writeoptions_create();
	if(!env->wopts) {
		db_env_destroy(env);
		return DB_ENOMEM;
	}
	env->flags &= ~DB_NOSYNC;
	leveldb_writeoptions_set_sync(env->wopts, 1);

	return 0;
}
DB_FN int db__env_get_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_COMMAND: *(DB_cmd_data *)data = *env->cmd; return 0;
	case DB_CFG_KEYSIZE: return db_env_get_config(env->tmpenv, type, data);
	case DB_CFG_TXNSIZE: return db_env_get_config(env->tmpenv, DB_CFG_MAPSIZE, data);
	case DB_CFG_FLAGS: *(unsigned *)data = env->flags; return 0;
	case DB_CFG_FILENAME: *(char const **)data = env->path; return 0;
	default: return DB_ENOTSUP;
	}
}
DB_FN int db__env_set_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_MAPSIZE: return 0;
	case DB_CFG_COMPARE: return DB_ENOTSUP; //*env->cmp = *(DB_cmp_data *)data; return 0;
	case DB_CFG_COMMAND: *env->cmd = *(DB_cmd_data *)data; return 0;
	case DB_CFG_TXNSIZE: return db_env_set_config(env->tmpenv, DB_CFG_MAPSIZE, data);
	case DB_CFG_FLAGS:
		env->flags = DB_NOSYNC & *(unsigned *)data;
		leveldb_writeoptions_set_sync(env->wopts, !(DB_NOSYNC & env->flags));
		return 0;
	case DB_CFG_FILENAME:
		free(env->path);
		env->path = data ? strdup(data) : NULL;
		if(data && !env->path) return DB_ENOMEM;
		return 0;
	default: return DB_ENOTSUP;
	}
}
DB_FN int db__env_open0(DB_env *const env) {
	if(!env) return DB_EINVAL;
	char *err = NULL;
	env->db = leveldb_open(env->opts, env->path, &err);
	if(err) fprintf(stderr, "Database error %s\n", err);
	leveldb_free(err);
	if(!env->db || err) return -1; // TODO: Parse error string?

	int rc = 0;
	if(env->cmp->fn) { // TODO: Currently unsupported
		rc = db_env_set_config(env->tmpenv, DB_CFG_COMPARE, &env->cmp);
		if(rc < 0) return rc;
	}

	char tmppath[512]; // TODO
	if(snprintf(tmppath, sizeof(tmppath), "%s/tmp.mdb", env->path) < 0) return -1;

	// Notes on flags:
	// MDB_NOSYNC serves no point, since temp txns are never committed.
	// MDB_WRITEMAP unfortunately doesn't work with nested txns.
	rc = db_env_open(env->tmpenv, tmppath, 0, 0600);
	if(rc < 0) return rc;
	(void) remove(tmppath);

	return 0;
}
DB_FN void db__env_destroy(DB_env *const env) {
	if(!env) return;
	if(env->opts) {
		leveldb_options_destroy(env->opts); env->opts = NULL;
	}
	if(env->filterpolicy) {
		leveldb_filterpolicy_destroy(env->filterpolicy); env->filterpolicy = NULL;
	}
	if(env->comparator) {
		leveldb_comparator_destroy(env->comparator); env->comparator = NULL;
	}
	if(env->db) {
		leveldb_close(env->db); env->db = NULL;
	}
	db_env_close(env->tmpenv); env->tmpenv = NULL;
	if(env->wopts) {
		leveldb_writeoptions_destroy(env->wopts); env->wopts = NULL;
	}
	env->isa = NULL;
	env->cmp->fn = NULL;
	env->cmp->ctx = NULL;
	env->cmd->fn = NULL;
	env->cmd->ctx = NULL;
	env->flags = 0;
	free(env->path); env->path = NULL;
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
	txn->isa = db_base_leveldb;
	txn->env = env;
	txn->parent = parent;
	txn->child = NULL;
	txn->flags = flags;
	txn->ropts = leveldb_readoptions_create();
	if(!txn->ropts) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;

	if(DB_RDONLY & flags) {
		txn->tmptxn = NULL;
		txn->snapshot = leveldb_create_snapshot(txn->env->db);
		if(!txn->snapshot) rc = DB_ENOMEM;
		if(rc < 0) goto cleanup;
		leveldb_readoptions_set_snapshot(txn->ropts, txn->snapshot);
	} else {
		rc = db_txn_begin(env->tmpenv, parent ? parent->tmptxn : NULL, flags, &txn->tmptxn);
		if(rc < 0) goto cleanup;
		txn->snapshot = NULL;
	}

	if(parent) parent->child = txn;
cleanup:
	if(rc < 0) db_txn_abort_destroy(txn);
	return rc;
}
DB_FN int db__txn_commit_destroy(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	leveldb_writebatch_t *batch = NULL;
	DB_cursor *cursor = NULL;
	DB_val key[1], data[1];
	int rc = 0;
	if(DB_RDONLY & txn->flags) goto cleanup;
	assert(txn->tmptxn);
	if(txn->child) {
		rc = db_txn_commit(txn->child); txn->child = NULL;
		if(rc < 0) goto cleanup;
	}

	if(txn->parent) {
		db_cursor_close(txn->cursor); txn->cursor = NULL;
		rc = db_txn_commit(txn->tmptxn); txn->tmptxn = NULL;
		goto cleanup;
	}

	rc = db_txn_cursor(txn->tmptxn, &cursor);
	if(rc < 0) goto cleanup;
	batch = leveldb_writebatch_create();
	if(!batch) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;
	rc = db_cursor_first(cursor, key, data, +1);
	for(; rc >= 0; rc = db_cursor_next(cursor, key, data, +1)) {
		switch(db_wrbuf_type(data)) {
		case DB_WRBUF_DEL:
			leveldb_writebatch_delete(batch,
				key->data, key->size);
			break;
		case DB_WRBUF_PUT:
			db_wrbuf_trim(data);
			leveldb_writebatch_put(batch,
				key->data, key->size,
				data->data, data->size);
			break;
		default: assert(0);
		}
	}
	if(DB_NOTFOUND == rc) rc = 0;
	if(rc < 0) goto cleanup;

	char *err = NULL;
	leveldb_write(txn->env->db, txn->env->wopts, batch, &err);
	leveldb_free(err);
	if(err) rc = DB_EIO; // TODO
	if(rc < 0) goto cleanup;

cleanup:
	leveldb_writebatch_destroy(batch); batch = NULL;
	cursor = NULL;
	db_txn_abort_destroy(txn);
	return 0;
}
DB_FN void db__txn_abort_destroy(DB_txn *const txn) {
	if(!txn) return;
	if(txn->child) {
		db_txn_abort(txn->child); txn->child = NULL;
	}
	if(txn->snapshot) {
		leveldb_readoptions_set_snapshot(txn->ropts, NULL);
		leveldb_release_snapshot(txn->env->db, txn->snapshot); txn->snapshot = NULL;
	}
	leveldb_readoptions_destroy(txn->ropts); txn->ropts = NULL;
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	db_txn_abort(txn->tmptxn); txn->tmptxn = NULL;
	if(txn->parent) txn->parent->child = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->flags = 0;
	txn->isa = NULL;
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
	if(!flags) return DB_EINVAL;
	*flags = txn->flags;
	return 0;
}
DB_FN int db__txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	assert(txn); // We can't report an error from this function.
	return cmp_internal(txn->env, a, b);
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
	return db_helper_put(txn, key, data, flags);
}
DB_FN int db__del(DB_txn *const txn, DB_val *const key, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	return db_wrbuf_del_direct(txn->tmptxn, key, flags);
}
DB_FN int db__cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len) {
	if(!txn) return DB_EINVAL;
	if(!txn->env->cmd->fn) return DB_EINVAL;
	int rc = txn->env->cmd->fn(txn->env->cmd->ctx, txn, buf, len);
	assert(txn->isa); // Simple check that we weren't committed/aborted.
	return rc;
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
	DB_cursor *t = NULL;
	DB_cursor *m = NULL;
	LDB_txn mtxn = {
		.isa = db_base_leveldb_internal,
		.db = txn->env->db,
		.ropts = txn->ropts,
		.cmp = { *txn->env->cmp },
	};
	int rc = 0;

	cursor->isa = db_base_leveldb;
	cursor->txn = txn;

	if(txn->tmptxn) {
		rc = db_cursor_open(txn->tmptxn, &t);
		if(rc < 0) goto cleanup;
	}
	rc = db_cursor_open((DB_txn *)&mtxn, &m);
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
	assert(cursor); // We can't report an error from this function.
	return db_txn_cmp(cursor->txn, a, b);
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
	int rc = db_wrbuf_put(cursor->wrbuf, key, data, flags);
	// Invalidating here is safe because a put will always end up
	// pointing to the temp cursor.
	ldb_cursor_storage_invalidate((LDB_cursor *)cursor->wrbuf->main);
	return rc;
}
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	int rc = db_wrbuf_del(cursor->wrbuf, flags);
	ldb_cursor_storage_invalidate((LDB_cursor *)cursor->wrbuf->main);
	return rc;
}

#ifdef LEVELDB_AS_ROCKSDB
DB_BASE_V0(rocksdb)
#else
DB_BASE_V0(leveldb)
#endif

static DB_base const db_base_leveldb_internal[1] = {{
	.version = 0,
	.name = "leveldb-cursor",
	.cursor_size = ldb_cursor_size,
	.cursor_init = (void *)ldb_cursor_init,
	.cursor_destroy = (void *)ldb_cursor_destroy,
	.cursor_clear = (void *)ldb_cursor_clear,
	.cursor_current = (void *)ldb_cursor_current,
	.cursor_seek = (void *)ldb_cursor_seek,
	.cursor_first = (void *)ldb_cursor_first,
	.cursor_next = (void *)ldb_cursor_next,
}};

