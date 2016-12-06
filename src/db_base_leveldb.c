// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For unlink(2)
#include <sys/resource.h>

// TODO: Proper Rocks and Hyper support.
#ifdef DB_BASE_ROCKSDB
#include "rocks_wrapper.h"
#else
#include <leveldb/c.h>
#endif

#include "liblmdb/lmdb.h"
#include "db_base_internal.h"
#include "common.h"

typedef enum {
	S_INVALID = 0,
	S_EQUAL,
	S_PENDING,
	S_PERSIST,
} DB_state;

enum {
	KEY_TOMBSTONE = 'T',
	KEY_PRESENT = 'P',
};

typedef struct LDB_cursor LDB_cursor;

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
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
	unsigned flags;
	leveldb_readoptions_t *ropts;
	leveldb_snapshot_t const *snapshot;
	DB_txn *tmptxn;
	DB_cursor *cursor;
};
struct DB_cursor {
	DB_base const *isa;
	DB_txn *txn;
	DB_state state;
	DB_cursor *pending;
	LDB_cursor *persist;
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


static char tombstone_get(DB_val const *const data) {
	assert(data);
	assert(data->size >= 1);
	return ((char const *)data->data)[0];
}
static void tombstone_trim(DB_val *const data) {
	if(!data) return;
	assert(KEY_PRESENT == tombstone_get(data));
	data->data++;
	data->size--;
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

struct LDB_cursor {
	leveldb_iterator_t *iter;
	DB_cmp_data cmp[1];
	bool valid;
	bool storage_current;
	struct storage *keys;
	struct storage *vals;
};
static void ldb_cursor_close(LDB_cursor *const cursor);
static int ldb_cursor_open(leveldb_t *const db, leveldb_readoptions_t *const ropts, DB_cmp_data const *const cmp, LDB_cursor **const out) {
	if(!db) return DB_EINVAL;
	if(!ropts) return DB_EINVAL;
	if(!out) return DB_EINVAL;

	LDB_cursor *cursor = calloc(1, sizeof(struct LDB_cursor));
	if(!cursor) return DB_ENOMEM;

	int rc = 0;
	cursor->iter = leveldb_create_iterator(db, ropts);
	if(!cursor->iter) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;

	*cursor->cmp = *cmp;
	cursor->valid = false;

	cursor->storage_current = false;
	cursor->keys = NULL;
	cursor->vals = NULL;

	*out = cursor; cursor = NULL;
cleanup:
	ldb_cursor_close(cursor);
	return rc;
}
static void ldb_cursor_storage_invalidate(LDB_cursor *const cursor) {
	if(!cursor) return;
	cursor->storage_current = false;
	storage_free(cursor->keys); cursor->keys = NULL;
	storage_free(cursor->vals); cursor->vals = NULL;
}
static void ldb_cursor_close(LDB_cursor *const cursor) {
	if(!cursor) return;
	leveldb_iter_destroy(cursor->iter); cursor->iter = NULL;
	cursor->cmp->fn = NULL;
	cursor->cmp->ctx = NULL;
	cursor->valid = false;
	ldb_cursor_storage_invalidate(cursor);
	assert_zeroed(cursor, 1);
	free(cursor);
}
static int ldb_cursor_clear(LDB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	cursor->valid = false;
	ldb_cursor_storage_invalidate(cursor);
	return 0;
}
static int ldb_cursor_renew(leveldb_t *const db, leveldb_readoptions_t *const ropts, DB_cmp_data const *const cmp, LDB_cursor **const out) {
	if(!out) return DB_EINVAL;
	if(!*out) return ldb_cursor_open(db, ropts, cmp, out);
	LDB_cursor *const cursor = *out;
	leveldb_iter_destroy(cursor->iter); cursor->iter = NULL;
	cursor->iter = leveldb_create_iterator(db, ropts);
	if(!cursor->iter) return DB_ENOMEM;
	*cursor->cmp = *cmp;
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


DB_FN int db__env_create(DB_env **const out) {
	DB_env *env = calloc(1, sizeof(struct DB_env));
	if(!env) return DB_ENOMEM;

	env->isa = db_base_leveldb;

	env->opts = leveldb_options_create();
	if(!env->opts) {
		db_env_close(env);
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
		db_env_close(env);
		return DB_ENOMEM;
	}
	leveldb_options_set_filter_policy(env->opts, env->filterpolicy);
	env->comparator = leveldb_comparator_create(env, cmp_destructor, cmp_wrap, cmp_name);
	if(!env->comparator) {
		db_env_close(env);
		return DB_ENOMEM;
	}
	leveldb_options_set_comparator(env->opts, env->comparator);
	env->cmp->fn = NULL;
	env->cmp->ctx = NULL;

	int rc = db_env_create_base("mdb", &env->tmpenv);
	if(rc < 0) {
		db_env_close(env);
		return rc;
	}

	env->wopts = leveldb_writeoptions_create();
	if(!env->wopts) {
		db_env_close(env);
		return DB_ENOMEM;
	}
	leveldb_writeoptions_set_sync(env->wopts, 1);

	*out = env;
	return 0;
}
DB_FN int db__env_config(DB_env *const env, DB_cfg const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_MAPSIZE: return 0;
	case DB_CFG_COMPARE: return DB_ENOTSUP; //*env->cmp = *(DB_cmp_data *)data; return 0;
	case DB_CFG_COMMAND: *env->cmd = *(DB_cmd_data *)data; return 0;
	case DB_CFG_TXNSIZE: return DB_ENOTSUP;
	default: return DB_ENOTSUP;
	}
}
DB_FN int db__env_open(DB_env *const env, char const *const name, unsigned const flags, unsigned const mode) {
	if(!env) return DB_EINVAL;
	char *err = NULL;
	env->db = leveldb_open(env->opts, name, &err);
	if(err) fprintf(stderr, "Database error %s\n", err);
	leveldb_free(err);
	if(!env->db || err) return -1; // TODO: Parse error string?

	int rc = 0;
	if(env->cmp->fn) { // TODO: Currently unsupported
		rc = db_env_config(env->tmpenv, DB_CFG_COMPARE, &env->cmp);
		if(rc < 0) return rc;
	}

	char tmppath[512]; // TODO
	if(snprintf(tmppath, sizeof(tmppath), "%s/tmp.mdb", name) < 0) return -1;
	rc = db_env_open(env->tmpenv, tmppath, MDB_WRITEMAP, 0600);
	if(rc < 0) return rc;
	(void)unlink(tmppath);

	leveldb_writeoptions_set_sync(env->wopts, !(DB_NOSYNC & flags));
	return 0;
}
DB_FN void db__env_close(DB_env *const env) {
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
	assert_zeroed(env, 1);
	free(env);
}

DB_FN int db__txn_begin(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn **const out) {
	if(!env) return DB_EINVAL;
	if(!out) return DB_EINVAL;

	DB_txn *tmptxn = NULL;
	if(!(DB_RDONLY & flags)) {
		DB_txn *p = parent ? parent->tmptxn : NULL;
		int rc = db_txn_begin(env->tmpenv, p, flags, &tmptxn);
		if(rc < 0) return rc;
	}

	DB_txn *txn = calloc(1, sizeof(struct DB_txn));
	if(!txn) {
		db_txn_abort(tmptxn);
		return DB_ENOMEM;
	}
	txn->isa = db_base_leveldb;
	txn->env = env;
	txn->parent = parent;
	txn->flags = flags;
	txn->ropts = leveldb_readoptions_create();
	txn->snapshot = NULL;
	txn->tmptxn = tmptxn;
	if(!txn->ropts) {
		db_txn_abort(txn);
		return DB_ENOMEM;
	}
	if(DB_RDONLY & flags) {
		int rc = db_txn_renew(txn);
		if(rc < 0) {
			db_txn_abort(txn);
			return rc;
		}
	} else {
		txn->tmptxn = tmptxn;
	}
	*out = txn;
	return 0;
}
DB_FN int db__txn_commit(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	if(DB_RDONLY & txn->flags) {
		db_txn_abort(txn);
		return 0;
	}

	if(txn->parent) {
		assert(0); // TODO
	}

	leveldb_writebatch_t *batch = leveldb_writebatch_create();
	if(!batch) {
		db_txn_abort(txn);
		return DB_ENOMEM;
	}
	assert(txn->tmptxn);
	DB_cursor *cursor = NULL;
	int rc = db_txn_cursor(txn->tmptxn, &cursor);
	if(rc < 0) {
		db_txn_abort(txn);
		return rc;
	}
	DB_val key[1], data[1];
	rc = db_cursor_first(cursor, key, data, +1);
	for(; rc >= 0; rc = db_cursor_next(cursor, key, data, +1)) {
		switch(tombstone_get(data)) {
		case KEY_TOMBSTONE:
			leveldb_writebatch_delete(batch,
				key->data, key->size);
			break;
		case KEY_PRESENT:
			tombstone_trim(data);
			leveldb_writebatch_put(batch,
				key->data, key->size,
				data->data, data->size);
			break;
		default: assert(0);
		}
	}
	cursor = NULL;

	char *err = NULL;
	leveldb_write(txn->env->db, txn->env->wopts, batch, &err);
	leveldb_free(err);
	leveldb_writebatch_destroy(batch);
	if(err) {
		db_txn_abort(txn);
		return -1; // TODO
	}
	db_txn_abort(txn);
	return 0;
}
DB_FN void db__txn_abort(DB_txn *const txn) {
	if(!txn) return;
	if(txn->snapshot) {
		leveldb_readoptions_set_snapshot(txn->ropts, NULL);
		leveldb_release_snapshot(txn->env->db, txn->snapshot); txn->snapshot = NULL;
	}
	leveldb_readoptions_destroy(txn->ropts); txn->ropts = NULL;
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	db_txn_abort(txn->tmptxn); txn->tmptxn = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->flags = 0;
	txn->isa = NULL;
	assert_zeroed(txn, 1);
	free(txn);
}
DB_FN void db__txn_reset(DB_txn *const txn) {
	if(!txn) return;
	assert(txn->flags & DB_RDONLY);
	if(txn->snapshot) {
		leveldb_readoptions_set_snapshot(txn->ropts, NULL);
		leveldb_release_snapshot(txn->env->db, txn->snapshot); txn->snapshot = NULL;
	}
}
DB_FN int db__txn_renew(DB_txn *const txn) {
	// TODO: If renew fails, does the user have to explicitly abort?
	if(!txn) return DB_EINVAL;
	assert(txn->flags & DB_RDONLY);
	assert(!txn->snapshot);
	txn->snapshot = leveldb_create_snapshot(txn->env->db);
	if(!txn->snapshot) return DB_ENOMEM;
	leveldb_readoptions_set_snapshot(txn->ropts, txn->snapshot);
	return 0;
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
	if(flags) *flags = txn->flags;
	return 0;
}
DB_FN int db__txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	assert(txn); // We can't report an error from this function.
	return cmp_internal(txn->env, a, b);
}
DB_FN int db__txn_cursor(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	if(!txn->cursor) {
		int rc = db_cursor_open(txn, &txn->cursor);
		if(rc < 0) return rc;
	}
	if(out) *out = txn->cursor;
	return 0;
}

DB_FN int db__get(DB_txn *const txn, DB_val *const key, DB_val *const data) {
	DB_cursor *cursor;
	int rc = db_txn_cursor(txn, &cursor);
	if(rc < 0) return rc;
	return db_cursor_seek(cursor, key, data, 0);
}
DB_FN int db__put(DB_txn *const txn, DB_val *const key, DB_val *const data, unsigned const flags) {
	DB_cursor *cursor;
	int rc = db_txn_cursor(txn, &cursor);
	if(rc < 0) return rc;
	return db_cursor_put(cursor, key, data, flags);
}
DB_FN int db__del(DB_txn *const txn, DB_val *const key, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	if(flags) return DB_EINVAL;
	if(DB_RDONLY & txn->flags) return DB_EACCES;
	char tombstone = KEY_TOMBSTONE;
	DB_val k[1] = { *key };
	DB_val d[1] = {{ sizeof(tombstone), &tombstone }};
	int rc = db_put(txn->tmptxn, k, d, 0);
	if(rc < 0) return rc;
	return 0;
}
DB_FN int db__cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len) {
	if(!txn) return DB_EINVAL;
	if(!txn->env->cmd->fn) return DB_EINVAL;
	return txn->env->cmd->fn(txn->env->cmd->ctx, txn, buf, len);
}

DB_FN int db__cursor_open(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	DB_cursor *cursor = calloc(1, sizeof(struct DB_cursor));
	if(!cursor) return DB_ENOMEM;
	cursor->isa = db_base_leveldb;
	cursor->txn = txn;
	if(txn->tmptxn) {
		int rc = db_cursor_open(txn->tmptxn, &cursor->pending);
		if(rc < 0) {
			db_cursor_close(cursor);
			return rc;
		}
	}
	*out = cursor;
	return db_cursor_renew(txn, out);
}
DB_FN void db__cursor_close(DB_cursor *const cursor) {
	if(!cursor) return;
	db_cursor_close(cursor->pending); cursor->pending = NULL;
	db_cursor_reset(cursor);
	cursor->isa = NULL;
	assert_zeroed(cursor, 1);
	free(cursor);
}
DB_FN void db__cursor_reset(DB_cursor *const cursor) {
	if(!cursor) return;
	cursor->txn = NULL;
	cursor->state = S_INVALID;
	ldb_cursor_close(cursor->persist); cursor->persist = NULL;
}
DB_FN int db__cursor_renew(DB_txn *const txn, DB_cursor **const out) {
	if(!out) return DB_EINVAL;
	if(!*out) return db_cursor_open(txn, out);
	DB_cursor *const cursor = *out;
	cursor->txn = txn;
	cursor->state = S_INVALID;
	int rc = ldb_cursor_renew(txn->env->db, txn->ropts, txn->env->cmp, &cursor->persist);
	if(rc < 0) return rc;
	return 0;
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	if(!cursor->pending) {
		return ldb_cursor_clear(cursor->persist);
	} else {
		cursor->state = S_INVALID;
		return 0;
	}
}
DB_FN int db__cursor_txn(DB_cursor *const cursor, DB_txn **const out) {
	if(!cursor) return DB_EINVAL;
	if(out) *out = cursor->txn;
	return 0;
}
DB_FN int db__cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	assert(cursor); // We can't report an error from this function.
	return db_txn_cmp(cursor->txn, a, b);
}


static int db_cursor_update(DB_cursor *const cursor, int rc1, DB_val *const k1, DB_val *const d1, int const rc2, DB_val const *const k2, DB_val const *const d2, int const dir, DB_val *const key, DB_val *const data) {
	if(!cursor->pending) {
		if(key) *key = *k2;
		if(data) *data = *d2;
		return rc2;
	}
	for(;;) {
		cursor->state = S_INVALID;
		if(rc1 < 0 && DB_NOTFOUND != rc1) return rc1;
		if(rc2 < 0 && DB_NOTFOUND != rc2) return rc2;
		if(DB_NOTFOUND == rc1 && DB_NOTFOUND == rc2) return DB_NOTFOUND;

		int x = 0;
		if(DB_NOTFOUND == rc1) x = +1;
		if(DB_NOTFOUND == rc2) x = -1;
		if(0 == x) {
			x = db_cursor_cmp(cursor, k1, k2) * (dir ? dir : 1);
		}
		if(x > 0) {
			cursor->state = S_PERSIST;
			if(key) *key = *k2;
			if(data) *data = *d2;
			return 0;
		}
		cursor->state = 0 == x ? S_EQUAL : S_PENDING;
		char const tombstone = tombstone_get(d1);
		if(KEY_PRESENT == tombstone) {
			tombstone_trim(d1);
			if(key) *key = *k1;
			if(data) *data = *d1;
			return 0;
		}

		// The current key is a tombstone. Try to seek past it.
		assert(KEY_TOMBSTONE == tombstone);
		if(0 == dir) {
			cursor->state = S_INVALID;
			return DB_NOTFOUND;
		}
		rc1 = db_cursor_next(cursor->pending, k1, d1, dir);
	}
}
DB_FN int db__cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	if(!cursor->pending || S_PERSIST == cursor->state) {
		return ldb_cursor_current(cursor->persist, key, data);
	} else if(S_EQUAL == cursor->state || S_PENDING == cursor->state) {
		int rc = db_cursor_current(cursor->pending, key, data);
		if(DB_EINVAL == rc) return DB_NOTFOUND;
		assert(KEY_TOMBSTONE != tombstone_get(data));
		tombstone_trim(data);
		return rc;
	} else if(S_INVALID == cursor->state) {
		return DB_NOTFOUND;
	} else {
		assert(0);
		return DB_EINVAL;
	}
}
DB_FN int db__cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	DB_val k1[1] = { *key }, d1[1];
	DB_val k2[1] = { *key }, d2[1];
	int rc1 =  db_cursor_seek(cursor->pending, k1, d1, dir);
	int rc2 = ldb_cursor_seek(cursor->persist, k2, d2, dir);
	return db_cursor_update(cursor, rc1, k1, d1, rc2, k2, d2, dir, dir ? key : NULL, data);
	// Note: We pass NULL for the output key to emulate MDB_SET semantics,
	// which doesn't touch the key at all and leaves it pointing to the
	// user's copy. For MDB_SET_KEY behavior, you must make an extra call
	// to db_cursor_current.
	// Note: This only applies when dir is 0.
}
DB_FN int db__cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(0 == dir) return DB_EINVAL;
	DB_val k1[1], d1[1], k2[1], d2[1];
	int rc1 =  db_cursor_first(cursor->pending, k1, d1, dir);
	int rc2 = ldb_cursor_first(cursor->persist, k2, d2, dir);
	return db_cursor_update(cursor, rc1, k1, d1, rc2, k2, d2, dir, key, data);
}
DB_FN int db__cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(0 == dir) return DB_EINVAL;
	int rc1, rc2;
	DB_val k1[1], d1[1], k2[1], d2[1];
	if(S_PERSIST != cursor->state) {
		rc1 = db_cursor_next(cursor->pending, k1, d1, dir);
	} else {
		rc1 = db_cursor_current(cursor->pending, k1, d1);
		if(DB_EINVAL == rc1) rc1 = DB_NOTFOUND;
	}
	if(S_PENDING != cursor->state) {
		rc2 = ldb_cursor_next(cursor->persist, k2, d2, dir);
	} else {
		rc2 = ldb_cursor_current(cursor->persist, k2, d2);
	}
	return db_cursor_update(cursor, rc1, k1, d1, rc2, k2, d2, dir, key, data);
}

DB_FN int db__cursor_put(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	if(!key) return DB_EINVAL;
	if(DB_RDONLY & cursor->txn->flags) return DB_EACCES;
	DB_val k[1], d[1];
	int rc = 0;
	// DB_APPEND is mostly just an optimization, so we currently
	// don't bother checking it.
	if(DB_CURRENT & flags) {
		rc = db_cursor_current(cursor, k, NULL);
		if(rc < 0) return rc;
	} else {
		ldb_cursor_storage_invalidate(cursor->persist);
		*k = *key;
	}
	if(DB_NOOVERWRITE & flags) {
		rc = db_cursor_seek(cursor, k, d, 0);
		if(rc >= 0) {
			if(data) *data = *d;
			return DB_KEYEXIST;
		}
		if(DB_NOTFOUND != rc) return rc;
	}
	cursor->state = S_PENDING;
	*d = (DB_val){ 1+(data ? data->size : 0), NULL }; // Prefix with deletion flag.
	assert(cursor->pending);
	rc = db_cursor_put(cursor->pending, k, d, DB_RESERVE);
	if(rc < 0) return rc;
	assert(d->data);
	memset(d->data+0, KEY_PRESENT, 1);
	if(DB_RESERVE & flags) {
		if(data) *data = (DB_val){ d->size-1, (char *)d->data+1 };
	} else {
		if(data && data->size > 0) memcpy(d->data+1, data->data, data->size);
	}
	return 0;
}
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	if(flags) return DB_EINVAL;
	if(DB_RDONLY & cursor->txn->flags) return DB_EACCES;
	ldb_cursor_storage_invalidate(cursor->persist);
	DB_val k[1], d[1];
	int rc = db_cursor_current(cursor, k, NULL);
	if(rc < 0) return rc;
	cursor->state = S_INVALID;
	char tombstone = KEY_TOMBSTONE;
	*d = (DB_val){ sizeof(tombstone), &tombstone };
	assert(cursor->pending);
	rc = db_cursor_put(cursor->pending, k, d, 0);
	if(rc < 0) return rc;
	return 0;
}

DB_BASE_V0(leveldb)

