// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For unlink(2)
#include <sys/resource.h>

#ifdef USE_ROCKSDB
#include "rocks_wrapper.h"
#else
#include <leveldb/c.h>
#endif

#include "liblmdb/lmdb.h"
#include "db_base.h"
#include "common.h"

#define MDB_RDWR 0

#define MDB_MAIN_DBI 1

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
	leveldb_options_t *opts;
	leveldb_filterpolicy_t *filterpolicy;
	leveldb_t *db;
	MDB_env *tmpenv;
	leveldb_writeoptions_t *wopts;
	MDB_cmp_func *cmp;
};
struct DB_txn {
	DB_env *env;
	DB_txn *parent;
	unsigned flags;
	leveldb_readoptions_t *ropts;
	leveldb_snapshot_t const *snapshot;
	MDB_txn *tmptxn;
	DB_cursor *cursor;
};
struct DB_cursor {
	DB_txn *txn;
	DB_state state;
	MDB_cursor *pending;
	LDB_cursor *persist;
};


// DEBUG
static char *tohex(MDB_val const *const x) {
	char const *const map = "0123456789abcdef";
	char const *const buf = x->mv_data;
	char *const hex = calloc(x->mv_size*2+1, 1);
	if(!hex) return NULL;
	for(size_t i = 0; i < x->mv_size; ++i) {
		hex[i*2+0] = map[0xf & (buf[i] >> 4)];
		hex[i*2+1] = map[0xf & (buf[i] >> 0)];
	}
	return hex;
}


static int compare_default(MDB_val const *const a, MDB_val const *const b) {
	int x = memcmp(a->mv_data, b->mv_data, MIN(a->mv_size, b->mv_size));
	if(0 != x) return x;
	if(a->mv_size < b->mv_size) return -1;
	if(a->mv_size > b->mv_size) return +1;
	return 0;
}


static int mdberr(int const rc) {
	return rc <= 0 ? rc : -rc;
}
static int mdb_cursor_seek(MDB_cursor *const cursor, MDB_val *const key, MDB_val *const data, int const dir) {
	if(!key) return EINVAL;
	MDB_val const orig[1] = { *key };
	MDB_cursor_op const op = 0 == dir ? MDB_SET : MDB_SET_RANGE;
	int rc = mdberr(mdb_cursor_get(cursor, key, data, op));
	if(dir >= 0) return rc;
	if(rc >= 0) {
		MDB_txn *const txn = mdb_cursor_txn(cursor);
		MDB_dbi const dbi = mdb_cursor_dbi(cursor);
		if(0 == mdb_cmp(txn, dbi, orig, key)) return rc;
		return mdberr(mdb_cursor_get(cursor, key, data, MDB_PREV));
	} else if(DB_NOTFOUND == rc) {
		return mdberr(mdb_cursor_get(cursor, key, data, MDB_LAST));
	} else return rc;
}
static char tombstone_get(MDB_val const *const data) {
	assert(data);
	assert(data->mv_size >= 1);
	return ((char const *)data->mv_data)[0];
}
static void tombstone_trim(MDB_val *const data) {
	if(!data) return;
	assert(KEY_PRESENT == tombstone_get(data));
	data->mv_data++;
	data->mv_size--;
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
	MDB_cmp_func *cmp;
	bool valid;
	bool storage_current;
	struct storage *keys;
	struct storage *vals;
};
static void ldb_cursor_close(LDB_cursor *const cursor);
static int ldb_cursor_open(leveldb_t *const db, leveldb_readoptions_t *const ropts, MDB_cmp_func *const cmp, LDB_cursor **const out) {
	if(!db) return DB_EINVAL;
	if(!ropts) return DB_EINVAL;
	if(!cmp) return DB_EINVAL;
	if(!out) return DB_EINVAL;

	LDB_cursor *cursor = calloc(1, sizeof(struct LDB_cursor));
	if(!cursor) return DB_ENOMEM;

	int rc = 0;
	cursor->iter = leveldb_create_iterator(db, ropts);
	if(!cursor->iter) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;

	cursor->cmp = cmp;
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
	cursor->cmp = NULL;
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
static int ldb_cursor_renew(leveldb_t *const db, leveldb_readoptions_t *const ropts, MDB_cmp_func *const cmp, LDB_cursor **const out) {
	if(!out) return DB_EINVAL;
	if(!*out) return ldb_cursor_open(db, ropts, cmp, out);
	LDB_cursor *const cursor = *out;
	leveldb_iter_destroy(cursor->iter); cursor->iter = NULL;
	cursor->iter = leveldb_create_iterator(db, ropts);
	if(!cursor->iter) return DB_ENOMEM;
	cursor->cmp = cmp;
	cursor->valid = false;
	ldb_cursor_storage_invalidate(cursor);
	return 0;
}
static int ldb_cursor_current(LDB_cursor *const cursor, MDB_val *const key, MDB_val *const val) {
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
	if(key) *key = (MDB_val){ cursor->keys->size, cursor->keys->data };
	if(val) *val = (MDB_val){ cursor->vals->size, cursor->vals->data };
	return 0;
}
static int ldb_cursor_seek(LDB_cursor *const cursor, MDB_val *const key, MDB_val *const val, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(!key) return DB_EINVAL;
	cursor->storage_current = false;
	MDB_val const orig[1] = { *key };
	leveldb_iter_seek(cursor->iter, key->mv_data, key->mv_size);
	cursor->valid = !!leveldb_iter_valid(cursor->iter);
	int rc = ldb_cursor_current(cursor, key, val);
	if(dir > 0) return rc;
	if(dir < 0) {
		if(rc < 0) {
			leveldb_iter_seek_to_last(cursor->iter);
		} else if(0 != cursor->cmp(key, orig)) {
			leveldb_iter_prev(cursor->iter);
		} else return rc;
		cursor->valid = !!leveldb_iter_valid(cursor->iter);
		return ldb_cursor_current(cursor, key, val);
	}
	if(rc < 0) return rc;
	if(0 == cursor->cmp(key, orig)) return rc;
	cursor->valid = 0;
	return DB_NOTFOUND;
}
static int ldb_cursor_first(LDB_cursor *const cursor, MDB_val *const key, MDB_val *const val, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(0 == dir) return DB_EINVAL;
	cursor->storage_current = false;
	if(dir > 0) leveldb_iter_seek_to_first(cursor->iter);
	if(dir < 0) leveldb_iter_seek_to_last(cursor->iter);
	cursor->valid = !!leveldb_iter_valid(cursor->iter);
	return ldb_cursor_current(cursor, key, val);
}
static int ldb_cursor_next(LDB_cursor *const cursor, MDB_val *const key, MDB_val *const val, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(!cursor->valid) return ldb_cursor_first(cursor, key, val, dir);
	if(0 == dir) return DB_EINVAL;
	cursor->storage_current = false;
	if(dir > 0) leveldb_iter_next(cursor->iter);
	if(dir < 0) leveldb_iter_prev(cursor->iter);
	cursor->valid = !!leveldb_iter_valid(cursor->iter);
	return ldb_cursor_current(cursor, key, val);
}


int db_env_create(DB_env **const out) {
	DB_env *env = calloc(1, sizeof(struct DB_env));
	if(!env) return DB_ENOMEM;

	env->opts = leveldb_options_create();
	if(!env->opts) {
		db_env_close(env);
		return DB_ENOMEM;
	}

	leveldb_options_set_create_if_missing(env->opts, 1);
	leveldb_options_set_compression(env->opts, leveldb_snappy_compression);

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

	int rc = mdberr(mdb_env_create(&env->tmpenv));
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

	env->cmp = compare_default;
	*out = env;
	return 0;
}
int db_env_set_mapsize(DB_env *const env, size_t const size) {
	return 0;
}
int db_env_open(DB_env *const env, char const *const name, unsigned const flags, unsigned const mode) {
	if(!env) return DB_EINVAL;
	char *err = NULL;
	env->db = leveldb_open(env->opts, name, &err);
	if(err) fprintf(stderr, "Database error %s\n", err);
	leveldb_free(err);
	if(!env->db || err) return -1; // TODO: Parse error string?


	char tmppath[512]; // TODO
	if(snprintf(tmppath, sizeof(tmppath), "%s/tmp.mdb", name) < 0) return -1;
	int rc = mdberr(mdb_env_open(env->tmpenv, tmppath, MDB_NOSUBDIR | MDB_WRITEMAP, 0600));
	if(rc < 0) return rc;
	(void)unlink(tmppath);

	MDB_txn *tmptxn;
	rc = mdberr(mdb_txn_begin(env->tmpenv, NULL, MDB_RDWR, &tmptxn));
	if(rc < 0) return rc;
	MDB_dbi dbi;
	rc = mdberr(mdb_dbi_open(tmptxn, NULL, 0, &dbi));
	if(rc < 0) {
		mdb_txn_abort(tmptxn);
		return rc;
	}
	if(MDB_MAIN_DBI != dbi) {
		// Should never happen.
		mdb_txn_abort(tmptxn);
		return DB_PANIC;
	}
	rc = mdberr(mdb_txn_commit(tmptxn));
	if(rc < 0) return rc;


	leveldb_writeoptions_set_sync(env->wopts, !(DB_NOSYNC & flags));
	return 0;
}
void db_env_close(DB_env *const env) {
	if(!env) return;
	if(env->opts) {
		leveldb_options_destroy(env->opts); env->opts = NULL;
	}
	if(env->filterpolicy) {
		leveldb_filterpolicy_destroy(env->filterpolicy); env->filterpolicy = NULL;
	}
	if(env->db) {
		leveldb_close(env->db); env->db = NULL;
	}
	mdb_env_close(env->tmpenv); env->tmpenv = NULL;
	if(env->wopts) {
		leveldb_writeoptions_destroy(env->wopts); env->wopts = NULL;
	}
	env->cmp = NULL;
	assert_zeroed(env, 1);
	free(env);
}

int db_txn_begin(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn **const out) {
	if(!env) return DB_EINVAL;
	if(!out) return DB_EINVAL;

	MDB_txn *tmptxn = NULL;
	if(!(DB_RDONLY & flags)) {
		MDB_txn *p = parent ? parent->tmptxn : NULL;
		int rc = mdberr(mdb_txn_begin(env->tmpenv, p, flags, &tmptxn));
		if(rc < 0) return rc;
	}

	DB_txn *txn = calloc(1, sizeof(struct DB_txn));
	if(!txn) {
		mdb_txn_abort(tmptxn);
		return DB_ENOMEM;
	}
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
int db_txn_commit(DB_txn *const txn) {
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
	MDB_cursor *cursor = NULL;
	int rc = mdberr(mdb_cursor_open(txn->tmptxn, MDB_MAIN_DBI, &cursor));
	if(rc < 0) {
		db_txn_abort(txn);
		return rc;
	}
	MDB_val key[1], data[1];
	rc = mdberr(mdb_cursor_get(cursor, key, data, MDB_FIRST));
	for(; rc >= 0; rc = mdberr(mdb_cursor_get(cursor, key, data, MDB_NEXT))) {
		switch(tombstone_get(data)) {
		case KEY_TOMBSTONE:
			leveldb_writebatch_delete(batch,
				key->mv_data, key->mv_size);
			break;
		case KEY_PRESENT:
			tombstone_trim(data);
			leveldb_writebatch_put(batch,
				key->mv_data, key->mv_size,
				data->mv_data, data->mv_size);
			break;
		default: assert(0);
		}
	}
	mdb_cursor_close(cursor); cursor = NULL;

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
void db_txn_abort(DB_txn *const txn) {
	if(!txn) return;
	if(txn->snapshot) {
		leveldb_readoptions_set_snapshot(txn->ropts, NULL);
		leveldb_release_snapshot(txn->env->db, txn->snapshot); txn->snapshot = NULL;
	}
	leveldb_readoptions_destroy(txn->ropts); txn->ropts = NULL;
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	mdb_txn_abort(txn->tmptxn); txn->tmptxn = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->flags = 0;
	assert_zeroed(txn, 1);
	free(txn);
}
void db_txn_reset(DB_txn *const txn) {
	if(!txn) return;
	assert(txn->flags & DB_RDONLY);
	if(txn->snapshot) {
		leveldb_readoptions_set_snapshot(txn->ropts, NULL);
		leveldb_release_snapshot(txn->env->db, txn->snapshot); txn->snapshot = NULL;
	}
}
int db_txn_renew(DB_txn *const txn) {
	// TODO: If renew fails, does the user have to explicitly abort?
	if(!txn) return DB_EINVAL;
	assert(txn->flags & DB_RDONLY);
	assert(!txn->snapshot);
	txn->snapshot = leveldb_create_snapshot(txn->env->db);
	if(!txn->snapshot) return DB_ENOMEM;
	leveldb_readoptions_set_snapshot(txn->ropts, txn->snapshot);
	return 0;
}
int db_txn_get_flags(DB_txn *const txn, unsigned *const flags) {
	if(!txn) return DB_EINVAL;
	if(flags) *flags = txn->flags;
	return 0;
}
int db_txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	assert(txn); // We can't report an error from this function.
	return txn->env->cmp((MDB_val *)a, (MDB_val *)b);
}
int db_txn_cursor(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	if(!txn->cursor) {
		int rc = db_cursor_open(txn, &txn->cursor);
		if(rc < 0) return rc;
	}
	if(out) *out = txn->cursor;
	return 0;
}

int db_get(DB_txn *const txn, DB_val *const key, DB_val *const data) {
	DB_cursor *cursor;
	int rc = db_txn_cursor(txn, &cursor);
	if(rc < 0) return rc;
	return db_cursor_seek(cursor, key, data, 0);
}
int db_put(DB_txn *const txn, DB_val *const key, DB_val *const data, unsigned const flags) {
	DB_cursor *cursor;
	int rc = db_txn_cursor(txn, &cursor);
	if(rc < 0) return rc;
	return db_cursor_put(cursor, key, data, flags);
}
int db_del(DB_txn *const txn, DB_val *const key, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	if(flags) return DB_EINVAL;
	if(DB_RDONLY & txn->flags) return DB_EACCES;
	char tombstone = KEY_TOMBSTONE;
	DB_val k[1] = { *key };
	DB_val d[1] = {{ sizeof(tombstone), &tombstone }};
	int rc = mdberr(mdb_put(txn->tmptxn, MDB_MAIN_DBI, (MDB_val *)k, (MDB_val *)d, 0));
	if(rc < 0) return rc;
	return 0;
}

int db_cursor_open(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	DB_cursor *cursor = calloc(1, sizeof(struct DB_cursor));
	if(!cursor) return DB_ENOMEM;
	if(txn->tmptxn) {
		int rc = mdberr(mdb_cursor_open(txn->tmptxn, MDB_MAIN_DBI, &cursor->pending));
		if(rc < 0) {
			db_cursor_close(cursor);
			return rc;
		}
	}
	*out = cursor;
	return db_cursor_renew(txn, out);
}
void db_cursor_close(DB_cursor *const cursor) {
	if(!cursor) return;
	mdb_cursor_close(cursor->pending); cursor->pending = NULL;
	db_cursor_reset(cursor);
	assert_zeroed(cursor, 1);
	free(cursor);
}
void db_cursor_reset(DB_cursor *const cursor) {
	if(!cursor) return;
	cursor->txn = NULL;
	cursor->state = S_INVALID;
	ldb_cursor_close(cursor->persist); cursor->persist = NULL;
}
int db_cursor_renew(DB_txn *const txn, DB_cursor **const out) {
	if(!out) return DB_EINVAL;
	if(!*out) return db_cursor_open(txn, out);
	DB_cursor *const cursor = *out;
	cursor->txn = txn;
	cursor->state = S_INVALID;
	int rc = ldb_cursor_renew(txn->env->db, txn->ropts, txn->env->cmp, &cursor->persist);
	if(rc < 0) return rc;
	return 0;
}
int db_cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	if(!cursor->pending) {
		return ldb_cursor_clear(cursor->persist);
	} else {
		cursor->state = S_INVALID;
		return 0;
	}
}
int db_cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	return db_txn_cmp(cursor->txn, a, b);
}


static int db_cursor_update(DB_cursor *const cursor, int rc1, MDB_val *const k1, MDB_val *const d1, int const rc2, MDB_val const *const k2, MDB_val const *const d2, int const dir, DB_val *const key, DB_val *const data) {
	if(!cursor->pending) {
		if(key) *key = *(DB_val *)k2;
		if(data) *data = *(DB_val *)d2;
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
		if(0 == x) x = cursor->txn->env->cmp(k1, k2) * (dir ? dir : 1);
		if(x > 0) {
			cursor->state = S_PERSIST;
			if(key) *key = *(DB_val *)k2;
			if(data) *data = *(DB_val *)d2;
			return 0;
		}
		cursor->state = 0 == x ? S_EQUAL : S_PENDING;
		char const tombstone = tombstone_get(d1);
		if(KEY_PRESENT == tombstone) {
			tombstone_trim(d1);
			if(key) *key = *(DB_val *)k1;
			if(data) *data = *(DB_val *)d1;
			return 0;
		}

		// The current key is a tombstone. Try to seek past it.
		assert(KEY_TOMBSTONE == tombstone);
		if(0 == dir) {
			cursor->state = S_INVALID;
			return DB_NOTFOUND;
		}
		MDB_cursor_op const op = dir < 0 ? MDB_PREV : MDB_NEXT;
		rc1 = mdberr(mdb_cursor_get(cursor->pending, k1, d1, op));
	}
}
int db_cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	if(!cursor->pending || S_PERSIST == cursor->state) {
		return ldb_cursor_current(cursor->persist, (MDB_val *)key, (MDB_val *)data);
	} else if(S_EQUAL == cursor->state || S_PENDING == cursor->state) {
		int rc = mdberr(mdb_cursor_get(cursor->pending, (MDB_val *)key, (MDB_val *)data, MDB_GET_CURRENT));
		if(DB_EINVAL == rc) return DB_NOTFOUND;
		assert(KEY_TOMBSTONE != tombstone_get((MDB_val *)data));
		tombstone_trim((MDB_val *)data);
		return rc;
	} else if(S_INVALID == cursor->state) {
		return DB_NOTFOUND;
	} else {
		assert(0);
		return DB_EINVAL;
	}
}
int db_cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	MDB_val k1[1] = { *(MDB_val *)key }, d1[1];
	MDB_val k2[1] = { *(MDB_val *)key }, d2[1];
	int rc1 = mdberr(mdb_cursor_seek(cursor->pending, k1, d1, dir));
	int rc2 =        ldb_cursor_seek(cursor->persist, k2, d2, dir);
	return db_cursor_update(cursor, rc1, k1, d1, rc2, k2, d2, dir, NULL, data);
	// Note: We pass NULL for the output key to emulate MDB_SET semantics,
	// which doesn't touch the key at all and leaves it pointing to the
	// user's copy. For MDB_SET_KEY behavior, you must make an extra call
	// to db_cursor_current.
}
int db_cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(0 == dir) return DB_EINVAL;
	MDB_val k1[1], d1[1], k2[1], d2[1];
	MDB_cursor_op const op = dir < 0 ? MDB_LAST : MDB_FIRST;
	int rc1 = mdberr(mdb_cursor_get(cursor->pending, k1, d1, op));
	int rc2 =        ldb_cursor_first(cursor->persist, k2, d2, dir);
	return db_cursor_update(cursor, rc1, k1, d1, rc2, k2, d2, dir, key, data);
}
int db_cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(0 == dir) return DB_EINVAL;
	int rc1, rc2;
	MDB_val k1[1], d1[1], k2[1], d2[1];
	if(S_PERSIST != cursor->state) {
		MDB_cursor_op const op = dir < 0 ? MDB_PREV : MDB_NEXT;
		rc1 = mdberr(mdb_cursor_get(cursor->pending, k1, d1, op));
	} else {
		rc1 = mdberr(mdb_cursor_get(cursor->pending, k1, d1, MDB_GET_CURRENT));
		if(DB_EINVAL == rc1) rc1 = DB_NOTFOUND;
	}
	if(S_PENDING != cursor->state) {
		rc2 = ldb_cursor_next(cursor->persist, k2, d2, dir);
	} else {
		rc2 = ldb_cursor_current(cursor->persist, k2, d2);
	}
	return db_cursor_update(cursor, rc1, k1, d1, rc2, k2, d2, dir, key, data);
}

int db_cursor_put(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	if(!key) return DB_EINVAL;
	if(DB_RDONLY & cursor->txn->flags) return DB_EACCES;
	ldb_cursor_storage_invalidate(cursor->persist);
	DB_val k[1], d[1];
	int rc = 0;
	if(DB_NOOVERWRITE & flags) {
		*k = *key;
		rc = db_cursor_seek(cursor, k, d, 0);
		if(rc >= 0) {
			*key = *k;
			if(data) *data = *d;
			return DB_KEYEXIST;
		}
		if(DB_NOTFOUND != rc) return rc;
	}
	cursor->state = S_INVALID;
	*k = *key;
	*d = (DB_val){ 1+(data ? data->size : 0), NULL }; // Prefix with deletion flag.
	assert(cursor->pending);
	rc = mdberr(mdb_cursor_put(cursor->pending, (MDB_val *)k, (MDB_val *)d, MDB_RESERVE));
	if(rc < 0) return rc;
	assert(d->data);
	memset(d->data+0, KEY_PRESENT, 1);
	if(data && data->size > 0) memcpy(d->data+1, data->data, data->size);
	return 0;
}
int db_cursor_del(DB_cursor *const cursor, unsigned const flags) {
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
	rc = mdberr(mdb_cursor_put(cursor->pending, (MDB_val *)k, (MDB_val *)d, 0));
	if(rc < 0) return rc;
	return 0;
}

