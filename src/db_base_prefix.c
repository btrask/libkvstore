// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include "db_prefix.h"
#include "common.h"

struct DB_env {
	DB_base const *isa;
	DB_env *sub;
	size_t key_max;
	DB_range keyspace[1];
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
	DB_txn *child;
	DB_cursor *cursor;
	// Inner txn
};
struct DB_cursor {
	DB_base const *isa;
	DB_txn *txn;
	unsigned char *bufs[3];
	DB_val key[1];
	DB_range range[1];
	// Inner cursor
};
#define TXN_INNER(x) ((x)+1)
#define CURSOR_INNER(x) ((x)+1)

static bool key_ok(DB_cursor *const cursor, DB_val const *const key) {
	assert(cursor);
	DB_env *const env = cursor->txn->env;
	if(!key) return true;
	return env->keyspace->min->size + key->size < env->key_max;
}
static bool range_ok(DB_cursor *const cursor, DB_range const *const range) {
	return key_ok(cursor, range->min) && key_ok(cursor, range->max);
}
static DB_val *pfx_internal(DB_cursor *const cursor, DB_val const *const key, DB_val *const storage) {
	assert(cursor);
	DB_env *const env = cursor->txn->env;
	if(!key) return NULL;
	DB_val *const out = storage;
	DB_val const *const a = env->keyspace->min;
	DB_val const *const b = key;
	size_t const n = a->size;
	assert(a->size + b->size < env->key_max);
	out->size = a->size + b->size;
	memcpy(out->data+0, a->data, a->size);
	memcpy(out->data+n, b->data, b->size);
	return out;
}
static DB_val *pfx_key(DB_cursor *const cursor, DB_val const *const key) {
	*cursor->key = (DB_val){ 0, cursor->bufs[0] };
	return pfx_internal(cursor, key, cursor->key);
}
static DB_range *pfx_range(DB_cursor *const cursor, DB_range const *const range) {
	*cursor->range->min = (DB_val){0, cursor->bufs[1] };
	*cursor->range->max = (DB_val){0, cursor->bufs[2] };
	pfx_internal(cursor, range->min, cursor->range->min);
	pfx_internal(cursor, range->max, cursor->range->max);
	return cursor->range;
}
static void key_strip(DB_cursor *const cursor, DB_val const *const src, DB_val *const dst) {
	if(!dst) return;
	DB_env *const env = cursor->txn->env;
	DB_val const *const pfx = env->keyspace->min;
	dst->data = src->data + pfx->size;
	dst->size = src->size - pfx->size;
}

static void range_destroy(DB_range *range) {
	if(!range) return;
	free(range->min->data); range->min->data = NULL;
	free(range->max->data); range->max->data = NULL;
	range->min->size = 0;
	range->max->size = 0;
}
static void genmax(DB_range *const range) {
	assert(range);
	unsigned char *const out = range->max->data;
	memcpy(out, range->min->data, range->min->size);
	range->max->size = range->min->size;
	size_t i = range->max->size;
	while(i--) {
		if(out[i] < 0xff) {
			out[i]++;
			return;
		} else {
			out[i] = 0;
		}
	}
	assert(!"range overflow");
	// TODO: It would be nice to represent an unbounded range maximum
	// by {0, NULL}, but our range code would probably need a lot of
	// special cases to handle it.
}
static int keyspace(DB_range *const range, DB_val const *const pfx) {
	assert(range);
	range_destroy(range);
	if(!pfx || !pfx->size) return 0;
	if(!pfx->data) return DB_EINVAL;
	range->min->size = pfx->size;
	range->min->data = malloc(pfx->size);
	range->max->data = malloc(pfx->size);
	if(!range->min->data || !range->max->data) {
		range_destroy(range);
		return DB_ENOMEM;
	}
	memcpy(range->min->data, pfx->data, pfx->size);
	genmax(range);
	return 0;
}

DB_FN size_t db__env_size(void) {
	return sizeof(struct DB_env);
}
DB_FN int db__env_init(DB_env *const env) {
	if(!env) return DB_EINVAL;
	assert_zeroed(env, 1);
	env->isa = db_base_prefix;
	return 0;
}
DB_FN int db__env_get_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_INNERDB: *(DB_env **)data = env->sub; return 0;
	case DB_CFG_KEYSIZE: {
		int rc = db_env_get_config(env->sub, DB_CFG_KEYSIZE, data);
		if(rc < 0) return rc;
		if(*(size_t *)data <= env->keyspace->min->size) return DB_PANIC;
		*(size_t *)data -= env->keyspace->min->size;
		return 0;
	} case DB_CFG_PREFIX: *(DB_val *)data = *env->keyspace->min; return 0;
	default: return db_env_get_config(env->sub, type, data);
	}
}
DB_FN int db__env_set_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_INNERDB:
		db_env_close(env->sub);
		env->sub = data;
		return 0;
	case DB_CFG_KEYSIZE: {
		size_t max = *(size_t *)data + env->keyspace->min->size;
		return db_env_set_config(env, DB_CFG_KEYSIZE, &max);
	} case DB_CFG_PREFIX: return keyspace(env->keyspace, data);
	default: return db_env_set_config(env->sub, type, data);
	}
}
DB_FN int db__env_open0(DB_env *const env) {
	if(!env) return DB_EINVAL;
	if(!env->sub) return DB_EINVAL;

	int rc = db_env_open0(env->sub);
	if(rc < 0) goto cleanup;

	env->key_max = 512;
	(void) db_env_get_config(env->sub, DB_CFG_KEYSIZE, &env->key_max);
	if(env->key_max <= env->keyspace->min->size) {
		rc = DB_PANIC;
		goto cleanup;
	}

cleanup:
	if(rc < 0) db_env_destroy(env);
	return rc;
}
DB_FN void db__env_destroy(DB_env *env) {
	if(!env) return;
	db_env_close(env->sub); env->sub = NULL;
	env->key_max = 0;
	range_destroy(env->keyspace);
	env->isa = NULL;
	assert_zeroed(env, 1);
}

DB_FN size_t db__txn_size(DB_env *const env) {
	return sizeof(struct DB_env)+db_txn_size(env->sub);
}
DB_FN int db__txn_begin_init(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn *const txn) {
	if(!env) return DB_EINVAL;
	if(!txn) return DB_EINVAL;
	assert_zeroed(txn, 1);
	txn->isa = db_base_prefix;
	txn->env = env;
	txn->parent = parent;
	int rc = db_txn_begin_init(env->sub, parent ? TXN_INNER(parent) : NULL, flags, TXN_INNER(txn));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) db_txn_abort_destroy(txn);
	return rc;
}
DB_FN int db__txn_commit_destroy(DB_txn *txn) {
	if(!txn) return DB_EINVAL;
	int rc = 0;
	if(txn->child) {
		rc = db_txn_commit(txn->child); txn->child = NULL;
		if(rc < 0) goto cleanup;
	}
	rc = db_txn_commit_destroy(TXN_INNER(txn));
	if(rc < 0) goto cleanup;
cleanup:
	db_txn_abort_destroy(txn);
	return rc;
}
DB_FN void db__txn_abort_destroy(DB_txn *txn) {
	if(!txn) return;
	if(txn->child) {
		db_txn_abort(txn->child); txn->child = NULL;
	}
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	db_txn_abort_destroy(TXN_INNER(txn));
	if(txn->parent) txn->parent->child = NULL;
	txn->env = NULL;
	txn->parent = NULL;
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
	return db_txn_get_flags(TXN_INNER(txn), flags);
}
DB_FN int db__txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	assert(txn);
	return db_txn_cmp(TXN_INNER(txn), a, b);
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

DB_FN int db__get(DB_txn *const txn, DB_val const *const key, DB_val *const data) {
	return db_helper_get(txn, key, data);
}
DB_FN int db__put(DB_txn *const txn, DB_val const *const key, DB_val *const data, unsigned const flags) {
	return db_helper_put(txn, key, data, flags);
}
DB_FN int db__del(DB_txn *const txn, DB_val const *const key, unsigned const flags) {
	return db_helper_del(txn, key, flags); // TODO
}
DB_FN int db__cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len) {
	if(!txn) return DB_EINVAL;
	// TODO
	return DB_ENOTSUP;
}

DB_FN int db__countr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_countr(txn, range, out);
}
DB_FN int db__delr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_delr(txn, range, out);
}

DB_FN size_t db__cursor_size(DB_txn *const txn) {
	return sizeof(struct DB_cursor)+db_cursor_size(TXN_INNER(txn));
}
DB_FN int db__cursor_init(DB_txn *const txn, DB_cursor *const cursor) {
	if(!txn) return DB_EINVAL;
	if(!cursor) return DB_EINVAL;
	assert_zeroed(cursor, 1);
	int rc = 0;
	cursor->isa = db_base_prefix;
	cursor->txn = txn;

	rc = db_cursor_init(TXN_INNER(txn), CURSOR_INNER(cursor));
	if(rc < 0) goto cleanup;

	for(size_t i = 0; i < numberof(cursor->bufs); i++) {
		cursor->bufs[i] = malloc(cursor->txn->env->key_max);
		if(!cursor->bufs[i]) {
			rc = DB_ENOMEM;
			goto cleanup;
		}
	}

cleanup:
	if(rc < 0) db_cursor_destroy(cursor);
	return rc;
}
DB_FN void db__cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	db_cursor_destroy(CURSOR_INNER(cursor));
	memset(cursor->key, 0, sizeof(*cursor->key));
	memset(cursor->range, 0, sizeof(*cursor->range));
	for(size_t i = 0; i < numberof(cursor->bufs); i++) {
		free(cursor->bufs[i]); cursor->bufs[i] = NULL;
	}
	cursor->txn = NULL;
	cursor->isa = NULL;
	assert_zeroed(cursor, 1);
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	return db_cursor_clear(CURSOR_INNER(cursor));
}
DB_FN int db__cursor_txn(DB_cursor *const cursor, DB_txn **const out) {
	if(!cursor) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	*out = cursor->txn;
	return 0;
}
DB_FN int db__cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	assert(cursor);
	return db_cursor_cmp(CURSOR_INNER(cursor), a, b);
}

DB_FN int db__cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_current(CURSOR_INNER(cursor), key, data);
	if(rc >= 0) key_strip(cursor, key, key);
	return rc;
}
DB_FN int db__cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(!key_ok(cursor, key)) return DB_BAD_VALSIZE;
	int rc = db_cursor_seekr(CURSOR_INNER(cursor),
		cursor->txn->env->keyspace, pfx_key(cursor, key), data, dir);
	if(rc >= 0 && 0 != dir) key_strip(cursor, cursor->key, key);
	return rc;
}
DB_FN int db__cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_firstr(CURSOR_INNER(cursor),
		cursor->txn->env->keyspace, key, data, dir);
	if(rc >= 0) key_strip(cursor, key, key);
	return rc;
}
DB_FN int db__cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_nextr(CURSOR_INNER(cursor),
		cursor->txn->env->keyspace, key, data, dir);
	if(rc >= 0) key_strip(cursor, key, key);
	return rc;
}

DB_FN int db__cursor_seekr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(!range_ok(cursor, range)) return DB_BAD_VALSIZE;
	if(!key_ok(cursor, key)) return DB_BAD_VALSIZE;
	int rc = db_cursor_seekr(CURSOR_INNER(cursor),
		pfx_range(cursor, range), pfx_key(cursor, key), data, dir);
	if(rc >= 0 && 0 != dir) key_strip(cursor, cursor->key, key);
	return rc;
}
DB_FN int db__cursor_firstr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(!range_ok(cursor, range)) return DB_BAD_VALSIZE;
	int rc = db_cursor_firstr(CURSOR_INNER(cursor),
		pfx_range(cursor, range), key, data, dir);
	if(rc >= 0) key_strip(cursor, key, key);
	return rc;
}
DB_FN int db__cursor_nextr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(!range_ok(cursor, range)) return DB_BAD_VALSIZE;
	int rc = db_cursor_nextr(CURSOR_INNER(cursor),
		pfx_range(cursor, range), key, data, dir);
	if(rc >= 0) key_strip(cursor, key, key);
	return rc;
}

DB_FN int db__cursor_put(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	if(!key_ok(cursor, key)) return DB_BAD_VALSIZE;
	int rc = db_cursor_put(CURSOR_INNER(cursor),
		pfx_key(cursor, key), data, flags);
	if(rc >= 0 && DB_CURRENT & flags) key_strip(cursor, cursor->key, key);
	return rc;
}
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	return db_cursor_del(CURSOR_INNER(cursor), flags);
}

DB_env *db_prefix_env_raw(DB_env *const env) {
	if(!env) return NULL;
	assert(db_base_prefix == env->isa);
	return env->sub;
}
DB_txn *db_prefix_txn_raw(DB_txn *const txn) {
	if(!txn) return NULL;
	assert(db_base_prefix == txn->isa);
	return TXN_INNER(txn);
}
DB_cursor *db_prefix_cursor_raw(DB_cursor *cursor) {
	if(!cursor) return NULL;
	assert(db_base_prefix == cursor->isa);
	return CURSOR_INNER(cursor);
}

DB_BASE_V0(prefix);

