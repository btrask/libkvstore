// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include "db_prefix.h"
#include "common.h"

struct DB_cursor {
	DB_base const *isa;
	size_t key_max;
	unsigned char *bufs[3];
	DB_val pfx[1];
	DB_val key[1];
	DB_range range[1];
	// Inner cursor
};
#define CURSOR_INNER(x) ((x)+1)

static bool key_ok(DB_cursor *const cursor, DB_val const *const key) {
	assert(cursor);
	if(!key) return true;
	return cursor->pfx->size + key->size < cursor->key_max;
}
static bool range_ok(DB_cursor *const cursor, DB_range const *const range) {
	return key_ok(cursor, range->min) && key_ok(cursor, range->max);
}
static DB_val *pfx_internal(DB_cursor *const cursor, DB_val const *const key, DB_val *const storage) {
	assert(cursor);
	if(!key) return NULL;
	DB_val *const out = storage;
	DB_val const *const a = cursor->pfx;
	DB_val const *const b = key;
	size_t const n = a->size;
	assert(a->size + b->size < cursor->key_max);
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
	DB_val const *const pfx = cursor->pfx;
	dst->data = src->data + pfx->size;
	dst->size = src->size - pfx->size;
}


DB_FN size_t db__cursor_size(DB_txn *const fake) {
	DB_prefix_txn const *const txn = (DB_prefix_txn *)fake;
	return sizeof(struct DB_cursor)+db_cursor_size(txn->txn);
}
DB_FN int db__cursor_init(DB_txn *const fake, DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	if(!fake) return DB_EINVAL;
	DB_prefix_txn const *const txn = (DB_prefix_txn *)fake;
	assert_zeroed(cursor, 1);
	int rc = 0;
	cursor->isa = db_base_prefix;

	rc = db_cursor_init(txn->txn, CURSOR_INNER(cursor));
	if(rc < 0) goto cleanup;

	cursor->key_max = 512;
	DB_env *env = NULL;
	(void) db_txn_env(txn->txn, &env);
	(void) db_env_get_config(env, DB_CFG_KEYSIZE, &cursor->key_max);
	for(size_t i = 0; i < numberof(cursor->bufs); i++) {
		cursor->bufs[i] = malloc(cursor->key_max);
		if(!cursor->bufs[i]) rc = DB_ENOMEM;
		if(rc < 0) goto cleanup;
	}

	*cursor->pfx = (DB_val){ txn->pfx->size, malloc(txn->pfx->size+1) };
	if(!cursor->pfx->data) rc = DB_ENOMEM;
	if(rc < 0) goto cleanup;
	memcpy(cursor->pfx->data, txn->pfx->data, txn->pfx->size);

cleanup:
	if(rc < 0) db_cursor_destroy(cursor);
	return rc;
}
DB_FN void db__cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	db_cursor_destroy(CURSOR_INNER(cursor));
	cursor->key_max = 0;
	free(cursor->pfx->data); cursor->pfx->data = NULL;
	cursor->pfx->size = 0;
	memset(cursor->key, 0, sizeof(*cursor->key));
	memset(cursor->range, 0, sizeof(*cursor->range));
	for(size_t i = 0; i < numberof(cursor->bufs); i++) {
		free(cursor->bufs[i]); cursor->bufs[i] = NULL;
	}
	cursor->isa = NULL;
	assert_zeroed(cursor, 1);
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	return db_cursor_clear(CURSOR_INNER(cursor));
}
DB_FN int db__cursor_txn(DB_cursor *const cursor, DB_txn **const out) {
	if(!cursor) return DB_EINVAL;
	return DB_ENOTSUP;
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
	int rc = db_cursor_seek(CURSOR_INNER(cursor), pfx_key(cursor, key), data, dir);
	if(rc >= 0 && 0 != dir) key_strip(cursor, cursor->key, key);
	return rc;
}
DB_FN int db__cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_first(CURSOR_INNER(cursor), key, data, dir);
	if(rc >= 0) key_strip(cursor, key, key);
	return rc;
}
DB_FN int db__cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	int rc = db_cursor_next(CURSOR_INNER(cursor), key, data, dir);
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

DB_base const db_base_prefix[1] = {{
	.version = 0,
	.name = "prefix",
	.cursor_size = db__cursor_size,
	.cursor_init = db__cursor_init,
	.cursor_destroy = db__cursor_destroy,
	.cursor_clear = db__cursor_clear,
	.cursor_txn = db__cursor_txn,
	.cursor_cmp = db__cursor_cmp,
	.cursor_current = db__cursor_current,
	.cursor_seek = db__cursor_seek,
	.cursor_first = db__cursor_first,
	.cursor_next = db__cursor_next,
	.cursor_seekr = db__cursor_seekr,
	.cursor_firstr = db__cursor_firstr,
	.cursor_nextr = db__cursor_nextr,
	.cursor_put = db__cursor_put,
	.cursor_del = db__cursor_del,
}};

