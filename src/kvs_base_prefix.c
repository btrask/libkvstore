// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include "kvs_helper.h"
#include "common.h"

struct KVS_txn {
	KVS_base const *isa;
	KVS_txn *sub;
	size_t key_max;
	KVS_range keyspace[1];
	KVS_cursor *cursor;
};
struct KVS_cursor {
	KVS_base const *isa;
	KVS_txn *txn;
	unsigned char *bufs[3];
	KVS_val key[1];
	KVS_range range[1];
	// Inner cursor
};
#define CURSOR_INNER(x) ((x)+1)

static bool key_ok(KVS_cursor *const cursor, KVS_val const *const key) {
	assert(cursor);
	KVS_txn *const txn = cursor->txn;
	if(!key) return true;
	return txn->keyspace->min->size + key->size < txn->key_max;
}
static bool range_ok(KVS_cursor *const cursor, KVS_range const *const range) {
	return key_ok(cursor, range->min) && key_ok(cursor, range->max);
}
static KVS_val *pfx_internal(KVS_cursor *const cursor, KVS_val const *const key, KVS_val *const storage) {
	assert(cursor);
	KVS_txn *const txn = cursor->txn;
	if(!key) return NULL;
	KVS_val *const out = storage;
	KVS_val const *const a = txn->keyspace->min;
	KVS_val const *const b = key;
	size_t const n = a->size;
	assert(a->size + b->size < txn->key_max);
	out->size = a->size + b->size;
	memcpy(out->data+0, a->data, a->size);
	memcpy(out->data+n, b->data, b->size);
	return out;
}
static KVS_val *pfx_key(KVS_cursor *const cursor, KVS_val const *const key) {
	*cursor->key = (KVS_val){ 0, cursor->bufs[0] };
	return pfx_internal(cursor, key, cursor->key);
}
static KVS_range *pfx_range(KVS_cursor *const cursor, KVS_range const *const range) {
	*cursor->range->min = (KVS_val){0, cursor->bufs[1] };
	*cursor->range->max = (KVS_val){0, cursor->bufs[2] };
	pfx_internal(cursor, range->min, cursor->range->min);
	pfx_internal(cursor, range->max, cursor->range->max);
	return cursor->range;
}
static void key_strip(KVS_cursor *const cursor, KVS_val const *const src, KVS_val *const dst) {
	if(!dst) return;
	KVS_txn *const txn = cursor->txn;
	KVS_val const *const pfx = txn->keyspace->min;
	dst->data = src->data + pfx->size;
	dst->size = src->size - pfx->size;
}

static void range_destroy(KVS_range *range) {
	if(!range) return;
	free(range->min->data); range->min->data = NULL;
	free(range->max->data); range->max->data = NULL;
	range->min->size = 0;
	range->max->size = 0;
}
static void genmax(KVS_range *const range) {
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
static int keyspace(KVS_range *const range, KVS_val const *const pfx) {
	assert(range);
	range_destroy(range);
	if(!pfx || !pfx->size) return 0;
	if(!pfx->data) return KVS_EINVAL;
	range->min->size = pfx->size;
	range->min->data = malloc(pfx->size);
	range->max->data = malloc(pfx->size);
	if(!range->min->data || !range->max->data) {
		range_destroy(range);
		return KVS_ENOMEM;
	}
	memcpy(range->min->data, pfx->data, pfx->size);
	genmax(range);
	return 0;
}

KVS_FN size_t kvs__txn_size(KVS_env *const env) {
	if(env) return 0; // Wrapper only
	return sizeof(struct KVS_txn);
}
KVS_FN int kvs__txn_init(KVS_env *const env, KVS_txn *const txn) {
	if(!txn) return KVS_EINVAL;
	if(env) return KVS_EINVAL; // Wrapper only
	assert_zeroed(txn, 1);
	txn->isa = kvs_base_prefix;
	return 0;
}
KVS_FN int kvs__txn_get_config(KVS_txn *const txn, char const *const type, void *data) {
	if(!txn) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	if(0 == strcmp(type, KVS_TXN_CURSOR)) {
		if(!txn->cursor) {
			int rc = kvs_cursor_open(txn, &txn->cursor);
			if(rc < 0) return rc;
		}
		*(KVS_cursor **)data = txn->cursor;
		return 0;
	} else if(0 == strcmp(type, KVS_TXN_WRAPPEDTXN)) {
		*(KVS_txn **)data = txn->sub;
		return 0;
	} else if(0 == strcmp(type, KVS_TXN_PREFIX)) {
		*(KVS_val *)data = *txn->keyspace->min;
		return 0;
	} else {
		return KVS_ENOTSUP;
	}
}
KVS_FN int kvs__txn_set_config(KVS_txn *const txn, char const *const type, void *data) {
	if(!txn) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	if(0 == strcmp(type, KVS_TXN_WRAPPEDTXN)) {
		txn->sub = data;
		return 0;
	} else if(0 == strcmp(type, KVS_TXN_PREFIX)) {
		return keyspace(txn->keyspace, data);
	} else {
		return KVS_ENOTSUP;
	}
}
KVS_FN int kvs__txn_begin0(KVS_txn *const txn) {
	if(!txn) return KVS_EINVAL;
	txn->key_max = 512; // TODO
	return 0;
}
KVS_FN int kvs__txn_commit_destroy(KVS_txn *txn) {
	if(!txn) return KVS_EINVAL;
	return KVS_ENOTSUP;
}
KVS_FN void kvs__txn_abort_destroy(KVS_txn *txn) {
	if(!txn) return;
	kvs_cursor_close(txn->cursor); txn->cursor = NULL;
	txn->sub = NULL; // Non-owning
	txn->key_max = 0;
	range_destroy(txn->keyspace);
	txn->isa = NULL;
	assert_zeroed(txn, 1);
}
KVS_FN int kvs__txn_cmp(KVS_txn *const txn, KVS_val const *const a, KVS_val const *const b) {
	assert(txn);
	return kvs_txn_cmp(txn->sub, a, b);
}

KVS_FN int kvs__get(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data) {
	return kvs_helper_get(txn, key, data);
}
KVS_FN int kvs__put(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data, unsigned const flags) {
	return kvs_helper_put(txn, key, data, flags);
}
KVS_FN int kvs__del(KVS_txn *const txn, KVS_val const *const key, unsigned const flags) {
	return kvs_helper_del(txn, key, flags); // TODO
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
	return sizeof(struct KVS_cursor)+kvs_cursor_size(txn->sub);
}
KVS_FN int kvs__cursor_init(KVS_txn *const txn, KVS_cursor *const cursor) {
	if(!txn) return KVS_EINVAL;
	if(!cursor) return KVS_EINVAL;
	assert_zeroed(cursor, 1);
	int rc = 0;
	cursor->isa = kvs_base_prefix;
	cursor->txn = txn;

	rc = kvs_cursor_init(txn->sub, CURSOR_INNER(cursor));
	if(rc < 0) goto cleanup;

	for(size_t i = 0; i < numberof(cursor->bufs); i++) {
		cursor->bufs[i] = malloc(cursor->txn->key_max);
		if(!cursor->bufs[i]) {
			rc = KVS_ENOMEM;
			goto cleanup;
		}
	}

cleanup:
	if(rc < 0) kvs_cursor_destroy(cursor);
	return rc;
}
KVS_FN void kvs__cursor_destroy(KVS_cursor *const cursor) {
	if(!cursor) return;
	kvs_cursor_destroy(CURSOR_INNER(cursor));
	memset(cursor->key, 0, sizeof(*cursor->key));
	memset(cursor->range, 0, sizeof(*cursor->range));
	for(size_t i = 0; i < numberof(cursor->bufs); i++) {
		free(cursor->bufs[i]); cursor->bufs[i] = NULL;
	}
	cursor->txn = NULL;
	cursor->isa = NULL;
	assert_zeroed(cursor, 1);
}
KVS_FN int kvs__cursor_clear(KVS_cursor *const cursor) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_clear(CURSOR_INNER(cursor));
}
KVS_FN int kvs__cursor_txn(KVS_cursor *const cursor, KVS_txn **const out) {
	if(!cursor) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	*out = cursor->txn;
	return 0;
}
KVS_FN int kvs__cursor_cmp(KVS_cursor *const cursor, KVS_val const *const a, KVS_val const *const b) {
	assert(cursor);
	return kvs_cursor_cmp(CURSOR_INNER(cursor), a, b);
}

KVS_FN int kvs__cursor_current(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_current(CURSOR_INNER(cursor), key, data);
	if(rc >= 0) key_strip(cursor, key, key);
	return rc;
}
KVS_FN int kvs__cursor_seek(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	if(!key_ok(cursor, key)) return KVS_BAD_VALSIZE;
	int rc = kvs_cursor_seekr(CURSOR_INNER(cursor),
		cursor->txn->keyspace, pfx_key(cursor, key), data, dir);
	if(rc >= 0 && 0 != dir) key_strip(cursor, cursor->key, key);
	return rc;
}
KVS_FN int kvs__cursor_first(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_firstr(CURSOR_INNER(cursor),
		cursor->txn->keyspace, key, data, dir);
	if(rc >= 0) key_strip(cursor, key, key);
	return rc;
}
KVS_FN int kvs__cursor_next(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	int rc = kvs_cursor_nextr(CURSOR_INNER(cursor),
		cursor->txn->keyspace, key, data, dir);
	if(rc >= 0) key_strip(cursor, key, key);
	return rc;
}

// TODO: We should be able to use KVS_HELPER_CURSOR_RANGE_FUNCS here.
// However, an initial attempt produced incorrect results,
// which may indicate a bug.
KVS_FN int kvs__cursor_seekr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	if(!range_ok(cursor, range)) return KVS_BAD_VALSIZE;
	if(!key_ok(cursor, key)) return KVS_BAD_VALSIZE;
	int rc = kvs_cursor_seekr(CURSOR_INNER(cursor),
		pfx_range(cursor, range), pfx_key(cursor, key), data, dir);
	if(rc >= 0 && 0 != dir) key_strip(cursor, cursor->key, key);
	return rc;
}
KVS_FN int kvs__cursor_firstr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	if(!range_ok(cursor, range)) return KVS_BAD_VALSIZE;
	int rc = kvs_cursor_firstr(CURSOR_INNER(cursor),
		pfx_range(cursor, range), key, data, dir);
	if(rc >= 0) key_strip(cursor, key, key);
	return rc;
}
KVS_FN int kvs__cursor_nextr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	if(!range_ok(cursor, range)) return KVS_BAD_VALSIZE;
	int rc = kvs_cursor_nextr(CURSOR_INNER(cursor),
		pfx_range(cursor, range), key, data, dir);
	if(rc >= 0) key_strip(cursor, key, key);
	return rc;
}

KVS_FN int kvs__cursor_put(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	if(!key_ok(cursor, key)) return KVS_BAD_VALSIZE;
	int rc = kvs_cursor_put(CURSOR_INNER(cursor),
		pfx_key(cursor, key), data, flags);
	if(rc >= 0 && KVS_CURRENT & flags) key_strip(cursor, cursor->key, key);
	return rc;
}
KVS_FN int kvs__cursor_del(KVS_cursor *const cursor, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_del(CURSOR_INNER(cursor), flags);
}

KVS_base const kvs_base_prefix[1] = {{
	.version = 0,
	.name = "prefix",

	.txn_size = kvs__txn_size,
	.txn_init = kvs__txn_init,
	.txn_get_config = kvs__txn_get_config,
	.txn_set_config = kvs__txn_set_config,
	.txn_begin0 = kvs__txn_begin0,
	.txn_commit_destroy = kvs__txn_commit_destroy,
	.txn_abort_destroy = kvs__txn_abort_destroy,
	.txn_cmp = kvs__txn_cmp,

	.get = kvs__get,
	.put = kvs__put,
	.del = kvs__del,
	.cmd = kvs__cmd,

	.countr = kvs__countr,
	.delr = kvs__delr,

	.cursor_size = kvs__cursor_size,
	.cursor_init = kvs__cursor_init,
	.cursor_destroy = kvs__cursor_destroy,
	.cursor_clear = kvs__cursor_clear,
	.cursor_txn = kvs__cursor_txn,
	.cursor_cmp = kvs__cursor_cmp,

	.cursor_current = kvs__cursor_current,
	.cursor_seek = kvs__cursor_seek,
	.cursor_first = kvs__cursor_first,
	.cursor_next = kvs__cursor_next,

	.cursor_seekr = kvs__cursor_seekr,
	.cursor_firstr = kvs__cursor_firstr,
	.cursor_nextr = kvs__cursor_nextr,

	.cursor_put = kvs__cursor_put,
	.cursor_del = kvs__cursor_del,
}};

