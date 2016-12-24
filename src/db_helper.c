// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdio.h>
#include "db_base_internal.h"

int kvs_helper_get(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data) {
	KVS_cursor *cursor;
	int rc = kvs_txn_cursor(txn, &cursor);
	if(rc < 0) return rc;
	return kvs_cursor_seek(cursor, (KVS_val *)key, data, 0);
}
int kvs_helper_put(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data, unsigned const flags) {
	KVS_cursor *cursor;
	int rc = kvs_txn_cursor(txn, &cursor);
	if(rc < 0) return rc;
	return kvs_cursor_put(cursor, (KVS_val *)key, data, flags);
}
int kvs_helper_del(KVS_txn *const txn, KVS_val const *const key, unsigned const flags) {
	KVS_cursor *cursor;
	int rc = kvs_txn_cursor(txn, &cursor);
	if(rc < 0) return rc;
	rc = kvs_cursor_seek(cursor, (KVS_val *)key, NULL, 0);
	if(KVS_NOTFOUND == rc) return 0; // Unless flags & KVS_NOOVERWRITE?
	if(rc < 0) return rc;
	return kvs_cursor_del(cursor, flags);
}
int kvs_helper_cmd(KVS_txn *const txn, unsigned char const *const buf, size_t const len) {
	KVS_env *env = NULL;
	KVS_cmd_data *cmd = NULL;
	int rc = kvs_txn_env(txn, &env);
	if(rc < 0) return rc;
	rc = kvs_env_get_config(env, KVS_CFG_COMMAND, &cmd);
	if(rc < 0) return rc;
	if(!cmd || !cmd->fn) return KVS_EINVAL;
	return cmd->fn(cmd->ctx, txn, buf, len);
}

int kvs_helper_countr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	if(!out) return KVS_EINVAL;
	uint64_t n = 0;
	KVS_cursor *cursor = NULL;
	int rc = kvs_txn_cursor(txn, &cursor);
	if(rc < 0) goto cleanup;
	rc = kvs_cursor_firstr(cursor, range, NULL, NULL, +1);
	for(; rc >= 0; rc = kvs_cursor_nextr(cursor, range, NULL, NULL, +1)) {
		n++;
	}
	if(KVS_NOTFOUND == rc) rc = 0;
	if(rc < 0) goto cleanup;
	*out = n;
cleanup:
	cursor = NULL;
	return rc;
}
int kvs_helper_delr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	KVS_val key[1];
	uint64_t n = 0;
	KVS_cursor *cursor = NULL;
	int rc = kvs_cursor_open(txn, &cursor);
	if(rc < 0) goto cleanup;
	rc = kvs_cursor_firstr(cursor, range, key, NULL, +1);
	for(; rc >= 0; rc = kvs_cursor_nextr(cursor, range, key, NULL, +1)) {
		rc = kvs_del(txn, key, 0);
		if(rc < 0) goto cleanup;
		n++;
	}
	if(KVS_NOTFOUND == rc) rc = 0;
	if(rc < 0) goto cleanup;
	if(out) *out = n;
cleanup:
	kvs_cursor_close(cursor); cursor = NULL;
	return rc;
}

int kvs_helper_cursor_seekr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	assert(kvs_cursor_cmp(cursor, range->min, range->max) < 0);
	int rc = kvs_cursor_seek(cursor, key, data, dir);
	if(rc < 0) return rc;
	int const min = kvs_cursor_cmp(cursor, key, range->min);
	int const max = kvs_cursor_cmp(cursor, key, range->max);
	if(min > 0 && max < 0) return 0;
	kvs_cursor_clear(cursor);
	return KVS_NOTFOUND;
}
int kvs_helper_cursor_firstr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	assert(kvs_cursor_cmp(cursor, range->min, range->max) < 0);
	if(0 == dir) return KVS_EINVAL;
	KVS_val const *const first = dir > 0 ? range->min : range->max;
	KVS_val k = *first;
	int rc = kvs_cursor_seek(cursor, &k, data, dir);
	if(rc < 0) return rc;
	int x = kvs_cursor_cmp(cursor, &k, first);
	assert(x * dir >= 0);
	if(0 == x) {
		rc = kvs_cursor_next(cursor, &k, data, dir);
		if(rc < 0) return rc;
	}
	KVS_val const *const last = dir < 0 ? range->min : range->max;
	x = kvs_cursor_cmp(cursor, &k, last);
	if(x * dir < 0) {
		if(key) *key = k;
		return 0;
	} else {
		kvs_cursor_clear(cursor);
		return KVS_NOTFOUND;
	}
}
int kvs_helper_cursor_nextr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	assert(kvs_cursor_cmp(cursor, range->min, range->max) < 0);
	KVS_val tmp;
	KVS_val *k = key ? key : &tmp;
	int rc = kvs_cursor_next(cursor, k, data, dir);
	if(rc < 0) return rc;
	int const min = kvs_cursor_cmp(cursor, k, range->min);
	int const max = kvs_cursor_cmp(cursor, k, range->max);
	if(min > 0 && max < 0) return 0;
	kvs_cursor_clear(cursor);
	return KVS_NOTFOUND;
}

int kvs_helper_cursor_del(KVS_cursor *const cursor, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	if(flags) return KVS_ENOTSUP;
	KVS_txn *txn = NULL;
	KVS_val key[1];
	int rc = kvs_cursor_txn(cursor, &txn);
	if(rc < 0) return rc;
	rc = kvs_cursor_current(cursor, key, NULL);
	if(rc < 0) return rc;
	rc = kvs_del(txn, key, flags);
	if(rc < 0) return rc;
	kvs_cursor_clear(cursor);
	return rc;
}

