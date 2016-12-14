// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdio.h>
#include "db_base_internal.h"

int db_helper_get(DB_txn *const txn, DB_val *const key, DB_val *const data) {
	DB_cursor *cursor;
	int rc = db_txn_cursor(txn, &cursor);
	if(rc < 0) return rc;
	return db_cursor_seek(cursor, key, data, 0);
}
int db_helper_put(DB_txn *const txn, DB_val *const key, DB_val *const data, unsigned const flags) {
	DB_cursor *cursor;
	int rc = db_txn_cursor(txn, &cursor);
	if(rc < 0) return rc;
	return db_cursor_put(cursor, key, data, flags);
}
int db_helper_del(DB_txn *const txn, DB_val *const key, unsigned const flags) {
	DB_cursor *cursor;
	int rc = db_txn_cursor(txn, &cursor);
	if(rc < 0) return rc;
	rc = db_cursor_seek(cursor, key, NULL, 0);
	if(DB_NOTFOUND == rc) return 0; // Unless flags & DB_NOOVERWRITE?
	if(rc < 0) return rc;
	return db_cursor_del(cursor, flags);
}

int db_helper_countr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	if(!out) return DB_EINVAL;
	uint64_t n = 0;
	DB_cursor *cursor = NULL;
	int rc = db_txn_cursor(txn, &cursor);
	if(rc < 0) goto cleanup;
	rc = db_cursor_firstr(cursor, range, NULL, NULL, +1);
	for(; rc >= 0; rc = db_cursor_nextr(cursor, range, NULL, NULL, +1)) {
		n++;
	}
	if(DB_NOTFOUND == rc) rc = 0;
	if(rc < 0) goto cleanup;
	*out = n;
cleanup:
	cursor = NULL;
	return rc;
}
int db_helper_delr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	DB_val key[1];
	uint64_t n = 0;
	DB_cursor *cursor = NULL;
	int rc = db_cursor_open(txn, &cursor);
	if(rc < 0) goto cleanup;
	rc = db_cursor_firstr(cursor, range, key, NULL, +1);
	for(; rc >= 0; rc = db_cursor_nextr(cursor, range, key, NULL, +1)) {
		rc = db_del(txn, key, 0);
		if(rc < 0) goto cleanup;
		n++;
	}
	if(DB_NOTFOUND == rc) rc = 0;
	if(rc < 0) goto cleanup;
	if(out) *out = n;
cleanup:
	db_cursor_close(cursor); cursor = NULL;
	return rc;
}

int db_helper_cursor_seekr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	assert(db_cursor_cmp(cursor, range->min, range->max) < 0);
	int rc = db_cursor_seek(cursor, key, data, dir);
	if(rc < 0) return rc;
	int const min = db_cursor_cmp(cursor, key, range->min);
	int const max = db_cursor_cmp(cursor, key, range->max);
	if(min > 0 && max < 0) return 0;
	db_cursor_clear(cursor);
	return DB_NOTFOUND;
}
int db_helper_cursor_firstr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	assert(db_cursor_cmp(cursor, range->min, range->max) < 0);
	if(0 == dir) return DB_EINVAL;
	DB_val const *const first = dir > 0 ? range->min : range->max;
	DB_val k = *first;
	int rc = db_cursor_seek(cursor, &k, data, dir);
	if(rc < 0) return rc;
	int x = db_cursor_cmp(cursor, &k, first);
	assert(x * dir >= 0);
	if(0 == x) {
		rc = db_cursor_next(cursor, &k, data, dir);
		if(rc < 0) return rc;
	}
	DB_val const *const last = dir < 0 ? range->min : range->max;
	x = db_cursor_cmp(cursor, &k, last);
	if(x * dir < 0) {
		if(key) *key = k;
		return 0;
	} else {
		db_cursor_clear(cursor);
		return DB_NOTFOUND;
	}
}
int db_helper_cursor_nextr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	assert(db_cursor_cmp(cursor, range->min, range->max) < 0);
	DB_val tmp;
	DB_val *k = key ? key : &tmp;
	int rc = db_cursor_next(cursor, k, data, dir);
	if(rc < 0) return rc;
	int const min = db_cursor_cmp(cursor, k, range->min);
	int const max = db_cursor_cmp(cursor, k, range->max);
	if(min > 0 && max < 0) return 0;
	db_cursor_clear(cursor);
	return DB_NOTFOUND;
}

