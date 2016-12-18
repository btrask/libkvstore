// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <string.h>
#include "db_wrbuf.h"

int db_wrbuf_init(DB_wrbuf *const buf, DB_cursor *const temp, DB_cursor *const main) {
	if(!buf) return DB_EINVAL;
	if(!main) return DB_EINVAL;
	buf->temp = temp;
	buf->main = main;
	return db_wrbuf_clear(buf);
}
void db_wrbuf_destroy(DB_wrbuf *const buf) {
	if(!buf) return;
	buf->state = DB_WRBUF_INVALID;
	db_cursor_close(buf->temp); buf->temp = NULL;
	db_cursor_close(buf->main); buf->main = NULL;
}
int db_wrbuf_clear(DB_wrbuf *const buf) {
	if(!buf) return DB_EINVAL;
	if(!buf->temp) {
		return db_cursor_clear(buf->main);
	} else {
		buf->state = DB_WRBUF_INVALID;
		return 0;
	}
}

static int update(DB_wrbuf *const buf, int rc1, DB_val *const k1, DB_val *const d1, int const rc2, DB_val const *const k2, DB_val const *const d2, int const dir, DB_val *const key, DB_val *const data) {
	if(!buf->temp) {
		if(key) *key = *k2;
		if(data) *data = *d2;
		return rc2;
	}
	for(;;) {
		buf->state = DB_WRBUF_INVALID;
		if(rc1 < 0 && DB_NOTFOUND != rc1) return rc1;
		if(rc2 < 0 && DB_NOTFOUND != rc2) return rc2;
		if(DB_NOTFOUND == rc1 && DB_NOTFOUND == rc2) return DB_NOTFOUND;

		int x = 0;
		if(DB_NOTFOUND == rc1) x = +1;
		if(DB_NOTFOUND == rc2) x = -1;
		if(0 == x) {
			x = db_cursor_cmp(buf->temp, k1, k2) * (dir ? dir : 1);
		}
		if(x > 0) {
			buf->state = DB_WRBUF_MAIN;
			if(key) *key = *k2;
			if(data) *data = *d2;
			return 0;
		}
		buf->state = 0 == x ? DB_WRBUF_EQUAL : DB_WRBUF_TEMP;
		char const type = db_wrbuf_type(d1);
		if(DB_WRBUF_PUT == type) {
			db_wrbuf_trim(d1);
			if(key) *key = *k1;
			if(data) *data = *d1;
			return 0;
		}

		// The current key is a tombstone. Try to seek past it.
		assert(DB_WRBUF_DEL == type);
		if(0 == dir) {
			buf->state = DB_WRBUF_INVALID;
			return DB_NOTFOUND;
		}
		rc1 = db_cursor_next(buf->temp, k1, d1, dir);
	}
}

int db_wrbuf_current(DB_wrbuf *const buf, DB_val *const key, DB_val *const data) {
	if(!buf) return DB_EINVAL;
	if(!buf->temp || DB_WRBUF_MAIN == buf->state) {
		return db_cursor_current(buf->main, key, data);
	} else if(DB_WRBUF_EQUAL == buf->state || DB_WRBUF_TEMP == buf->state) {
		int rc = db_cursor_current(buf->temp, key, data);
		if(DB_EINVAL == rc) return DB_NOTFOUND;
		if(rc < 0) return rc;
		if(data) {
			assert(DB_WRBUF_DEL != db_wrbuf_type(data));
			db_wrbuf_trim(data);
		}
		return 0;
	} else if(DB_WRBUF_INVALID == buf->state) {
		return DB_NOTFOUND;
	} else {
		assert(0);
		return DB_EINVAL;
	}
}
int db_wrbuf_seek(DB_wrbuf *const buf, DB_val *const key, DB_val *const data, int const dir) {
	if(!buf) return DB_EINVAL;
	DB_val k1[1] = { *key }, d1[1];
	DB_val k2[1] = { *key }, d2[1];
	int rc1 = db_cursor_seek(buf->temp, k1, d1, dir);
	int rc2 = db_cursor_seek(buf->main, k2, d2, dir);
	return update(buf, rc1, k1, d1, rc2, k2, d2, dir, dir ? key : NULL, data);
	// Note: We pass NULL for the output key to emulate MDB_SET semantics,
	// which doesn't touch the key at all and leaves it pointing to the
	// user's copy. For MDB_SET_KEY behavior, you must make an extra call
	// to db_cursor_current.
	// Note: This only applies when dir is 0.
}
int db_wrbuf_first(DB_wrbuf *const buf, DB_val *const key, DB_val *const data, int const dir) {
	if(!buf) return DB_EINVAL;
	if(0 == dir) return DB_EINVAL;
	DB_val k1[1], d1[1], k2[1], d2[1];
	int rc1 = db_cursor_first(buf->temp, k1, d1, dir);
	int rc2 = db_cursor_first(buf->main, k2, d2, dir);
	return update(buf, rc1, k1, d1, rc2, k2, d2, dir, key, data);
}
int db_wrbuf_next(DB_wrbuf *const buf, DB_val *const key, DB_val *const data, int const dir) {
	if(!buf) return DB_EINVAL;
	if(0 == dir) return DB_EINVAL;
	int rc1, rc2;
	DB_val k1[1], d1[1], k2[1], d2[1];
	if(DB_WRBUF_MAIN != buf->state) {
		rc1 = db_cursor_next(buf->temp, k1, d1, dir);
	} else {
		rc1 = db_cursor_current(buf->temp, k1, d1);
		if(DB_EINVAL == rc1) rc1 = DB_NOTFOUND;
	}
	if(DB_WRBUF_TEMP != buf->state) {
		rc2 = db_cursor_next(buf->main, k2, d2, dir);
	} else {
		rc2 = db_cursor_current(buf->main, k2, d2);
	}
	return update(buf, rc1, k1, d1, rc2, k2, d2, dir, key, data);
}

int db_wrbuf_put(DB_wrbuf *const buf, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!buf) return DB_EINVAL;
	if(!key) return DB_EINVAL;
	if(!buf->temp) return DB_EACCES;
	DB_val k[1], d[1];
	int rc = 0;
	// DB_APPEND is mostly just an optimization, so we currently
	// don't bother checking it.
	if(DB_CURRENT & flags) { // TODO: Just forward DB_CURRENT?
		rc = db_wrbuf_current(buf, k, NULL);
		if(rc < 0) return rc;
	} else {
		*k = *key;
	}
	if(DB_NOOVERWRITE & flags) {
		rc = db_wrbuf_seek(buf, k, d, 0);
		if(rc >= 0) {
			if(data) *data = *d;
			return DB_KEYEXIST;
		}
		if(DB_NOTFOUND != rc) return rc;
	}
	buf->state = DB_WRBUF_TEMP;
	*d = (DB_val){ 1+(data ? data->size : 0), NULL }; // Prefix with deletion flag.
	assert(buf->temp);
	rc = db_cursor_put(buf->temp, k, d, DB_RESERVE);
	if(rc < 0) return rc;
	assert(d->data);
	memset(d->data+0, DB_WRBUF_PUT, 1);
	if(DB_RESERVE & flags) {
		if(data) *data = (DB_val){ d->size-1, (char *)d->data+1 };
	} else {
		if(data && data->size > 0) memcpy(d->data+1, data->data, data->size);
	}
	return 0;
}
int db_wrbuf_del(DB_wrbuf *const buf, unsigned const flags) {
	if(!buf) return DB_EINVAL;
	if(flags) return DB_EINVAL;
	if(!buf->temp) return DB_EACCES;
	DB_val k[1], d[1];
	int rc = db_wrbuf_current(buf, k, NULL);
	if(rc < 0) return rc;
	buf->state = DB_WRBUF_INVALID;
	char tombstone = DB_WRBUF_DEL;
	*d = (DB_val){ sizeof(tombstone), &tombstone };
	assert(buf->temp);
	rc = db_cursor_put(buf->temp, k, d, 0);
	if(rc < 0) return rc;
	return 0;
}

