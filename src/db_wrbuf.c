// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <stdio.h>
#include <string.h>
#include "db_wrbuf.h"
#include "common.h"

typedef enum {
	DB_WRBUF_INVALID = 0,
	DB_WRBUF_EQUAL,
	DB_WRBUF_TEMP,
	DB_WRBUF_MAIN,
} DB_wrbuf_state;

struct DB_cursor {
	DB_base const *isa;
	DB_wrbuf_state state;
	DB_cursor *temp; // Hard to calculate and also optional
	// Main cursor
	// Temp cursor, if present
};
#define CURSOR_MAIN(c) ((c)+1)
#define CURSOR_TEMP(c) ((c)->temp)

DB_FN size_t db__cursor_size(DB_txn *const fake) {
	DB_wrbuf_txn const *const txn = (DB_wrbuf_txn *)fake;
	return sizeof(struct DB_cursor)
		+ db_cursor_size(txn->main)
		+ (txn->temp ? db_cursor_size(txn->temp) : 0);
}
DB_FN int db__cursor_init(DB_txn *const fake, DB_cursor *const cursor) {
	if(!fake) return DB_EINVAL;
	if(!cursor) return DB_EINVAL;
	assert_zeroed(cursor, 1);
	DB_wrbuf_txn const *const txn = (DB_wrbuf_txn *)fake;
	int rc = 0;
	cursor->isa = db_base_wrbuf;
	cursor->state = DB_WRBUF_INVALID;
	cursor->temp = NULL;

	rc = db_cursor_init(txn->main, CURSOR_MAIN(cursor));
	if(rc < 0) goto cleanup;

	if(txn->temp) {
		cursor->temp = (DB_cursor *)((char *)CURSOR_MAIN(cursor)
			+ db_cursor_size(txn->main));
		rc = db_cursor_init(txn->temp, CURSOR_TEMP(cursor));
		if(rc < 0) goto cleanup;
	}

cleanup:
	if(rc < 0) db_cursor_destroy(cursor);
	return rc;
}
void db__cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	cursor->state = DB_WRBUF_INVALID;
	db_cursor_destroy(CURSOR_TEMP(cursor));
	db_cursor_destroy(CURSOR_MAIN(cursor));
	cursor->temp = NULL;
	cursor->isa = NULL;
	assert_zeroed(cursor, 1);
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	if(!cursor->temp) {
		return db_cursor_clear(CURSOR_MAIN(cursor));
	} else {
		cursor->state = DB_WRBUF_INVALID;
		return 0;
	}
}
DB_FN int db__cursor_txn(DB_cursor *const cursor, DB_txn **const out) {
	if(!cursor) return DB_EINVAL;
	return DB_ENOTSUP;
}
DB_FN int db__cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	assert(cursor);
	return db_cursor_cmp(CURSOR_MAIN(cursor), a, b);
}

static int update(DB_cursor *const cursor, int rc1, DB_val *const k1, DB_val *const d1, int const rc2, DB_val const *const k2, DB_val const *const d2, int const dir, DB_val *const key, DB_val *const data) {
	if(!cursor->temp) {
		if(key) *key = *k2;
		if(data) *data = *d2;
		return rc2;
	}
	for(;;) {
		cursor->state = DB_WRBUF_INVALID;
		if(rc1 < 0 && DB_NOTFOUND != rc1) return rc1;
		if(rc2 < 0 && DB_NOTFOUND != rc2) return rc2;
		if(DB_NOTFOUND == rc1 && DB_NOTFOUND == rc2) return DB_NOTFOUND;

		int x = 0;
		if(DB_NOTFOUND == rc1) x = +1;
		if(DB_NOTFOUND == rc2) x = -1;
		if(0 == x) {
			x = db_cursor_cmp(CURSOR_TEMP(cursor), k1, k2) * (dir ? dir : 1);
		}
		if(x > 0) {
			cursor->state = DB_WRBUF_MAIN;
			if(key) *key = *k2;
			if(data) *data = *d2;
			return 0;
		}
		cursor->state = 0 == x ? DB_WRBUF_EQUAL : DB_WRBUF_TEMP;
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
			cursor->state = DB_WRBUF_INVALID;
			return DB_NOTFOUND;
		}
		rc1 = db_cursor_next(CURSOR_TEMP(cursor), k1, d1, dir);
	}
}

DB_FN int db__cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	if(!cursor->temp || DB_WRBUF_MAIN == cursor->state) {
		return db_cursor_current(CURSOR_MAIN(cursor), key, data);
	} else if(DB_WRBUF_EQUAL == cursor->state || DB_WRBUF_TEMP == cursor->state) {
		int rc = db_cursor_current(CURSOR_TEMP(cursor), key, data);
		if(DB_EINVAL == rc) return DB_NOTFOUND;
		if(rc < 0) return rc;
		if(data) {
			assert(DB_WRBUF_DEL != db_wrbuf_type(data));
			db_wrbuf_trim(data);
		}
		return 0;
	} else if(DB_WRBUF_INVALID == cursor->state) {
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
	int rc1 = db_cursor_seek(CURSOR_TEMP(cursor), k1, d1, dir);
	int rc2 = db_cursor_seek(CURSOR_MAIN(cursor), k2, d2, dir);
	return update(cursor, rc1, k1, d1, rc2, k2, d2, dir, dir ? key : NULL, data);
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
	int rc1 = db_cursor_first(CURSOR_TEMP(cursor), k1, d1, dir);
	int rc2 = db_cursor_first(CURSOR_MAIN(cursor), k2, d2, dir);
	return update(cursor, rc1, k1, d1, rc2, k2, d2, dir, key, data);
}
DB_FN int db__cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	if(0 == dir) return DB_EINVAL;
	int rc1, rc2;
	DB_val k1[1], d1[1], k2[1], d2[1];
	if(DB_WRBUF_MAIN != cursor->state) {
		rc1 = db_cursor_next(CURSOR_TEMP(cursor), k1, d1, dir);
	} else {
		rc1 = db_cursor_current(CURSOR_TEMP(cursor), k1, d1);
		if(DB_EINVAL == rc1) rc1 = DB_NOTFOUND;
	}
	if(DB_WRBUF_TEMP != cursor->state) {
		rc2 = db_cursor_next(CURSOR_MAIN(cursor), k2, d2, dir);
	} else {
		rc2 = db_cursor_current(CURSOR_MAIN(cursor), k2, d2);
	}
	return update(cursor, rc1, k1, d1, rc2, k2, d2, dir, key, data);
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
	if(!key) return DB_EINVAL;
	if(!cursor->temp) return DB_EACCES;
	DB_val k[1], d[1];
	int rc = 0;
	// DB_APPEND is mostly just an optimization, so we currently
	// don't bother checking it.
	if(DB_CURRENT & flags) { // TODO: Just forward DB_CURRENT?
		rc = db_cursor_current(cursor, k, NULL);
		if(rc < 0) return rc;
	} else {
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
	cursor->state = DB_WRBUF_TEMP;
	*d = (DB_val){ 1+(data ? data->size : 0), NULL }; // Prefix with deletion flag.
	assert(CURSOR_TEMP(cursor));
	rc = db_cursor_put(CURSOR_TEMP(cursor), k, d, DB_RESERVE);
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
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	if(flags) return DB_EINVAL;
	if(!cursor->temp) return DB_EACCES;
	DB_val k[1], d[1];
	int rc = db_cursor_current(cursor, k, NULL);
	if(rc < 0) return rc;
	cursor->state = DB_WRBUF_INVALID;
	char tombstone = DB_WRBUF_DEL;
	*d = (DB_val){ sizeof(tombstone), &tombstone };
	assert(CURSOR_TEMP(cursor));
	rc = db_cursor_put(CURSOR_TEMP(cursor), k, d, 0);
	if(rc < 0) return rc;
	return 0;
}

int db_wrbuf_del(DB_txn *const temp, DB_val const *const key, unsigned const flags) {
	if(!temp) return DB_EACCES;
	if(flags) return DB_EINVAL;
	char tombstone = DB_WRBUF_DEL;
	DB_val k[1] = { *key };
	DB_val d[1] = {{ sizeof(tombstone), &tombstone }};
	int rc = db_put(temp, k, d, 0);
	if(rc < 0) return rc;
	return 0;
}

DB_cursor *db_wrbuf_cursor_temp(DB_cursor *const cursor) {
	if(!cursor) return NULL;
	assert(db_base_wrbuf == cursor->isa);
	return CURSOR_TEMP(cursor);
}
DB_cursor *db_wrbuf_cursor_main(DB_cursor *const cursor) {
	if(!cursor) return NULL;
	assert(db_base_wrbuf == cursor->isa);
	return CURSOR_MAIN(cursor);
}

DB_base const db_base_wrbuf[1] = {{
	.version = 0,
	.name = "write-buffer",
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

