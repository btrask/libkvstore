// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <stdio.h>
#include <string.h>
#include "kvs_wrbuf.h"
#include "kvs_helper.h"
#include "common.h"

typedef enum {
	KVS_WRBUF_INVALID = 0,
	KVS_WRBUF_EQUAL,
	KVS_WRBUF_TEMP,
	KVS_WRBUF_MAIN,
} KVS_wrbuf_state;

struct KVS_cursor {
	KVS_base const *isa;
	KVS_wrbuf_state state;
	KVS_cursor *temp; // Hard to calculate and also optional
	// Main cursor
	// Temp cursor, if present
};
#define CURSOR_MAIN(c) ((c)+1)
#define CURSOR_TEMP(c) ((c)->temp)

KVS_FN size_t kvs__cursor_size(KVS_txn *const fake) {
	KVS_wrbuf_txn const *const txn = (KVS_wrbuf_txn *)fake;
	return sizeof(struct KVS_cursor)
		+ kvs_cursor_size(txn->main)
		+ (txn->temp ? kvs_cursor_size(txn->temp) : 0);
}
KVS_FN int kvs__cursor_init(KVS_txn *const fake, KVS_cursor *const cursor) {
	if(!fake) return KVS_EINVAL;
	if(!cursor) return KVS_EINVAL;
	assert_zeroed(cursor, 1);
	KVS_wrbuf_txn const *const txn = (KVS_wrbuf_txn *)fake;
	int rc = 0;
	cursor->isa = kvs_base_wrbuf;
	cursor->state = KVS_WRBUF_INVALID;
	cursor->temp = NULL;

	rc = kvs_cursor_init(txn->main, CURSOR_MAIN(cursor));
	if(rc < 0) goto cleanup;

	if(txn->temp) {
		cursor->temp = (KVS_cursor *)((char *)CURSOR_MAIN(cursor)
			+ kvs_cursor_size(txn->main));
		rc = kvs_cursor_init(txn->temp, CURSOR_TEMP(cursor));
		if(rc < 0) goto cleanup;
	}

cleanup:
	if(rc < 0) kvs_cursor_destroy(cursor);
	return rc;
}
void kvs__cursor_destroy(KVS_cursor *const cursor) {
	if(!cursor) return;
	cursor->state = KVS_WRBUF_INVALID;
	kvs_cursor_destroy(CURSOR_TEMP(cursor));
	kvs_cursor_destroy(CURSOR_MAIN(cursor));
	cursor->temp = NULL;
	cursor->isa = NULL;
	assert_zeroed(cursor, 1);
}
KVS_FN int kvs__cursor_clear(KVS_cursor *const cursor) {
	if(!cursor) return KVS_EINVAL;
	if(!cursor->temp) {
		return kvs_cursor_clear(CURSOR_MAIN(cursor));
	} else {
		cursor->state = KVS_WRBUF_INVALID;
		return 0;
	}
}
KVS_FN int kvs__cursor_txn(KVS_cursor *const cursor, KVS_txn **const out) {
	if(!cursor) return KVS_EINVAL;
	return KVS_ENOTSUP;
}
KVS_FN int kvs__cursor_cmp(KVS_cursor *const cursor, KVS_val const *const a, KVS_val const *const b) {
	assert(cursor);
	return kvs_cursor_cmp(CURSOR_MAIN(cursor), a, b);
}

static int update(KVS_cursor *const cursor, int rc1, KVS_val *const k1, KVS_val *const d1, int const rc2, KVS_val const *const k2, KVS_val const *const d2, int const dir, KVS_val *const key, KVS_val *const data) {
	if(!cursor->temp) {
		if(key) *key = *k2;
		if(data) *data = *d2;
		return rc2;
	}
	for(;;) {
		cursor->state = KVS_WRBUF_INVALID;
		if(rc1 < 0 && KVS_NOTFOUND != rc1) return rc1;
		if(rc2 < 0 && KVS_NOTFOUND != rc2) return rc2;
		if(KVS_NOTFOUND == rc1 && KVS_NOTFOUND == rc2) return KVS_NOTFOUND;

		int x = 0;
		if(KVS_NOTFOUND == rc1) x = +1;
		if(KVS_NOTFOUND == rc2) x = -1;
		if(0 == x) {
			x = kvs_cursor_cmp(CURSOR_TEMP(cursor), k1, k2) * (dir ? dir : 1);
		}
		if(x > 0) {
			cursor->state = KVS_WRBUF_MAIN;
			if(key) *key = *k2;
			if(data) *data = *d2;
			return 0;
		}
		cursor->state = 0 == x ? KVS_WRBUF_EQUAL : KVS_WRBUF_TEMP;
		char const type = kvs_wrbuf_type(d1);
		if(KVS_WRBUF_PUT == type) {
			kvs_wrbuf_trim(d1);
			if(key) *key = *k1;
			if(data) *data = *d1;
			return 0;
		}

		// The current key is a tombstone. Try to seek past it.
		assert(KVS_WRBUF_DEL == type);
		if(0 == dir) {
			cursor->state = KVS_WRBUF_INVALID;
			return KVS_NOTFOUND;
		}
		rc1 = kvs_cursor_next(CURSOR_TEMP(cursor), k1, d1, dir);
	}
}

KVS_FN int kvs__cursor_current(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data) {
	if(!cursor) return KVS_EINVAL;
	if(!cursor->temp || KVS_WRBUF_MAIN == cursor->state) {
		return kvs_cursor_current(CURSOR_MAIN(cursor), key, data);
	} else if(KVS_WRBUF_EQUAL == cursor->state || KVS_WRBUF_TEMP == cursor->state) {
		int rc = kvs_cursor_current(CURSOR_TEMP(cursor), key, data);
		if(KVS_EINVAL == rc) return KVS_NOTFOUND;
		if(rc < 0) return rc;
		if(data) {
			assert(KVS_WRBUF_DEL != kvs_wrbuf_type(data));
			kvs_wrbuf_trim(data);
		}
		return 0;
	} else if(KVS_WRBUF_INVALID == cursor->state) {
		return KVS_NOTFOUND;
	} else {
		assert(0);
		return KVS_EINVAL;
	}
}
KVS_FN int kvs__cursor_seek(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	KVS_val k1[1] = { *key }, d1[1];
	KVS_val k2[1] = { *key }, d2[1];
	int rc1 = kvs_cursor_seek(CURSOR_TEMP(cursor), k1, d1, dir);
	int rc2 = kvs_cursor_seek(CURSOR_MAIN(cursor), k2, d2, dir);
	return update(cursor, rc1, k1, d1, rc2, k2, d2, dir, dir ? key : NULL, data);
	// Note: We pass NULL for the output key to emulate MDB_SET semantics,
	// which doesn't touch the key at all and leaves it pointing to the
	// user's copy. For MDB_SET_KEY behavior, you must make an extra call
	// to kvs_cursor_current.
	// Note: This only applies when dir is 0.
}
KVS_FN int kvs__cursor_first(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	if(0 == dir) return KVS_EINVAL;
	KVS_val k1[1], d1[1], k2[1], d2[1];
	int rc1 = kvs_cursor_first(CURSOR_TEMP(cursor), k1, d1, dir);
	int rc2 = kvs_cursor_first(CURSOR_MAIN(cursor), k2, d2, dir);
	return update(cursor, rc1, k1, d1, rc2, k2, d2, dir, key, data);
}
KVS_FN int kvs__cursor_next(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	if(0 == dir) return KVS_EINVAL;
	int rc1, rc2;
	KVS_val k1[1], d1[1], k2[1], d2[1];
	if(KVS_WRBUF_MAIN != cursor->state) {
		rc1 = kvs_cursor_next(CURSOR_TEMP(cursor), k1, d1, dir);
	} else {
		rc1 = kvs_cursor_current(CURSOR_TEMP(cursor), k1, d1);
		if(KVS_EINVAL == rc1) rc1 = KVS_NOTFOUND;
	}
	if(KVS_WRBUF_TEMP != cursor->state) {
		rc2 = kvs_cursor_next(CURSOR_MAIN(cursor), k2, d2, dir);
	} else {
		rc2 = kvs_cursor_current(CURSOR_MAIN(cursor), k2, d2);
	}
	return update(cursor, rc1, k1, d1, rc2, k2, d2, dir, key, data);
}

KVS_FN int kvs__cursor_seekr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	return kvs_helper_cursor_seekr(cursor, range, key, data, dir);
}
KVS_FN int kvs__cursor_firstr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	return kvs_helper_cursor_firstr(cursor, range, key, data, dir);
}
KVS_FN int kvs__cursor_nextr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	return kvs_helper_cursor_nextr(cursor, range, key, data, dir);
}

KVS_FN int kvs__cursor_put(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	if(!key) return KVS_EINVAL;
	if(!cursor->temp) return KVS_EACCES;
	KVS_val k[1], d[1];
	int rc = 0;
	// KVS_APPEND is mostly just an optimization, so we currently
	// don't bother checking it.
	if(KVS_CURRENT & flags) { // TODO: Just forward KVS_CURRENT?
		rc = kvs_cursor_current(cursor, k, NULL);
		if(rc < 0) return rc;
	} else {
		*k = *key;
	}
	if(KVS_NOOVERWRITE & flags) {
		rc = kvs_cursor_seek(cursor, k, d, 0);
		if(rc >= 0) {
			if(data) *data = *d;
			return KVS_KEYEXIST;
		}
		if(KVS_NOTFOUND != rc) return rc;
	}
	cursor->state = KVS_WRBUF_TEMP;
	*d = (KVS_val){ 1+(data ? data->size : 0), NULL }; // Prefix with deletion flag.
	assert(CURSOR_TEMP(cursor));
	rc = kvs_cursor_put(CURSOR_TEMP(cursor), k, d, KVS_RESERVE);
	if(rc < 0) return rc;
	assert(d->data);
	memset(d->data+0, KVS_WRBUF_PUT, 1);
	if(KVS_RESERVE & flags) {
		if(data) *data = (KVS_val){ d->size-1, (char *)d->data+1 };
	} else {
		if(data && data->size > 0) memcpy(d->data+1, data->data, data->size);
	}
	return 0;
}
KVS_FN int kvs__cursor_del(KVS_cursor *const cursor, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	if(flags) return KVS_EINVAL;
	if(!cursor->temp) return KVS_EACCES;
	KVS_val k[1], d[1];
	int rc = kvs_cursor_current(cursor, k, NULL);
	if(rc < 0) return rc;
	cursor->state = KVS_WRBUF_INVALID;
	char tombstone = KVS_WRBUF_DEL;
	*d = (KVS_val){ sizeof(tombstone), &tombstone };
	assert(CURSOR_TEMP(cursor));
	rc = kvs_cursor_put(CURSOR_TEMP(cursor), k, d, 0);
	if(rc < 0) return rc;
	return 0;
}

int kvs_wrbuf_del(KVS_txn *const temp, KVS_val const *const key, unsigned const flags) {
	if(!temp) return KVS_EACCES;
	if(flags) return KVS_EINVAL;
	char tombstone = KVS_WRBUF_DEL;
	KVS_val k[1] = { *key };
	KVS_val d[1] = {{ sizeof(tombstone), &tombstone }};
	int rc = kvs_put(temp, k, d, 0);
	if(rc < 0) return rc;
	return 0;
}

KVS_cursor *kvs_wrbuf_cursor_temp(KVS_cursor *const cursor) {
	if(!cursor) return NULL;
	assert(kvs_base_wrbuf == cursor->isa);
	return CURSOR_TEMP(cursor);
}
KVS_cursor *kvs_wrbuf_cursor_main(KVS_cursor *const cursor) {
	if(!cursor) return NULL;
	assert(kvs_base_wrbuf == cursor->isa);
	return CURSOR_MAIN(cursor);
}

KVS_base const kvs_base_wrbuf[1] = {{
	.version = 0,
	.name = "write-buffer",
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

