// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include "db_base_internal.h"

// A write buffer is a pseudo-cursor that wraps two regular cursors that
// buffers writes and deletions from the main cursor to the temp cursor.

// temp cursor needs: close, current, seek, first, next, put, cmp
// main cursor needs: close, current, seek, first, next, clear

extern KVS_base const kvs_base_wrbuf[1];

typedef struct {
	KVS_base const *isa;
	KVS_txn *temp;
	KVS_txn *main;
} KVS_wrbuf_txn;

// Equivalent to kvs_del. Can be much faster than operating on a temporary cursor.
int kvs_wrbuf_del(KVS_txn *const temp, KVS_val const *const key, unsigned const flags);

KVS_cursor *kvs_wrbuf_cursor_temp(KVS_cursor *const cursor);
KVS_cursor *kvs_wrbuf_cursor_main(KVS_cursor *const cursor);

enum {
	KVS_WRBUF_PUT = 'P',
	KVS_WRBUF_DEL = 'D',
};
static char kvs_wrbuf_type(KVS_val const *const data) {
	assert(data);
	assert(data->size >= 1);
	return ((char const *)data->data)[0];
}
static void kvs_wrbuf_trim(KVS_val *const data) {
	if(!data) return;
	assert(KVS_WRBUF_PUT == kvs_wrbuf_type(data));
	data->data++;
	data->size--;
}

