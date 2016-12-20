// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include "db_base_internal.h"

// A write buffer is a pseudo-cursor that wraps two regular cursors that
// buffers writes and deletions from the main cursor to the temp cursor.

// temp cursor needs: close, current, seek, first, next, put, cmp
// main cursor needs: close, current, seek, first, next, clear

extern DB_base const db_base_wrbuf[1];

typedef struct {
	DB_base const *isa;
	DB_txn *temp;
	DB_txn *main;
} DB_wrbuf_txn;

// Equivalent to db_del. Can be much faster than operating on a temporary cursor.
int db_wrbuf_del(DB_txn *const temp, DB_val const *const key, unsigned const flags);

DB_cursor *db_wrbuf_cursor_temp(DB_cursor *const cursor);
DB_cursor *db_wrbuf_cursor_main(DB_cursor *const cursor);

enum {
	DB_WRBUF_PUT = 'P',
	DB_WRBUF_DEL = 'D',
};
static char db_wrbuf_type(DB_val const *const data) {
	assert(data);
	assert(data->size >= 1);
	return ((char const *)data->data)[0];
}
static void db_wrbuf_trim(DB_val *const data) {
	if(!data) return;
	assert(DB_WRBUF_PUT == db_wrbuf_type(data));
	data->data++;
	data->size--;
}

