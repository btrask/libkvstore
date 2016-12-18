// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include "db_base.h"

// A write buffer is a pseudo-cursor that wraps two regular cursors that
// buffers writes and deletions from the main cursor to the temp cursor.

// temp cursor needs: close, current, seek, first, next, put, cmp
// main cursor needs: close, current, seek, first, next, clear

typedef enum {
	DB_WRBUF_INVALID = 0,
	DB_WRBUF_EQUAL,
	DB_WRBUF_TEMP,
	DB_WRBUF_MAIN,
} DB_wrbuf_state;

typedef struct {
	DB_wrbuf_state state;
	DB_cursor *temp;
	DB_cursor *main;
} DB_wrbuf;

int db_wrbuf_init(DB_wrbuf *const buf, DB_cursor *const temp, DB_cursor *const main);
void db_wrbuf_destroy(DB_wrbuf *const buf);
int db_wrbuf_clear(DB_wrbuf *const buf);

int db_wrbuf_current(DB_wrbuf *const buf, DB_val *const key, DB_val *const data);
int db_wrbuf_seek(DB_wrbuf *const buf, DB_val *const key, DB_val *const data, int const dir);
int db_wrbuf_first(DB_wrbuf *const buf, DB_val *const key, DB_val *const data, int const dir);
int db_wrbuf_next(DB_wrbuf *const buf, DB_val *const key, DB_val *const data, int const dir);

int db_wrbuf_put(DB_wrbuf *const buf, DB_val *const key, DB_val *const data, unsigned const flags);
int db_wrbuf_del(DB_wrbuf *const buf, unsigned const flags);

// Equivalent to db_del. Can be much faster than operating on a temporary cursor.
int db_wrbuf_del_direct(DB_txn *const temp, DB_val *const key, unsigned const flags);

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

