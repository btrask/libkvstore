// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include "db_base.h"

// A prefix cursor wraps a normal cursor, transparently prefixing all keys
// written to the underlying data store, and stripping all prefixes read
// from it.

int db_prefix_cursor_init(DB_txn *const txn, DB_val const *const pfx, DB_cursor *const cursor);
int db_prefix_cursor_create(DB_txn *const txn, DB_val const *const pfx, DB_cursor **const out);

