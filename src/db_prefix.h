// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include "db_base_internal.h"

// A prefix cursor wraps a normal cursor, transparently prefixing all keys
// written to the underlying data store, and stripping all prefixes read
// from it.

// Usage:
// 1. Initialize a fake transaction as below
// 2. Call db_cursor_init/open, casting the transaction to DB_txn

// Yes, this is kind of ugly, but it allows arbitrary nesting.

extern DB_base const db_base_prefix[1];

typedef struct {
	DB_base const *isa;
	DB_val pfx[1];
	DB_txn *txn;
} DB_prefix_txn;

