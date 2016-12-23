// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include "db_base_internal.h"

// A prefix cursor wraps a normal cursor, transparently prefixing all keys
// written to the underlying data store, and stripping all prefixes read
// from it.

extern DB_base const db_base_prefix[1];

DB_env *db_prefix_env_raw(DB_env *const env);
DB_txn *db_prefix_txn_raw(DB_txn *const txn);
DB_cursor *db_prefix_cursor_raw(DB_cursor *cursor);

