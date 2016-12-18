// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

// This is obviously a very basic RocksDB back-end.
// A second, more "native" back-end might be added in the future.

#define LEVELDB_AS_ROCKSDB
#include "db_base_leveldb.c"

