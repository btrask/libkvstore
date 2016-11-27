libkvstore
==========

A general-purpose wrapper around key-value stores.

- LMDB-style API
- Trasactional
- ACID
- Written in C
- No frills

If you're unsure of when to use something like libkvstore:

- When you're currently using flat files but you want something easier, faster and less error-prone
- When you're currently using SQL but feel like you're fighting the query planner or dynamically generating queries
- When you want to support multiple storage engines with different tradeoffs
- When you want a transactional interface to LevelDB

libkvstore is low level enough to give you direct control over precisely how data is indexed and read, but high level enough that you can use it for general application programming without too much pain. If [SQLite is fopen](https://www.sqlite.org/whentouse.html), then libkvstore is `open(2)`.

Supported back-ends:

- [LMDB](https://symas.com/products/lightning-memory-mapped-database/) (built-in)
- [LevelDB](https://github.com/google/leveldb) (built-in)

Semi-supported back-ends:
- [RocksDB](http://rocksdb.org/) (external)
- [HyperLevelDB](https://github.com/rescrv/HyperLevelDB) (external)
- [lsmdb](https://github.com/btrask/lsmdb) (external)

Possible future back-ends:

- [WiredTiger](https://docs.mongodb.com/manual/core/wiredtiger/)
- [BerkeleyDB?](http://www.oracle.com/us/products/database/berkeley-db/index.html)
- [CockroachDB?](https://github.com/cockroachdb/cockroach)
- [SQLite?](https://www.sqlite.org/)
- [SQLite4 LSM?](https://www.sqlite.org/src4/doc/trunk/www/lsmusr.wiki)

To build with a given back-end, use e.g. `DB=leveldb make`. You may need to `make clean` when switching. Use `make test` to test.

API
---

Please refer to the [LMDB documentation](http://lmdb.tech/doc/group__mdb.html) for general information.

Notable differences from LMDB's API:

- `mdb_cursor_get` is split into several functions:
	- `db_cursor_current`: returns key and value at the cursor's current location.
	- `db_cursor_seek`: seeks to key. Direction can be positive (`>=`), negative (`<=`), or 0 (`==`).
	- `db_cursor_next`: steps forward (dir is positive) or backward (dir is negative).
	- `db_cursor_first`: seeks to first (dir is positive) or last (dir is negative) element.
	- `db_cursor_get` is still supported.
- DBIs are not supported, There is only a single keyspace. (Use ranges for partitioning.)
- `DUPSORT` mode is not supported. Each key can only have one value. (Suffix your keys and use ranges.)
- Many of the more specialized options are unsupported.
- `DB_NOOVERWRITE` is a large performance hit for write-optimized back-ends, so try to avoid it.
- Transactions have a shared cursor which can be used to avoid frequently creating and destroying cursors. Note that "shared" means "not re-entrant."
- A low level schema layer is included. It's optional and subject to change.
- Concurrent access between several processes is supported by some back-ends (LMDB) and not others (LevelDB).
- Puts with `NULL` data (rather than just empty data) are explicitly allowed.

Known Issues
------------

- The RocksDB and HyperLevelDB back-ends are currently broken.
- Custom comparators are currently unsupported in any of the included back-ends due to limitations with LMDB (which is even used in the LevelDB back-end).
- The LevelDB-based back-ends don't support nested transactions yet.
- The lsmdb back-end is more or less unsupported.
- Disk formats are not explicitly detected. If your application supports multiple back-ends, you may need to track which one is used manually.

License: MIT

