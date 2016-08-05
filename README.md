libkvstore
==========

A general-purpose wrapper around key-value stores.

- LMDB-style API
- Trasactional
- ACID
- Written in C
- No frills

Supported backends:

- LMDB (built-in)
- LevelDB (built-in)
- RocksDB (external)
- HyperLevelDB (external)
- lsmdb (external)

Possible future backends:

- WiredTiger
- BerkeleyDB?
- CockroachDB?
- SQLite?

To build with a given backend, use e.g. `DB=leveldb make`. You may need to `make clean` when switching. Use `make test` to test.

API
---

Please refer to the LMDB documentation for basic information.

Notable differences from LMDB's API:

- `db_cursor_current`: returns key and value at the cursor's current location.
- `db_cursor_seek`: seeks to key. Direction can be positive (`>=`), negative (`<=`), or 0 (`==`).
- `db_cursor_next`: steps forward (dir is positive) or backward (dir is negative).
- `db_cursor_first`: seeks to first (dir is positive) or last (dir is negative) element.
- DBIs are not supported, There is only a single keyspace. (Use ranges for partitioning.)
- `DUPSORT` mode is not supported. Each key can only have one value. (Suffix your keys and use ranges.)
- Many of the more specialized options are unsupported.
- `DB_NOOVERWRITE` is a large performance hit for write-optimized backends, so try to avoid it.

Known Issues
------------

- The RocksDB backend doesn't do very smart configuration (doesn't even enable bloom filters).
- The LevelDB-based backends don't support nested transactions.
- The lsmdb backend is more or less unsupported.

License: MIT

