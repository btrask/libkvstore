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

API
---

Please refer to the LMDB documentation for basic information.

Notable differences from LMDB's API:

- `mdb_cursor_get` is replaced with `db_cursor_current`, `db_cursor_seek`, `db_cursor_first`, and `db_cursor_next`. First and next take directions that can be positive (forward) or negative (backward). Seek takes a direction that can be positive (`>=`), negative (`<=`), or 0 (`==`).
- DBIs are not supported, There is only a single keyspace. (Use ranges for partitioning.)
- `DUPSORT` mode is not supported. Each key can only have one value. (Use longer, distinct keys and ranges.)
- Many of the more specialized options are unsupported.
- `DB_NOOVERWRITE` is a large performance hit for write-optimized backends, so try to avoid it.

License: MIT

