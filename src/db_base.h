// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#ifndef KVSTORE_DB_BASE_H
#define KVSTORE_DB_BASE_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Equivalent to MDB constants.
// More may be exposed here in the future.
#define DB_NOSYNC 0x10000

// db_txn_begin flags
#define DB_RDWR 0
#define DB_RDONLY 0x20000

// db_cursor_put flags
#define DB_NOOVERWRITE 0x10 // May be expensive for LSM-tree back-ends.
#define DB_CURRENT 0x40 // Overwrite data of current key.
#define DB_RESERVE 0x10000 // Return pointer to writable data.
#define DB_APPEND 0x20000

// Errors
#define DB_KEYEXIST (-30799)
#define DB_NOTFOUND (-30798)
//#define DB_PAGE_NOTFOUND (-30797)
#define DB_CORRUPTED (-30796)
#define DB_PANIC (-30795) // Fatal error
#define DB_VERSION_MISMATCH (-30794)
#define DB_INVALID (-30793) // Invalid file type
#define DB_MAP_FULL (-30792)
//#define DB_DBS_FULL (-30791)
#define DB_READERS_FULL (-30790)
//#define DB_TLS_FULL (-30789)
#define DB_TXN_FULL (-30788)
//#define DB_CURSOR_FULL (-30787)
//#define DB_PAGE_FULL (-30786)
//#define DB_MAP_RESIZED (-30785)
#define DB_INCOMPATIBLE (-30784)
//#define DB_BAD_RSLOT (-30783)
#define DB_BAD_TXN (-30782)
#define DB_BAD_VALSIZE (-30781)
//#define DB_BAD_DBI (-30780)
#define DB_LAST_ERRCODE DB_BAD_DBI

// Unlike MDB, these error codes are negative too.
#define DB_ENOENT (-ENOENT)
#define DB_EEXIST (-EEXIST)
#define DB_EIO (-EIO)
#define DB_ENOMEM (-ENOMEM)
#define DB_EACCES (-EACCES)
#define DB_EBUSY (-EBUSY)
#define DB_EINVAL (-EINVAL)
#define DB_ENOSPC (-ENOSPC)
#define DB_ENOTSUP (-ENOTSUP)
#define DB_ENAMETOOLONG (-ENAMETOOLONG)

// Equivalent to MDB_val.
typedef struct {
	size_t size;
	void *data;
} DB_val;

typedef struct {
	DB_val min[1];
	DB_val max[1];
} DB_range;

typedef struct DB_base DB_base;
typedef struct DB_env DB_env;
typedef struct DB_txn DB_txn;
typedef struct DB_cursor DB_cursor;

typedef int (*DB_cmp_func)(void *ctx, DB_txn *const txn, DB_val const *const a, DB_val const *const b);
typedef struct {
	DB_cmp_func fn;
	void *ctx;
} DB_cmp_data;

typedef int (*DB_cmd_func)(void *ctx, DB_txn *const txn, unsigned char const *const buf, size_t const len);
typedef struct {
	DB_cmd_func fn;
	void *ctx;
} DB_cmd_data;

typedef void (*DB_print_func)(void *ctx, DB_env *const env, char const *const format, ...);
typedef struct {
	DB_print_func fn;
	void *ctx;
} DB_print_data;

typedef int (*DB_commit_func)(void *ctx, DB_env *const env, FILE *const log);
typedef struct {
	DB_commit_func fn;
	void *ctx;
} DB_commit_data;
typedef struct {
	DB_val txn_id[1];
	FILE *log;
} DB_apply_data;

#define DB_CFG_MAPSIZE 1 // size_t *data
#define DB_CFG_COMPARE 2 // DB_cmp_data *data
#define DB_CFG_COMMAND 3 // DB_cmd_data *data
#define DB_CFG_TXNSIZE 4 // size_t *data
#define DB_CFG_LOG 5 // DB_print_data *data
#define DB_CFG_INNERDB 6 // DB_env *set (takes ownership) / DB_env **get
#define DB_CFG_COMMIT 7 // DB_commit_data *data
#define DB_CFG_APPLY 8 // DB_apply_data *data
#define DB_CFG_TXNID 9 // DB_val *data
#define DB_CFG_CONFLICTFREE 10 // int *data (as boolean)
#define DB_CFG_KEYSIZE 11 // size_t *data (might be read-only)
#define DB_CFG_FLAGS 12 // unsigned *data (DB_NOSYNC, DB_RDONLY)
#define DB_CFG_FILENAME 13 // char const *set / char const **get
#define DB_CFG_FILEMODE 14 // int *data (e.g. 0644)
#define DB_CFG_LOCKFILE 15 // char const *set / char const **get
#define DB_CFG_TEMPDB 16 // DB_env *set (takes ownership) / DB_env **get
#define DB_CFG_PREFIX 17 // DB_val *data

DB_base const *db_base_find(char const *const name);

int db_env_init_base(char const *const basename, DB_env *const env);
int db_env_create_base(char const *const basename, DB_env **const out);
int db_env_init_custom(DB_base const *const base, DB_env *const env);
int db_env_create_custom(DB_base const *const base, DB_env **const out);

size_t db_env_size(DB_base const *const base);
int db_env_init(DB_env *const env);
int db_env_create(DB_env **const out); // Convenience
int db_env_get_config(DB_env *const env, unsigned const type, void *data);
int db_env_set_config(DB_env *const env, unsigned const type, void *data);
int db_env_open0(DB_env *const env);
int db_env_open(DB_env *const env, char const *const name, unsigned const flags, int const mode); // Convenience
DB_base const *db_env_base(DB_env *const env);
void db_env_destroy(DB_env *const env);
void db_env_close(DB_env *env); // Convenience

size_t db_txn_size(DB_env *const env);
int db_txn_begin_init(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn *const txn);
int db_txn_begin(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn **const out); // Convenience
int db_txn_commit_destroy(DB_txn *const txn);
void db_txn_abort_destroy(DB_txn *const txn);
int db_txn_commit(DB_txn *txn); // Convenience
void db_txn_abort(DB_txn *txn); // Convenience
int db_txn_env(DB_txn *const txn, DB_env **const out);
int db_txn_parent(DB_txn *const txn, DB_txn **const out);
int db_txn_get_flags(DB_txn *const txn, unsigned *const flags);
int db_txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b);

// A shared cursor for cases where you just need one for one or two ops.
// Warning: Not re-entrant. If you're using this cursor, you can't call any
// other function that might also use it, including functions that call
// db_get/put. It belongs to the transaction, so don't close it when
// you're done.
int db_txn_cursor(DB_txn *const txn, DB_cursor **const out);

int db_get(DB_txn *const txn, DB_val const *const key, DB_val *const data);
int db_put(DB_txn *const txn, DB_val const *const key, DB_val *const data, unsigned const flags);
int db_del(DB_txn *const txn, DB_val const *const key, unsigned const flags); // Doesn't return DB_NOTFOUND if key doesn't exist (a flag may be added in the future).
int db_cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len); // For efficient logical replication. Must call set_cmdfn to implement.

int db_countr(DB_txn *const txn, DB_range const *const range, uint64_t *const out);
int db_delr(DB_txn *const txn, DB_range const *const range, uint64_t *const out);

// Note: Currently, you must manually close all cursors before
// committing/aborting their transactions. In the future, any cursors
// remaining open may be closed automatically.
size_t db_cursor_size(DB_txn *const txn);
int db_cursor_init(DB_txn *const txn, DB_cursor *const cursor);
int db_cursor_open(DB_txn *const txn, DB_cursor **const out); // Convenience
void db_cursor_destroy(DB_cursor *const cursor);
void db_cursor_close(DB_cursor *cursor); // Convenience
int db_cursor_clear(DB_cursor *const cursor);
int db_cursor_txn(DB_cursor *const cursor, DB_txn **const out);
int db_cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b);

int db_cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data);
int db_cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir);
int db_cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir);
int db_cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir);

int db_cursor_seekr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir);
int db_cursor_firstr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir);
int db_cursor_nextr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir);

int db_cursor_put(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags);
int db_cursor_del(DB_cursor *const cursor, unsigned const flags);

typedef enum DB_cursor_op {
	DB_GET_CURRENT,
	DB_FIRST,
	DB_LAST,
	DB_NEXT,
	DB_PREV,
	DB_SET, // Seeks preserving input key.
	DB_SET_KEY, // Seeks overwriting input key with DB copy.
	DB_SET_RANGE,
} DB_cursor_op;
static int db_cursor_get(DB_cursor *const cursor, DB_val *const key, DB_val *const data, DB_cursor_op const op) {
	int rc;
	switch(op) {
	case DB_GET_CURRENT: return db_cursor_current(cursor, key, data);
	case DB_FIRST: return db_cursor_first(cursor, key, data, +1);
	case DB_LAST: return db_cursor_first(cursor, key, data, -1);
	case DB_NEXT: return db_cursor_next(cursor, key, data, +1);
	case DB_PREV: return db_cursor_next(cursor, key, data, -1);
	case DB_SET: return db_cursor_seek(cursor, key, data, 0);
	case DB_SET_KEY:
		rc = db_cursor_seek(cursor, key, data, 0);
		if(rc < 0) return rc;
		return db_cursor_current(cursor, key, data);
	case DB_SET_RANGE: return db_cursor_seek(cursor, key, data, +1);
	default: return DB_EINVAL;
	}
}

static char const *db_strerror(int const rc) {
	switch(rc) {
	case DB_KEYEXIST: return "Database item already exists";
	case DB_NOTFOUND: return "Database item not found";
	case DB_CORRUPTED: return "Database file corrupted";
	case DB_PANIC: return "Database panic";
	case DB_VERSION_MISMATCH: return "Database version mismatch";
	case DB_INVALID: return "Invalid database file type";
	case DB_MAP_FULL: return "Database map full";
	case DB_READERS_FULL: return "Too many database readers";
	case DB_TXN_FULL: return "Database transaction full";
	case DB_INCOMPATIBLE: return "Database incompatible";
	case DB_BAD_TXN: return "Invalid database transaction";
	case DB_BAD_VALSIZE: return "Database bad value size";

	case DB_ENOENT: return "No entity";
	case DB_EEXIST: return "Already exists";
	case DB_EIO: return "IO";
	case DB_ENOMEM: return "No memory";
	case DB_EACCES: return "Access";
	case DB_EBUSY: return "Busy";
	case DB_EINVAL: return "Bad input value";
	case DB_ENOSPC: return "No space";
	case DB_ENOTSUP: return "Not supported";
	case DB_ENAMETOOLONG: return "Name too long";

	default: return NULL;
	}
}

#endif
