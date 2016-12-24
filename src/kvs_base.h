// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#ifndef KVSTORE_KVS_BASE_H
#define KVSTORE_KVS_BASE_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

// Equivalent to MDB constants.
// More may be exposed here in the future.
#define KVS_NOSYNC 0x10000

// kvs_txn_begin flags
#define KVS_RDWR 0
#define KVS_RDONLY 0x20000

// kvs_cursor_put flags
#define KVS_NOOVERWRITE 0x10 // May be expensive for LSM-tree back-ends.
#define KVS_CURRENT 0x40 // Overwrite data of current key.
#define KVS_RESERVE 0x10000 // Return pointer to writable data.
#define KVS_APPEND 0x20000

// Errors
#define KVS_KEYEXIST (-30799)
#define KVS_NOTFOUND (-30798)
//#define KVS_PAGE_NOTFOUND (-30797)
#define KVS_CORRUPTED (-30796)
#define KVS_PANIC (-30795) // Fatal error
#define KVS_VERSION_MISMATCH (-30794)
#define KVS_INVALID (-30793) // Invalid file type
#define KVS_MAP_FULL (-30792)
//#define KVS_DBS_FULL (-30791)
#define KVS_READERS_FULL (-30790)
//#define KVS_TLS_FULL (-30789)
#define KVS_TXN_FULL (-30788)
//#define KVS_CURSOR_FULL (-30787)
//#define KVS_PAGE_FULL (-30786)
//#define KVS_MAP_RESIZED (-30785)
#define KVS_INCOMPATIBLE (-30784)
//#define KVS_BAD_RSLOT (-30783)
#define KVS_BAD_TXN (-30782)
#define KVS_BAD_VALSIZE (-30781)
//#define KVS_BAD_DBI (-30780)
#define KVS_LAST_ERRCODE KVS_BAD_DBI

// Unlike MDB, these error codes are negative too.
#define KVS_ENOENT (-ENOENT)
#define KVS_EEXIST (-EEXIST)
#define KVS_EIO (-EIO)
#define KVS_ENOMEM (-ENOMEM)
#define KVS_EACCES (-EACCES)
#define KVS_EBUSY (-EBUSY)
#define KVS_EINVAL (-EINVAL)
#define KVS_ENOSPC (-ENOSPC)
#define KVS_ENOTSUP (-ENOTSUP)
#define KVS_ENAMETOOLONG (-ENAMETOOLONG)

// Equivalent to MDB_val.
typedef struct {
	size_t size;
	void *data;
} KVS_val;

typedef struct {
	KVS_val min[1];
	KVS_val max[1];
} KVS_range;

typedef struct KVS_base KVS_base;
typedef struct KVS_env KVS_env;
typedef struct KVS_txn KVS_txn;
typedef struct KVS_cursor KVS_cursor;

typedef int (*KVS_cmp_func)(void *ctx, KVS_txn *const txn, KVS_val const *const a, KVS_val const *const b);
typedef struct {
	KVS_cmp_func fn;
	void *ctx;
} KVS_cmp_data;

typedef int (*KVS_cmd_func)(void *ctx, KVS_txn *const txn, unsigned char const *const buf, size_t const len);
typedef struct {
	KVS_cmd_func fn;
	void *ctx;
} KVS_cmd_data;

typedef void (*KVS_print_func)(void *ctx, KVS_env *const env, char const *const format, ...);
typedef struct {
	KVS_print_func fn;
	void *ctx;
} KVS_print_data;

typedef int (*KVS_commit_func)(void *ctx, KVS_env *const env, FILE *const log);
typedef struct {
	KVS_commit_func fn;
	void *ctx;
} KVS_commit_data;
typedef struct {
	KVS_val txn_id[1];
	FILE *log;
} KVS_apply_data;

// Back-ends are free to define custom config options.
// Please choose names carefully so that equivalent options are
// likely to be reusable. If an option is highly back-end specific,
// give it a more specific name.
#define KVS_CFG_MAPSIZE "mapsize" // size_t *data
#define KVS_CFG_COMPARE "compare" // KVS_cmp_data *data
#define KVS_CFG_COMMAND "command" // KVS_cmd_data *data
#define KVS_CFG_TXNSIZE "txnsize" // size_t *data
#define KVS_CFG_LOG "log" // KVS_print_data *data
#define KVS_CFG_INNERDB "innerdb" // KVS_env *set (takes ownership) / KVS_env **get
#define KVS_CFG_COMMITHOOK "commithook" // KVS_commit_data *data
#define KVS_CFG_COMMITAPPLY "commitapply" // KVS_apply_data *data
#define KVS_CFG_TXNID "txnid" // KVS_val *data
#define KVS_CFG_CONFLICTFREE "conflictfree" // int *data (as boolean)
#define KVS_CFG_KEYSIZE "keysize" // size_t *data (might be read-only)
#define KVS_CFG_FLAGS "flags" // unsigned *data (KVS_NOSYNC, KVS_RDONLY)
#define KVS_CFG_FILENAME "filename" // char const *set / char const **get
#define KVS_CFG_FILEMODE "filemode" // int *data (e.g. 0644)
#define KVS_CFG_LOCKFILE "lockfile" // char const *set / char const **get
#define KVS_CFG_TEMPDB "tempdb" // KVS_env *set (takes ownership) / KVS_env **get
#define KVS_CFG_PREFIX "prefix" // KVS_val *data

KVS_base const *kvs_base_find(char const *const name);

int kvs_env_init_base(char const *const basename, KVS_env *const env);
int kvs_env_create_base(char const *const basename, KVS_env **const out);
int kvs_env_init_custom(KVS_base const *const base, KVS_env *const env);
int kvs_env_create_custom(KVS_base const *const base, KVS_env **const out);

size_t kvs_env_size(KVS_base const *const base);
int kvs_env_init(KVS_env *const env);
int kvs_env_create(KVS_env **const out); // Convenience
int kvs_env_get_config(KVS_env *const env, char const *const type, void *data);
int kvs_env_set_config(KVS_env *const env, char const *const type, void *data);
int kvs_env_open0(KVS_env *const env);
int kvs_env_open(KVS_env *const env, char const *const name, unsigned const flags, int const mode); // Convenience
KVS_base const *kvs_env_base(KVS_env *const env);
void kvs_env_destroy(KVS_env *const env);
void kvs_env_close(KVS_env *env); // Convenience

size_t kvs_txn_size(KVS_env *const env);
int kvs_txn_begin_init(KVS_env *const env, KVS_txn *const parent, unsigned const flags, KVS_txn *const txn);
int kvs_txn_begin(KVS_env *const env, KVS_txn *const parent, unsigned const flags, KVS_txn **const out); // Convenience
int kvs_txn_commit_destroy(KVS_txn *const txn);
void kvs_txn_abort_destroy(KVS_txn *const txn);
int kvs_txn_commit(KVS_txn *txn); // Convenience
void kvs_txn_abort(KVS_txn *txn); // Convenience
int kvs_txn_env(KVS_txn *const txn, KVS_env **const out);
int kvs_txn_parent(KVS_txn *const txn, KVS_txn **const out);
int kvs_txn_get_flags(KVS_txn *const txn, unsigned *const flags);
int kvs_txn_cmp(KVS_txn *const txn, KVS_val const *const a, KVS_val const *const b);

// A shared cursor for cases where you just need one for one or two ops.
// Warning: Not re-entrant. If you're using this cursor, you can't call any
// other function that might also use it, including functions that call
// kvs_get/put. It belongs to the transaction, so don't close it when
// you're done.
int kvs_txn_cursor(KVS_txn *const txn, KVS_cursor **const out);

int kvs_get(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data);
int kvs_put(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data, unsigned const flags);
int kvs_del(KVS_txn *const txn, KVS_val const *const key, unsigned const flags); // Doesn't return KVS_NOTFOUND if key doesn't exist (a flag may be added in the future).
int kvs_cmd(KVS_txn *const txn, unsigned char const *const buf, size_t const len); // For efficient logical replication. Must call set_cmdfn to implement.

int kvs_countr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out);
int kvs_delr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out);

// Note: Currently, you must manually close all cursors before
// committing/aborting their transactions. In the future, any cursors
// remaining open may be closed automatically.
size_t kvs_cursor_size(KVS_txn *const txn);
int kvs_cursor_init(KVS_txn *const txn, KVS_cursor *const cursor);
int kvs_cursor_open(KVS_txn *const txn, KVS_cursor **const out); // Convenience
void kvs_cursor_destroy(KVS_cursor *const cursor);
void kvs_cursor_close(KVS_cursor *cursor); // Convenience
int kvs_cursor_clear(KVS_cursor *const cursor);
int kvs_cursor_txn(KVS_cursor *const cursor, KVS_txn **const out);
int kvs_cursor_cmp(KVS_cursor *const cursor, KVS_val const *const a, KVS_val const *const b);

int kvs_cursor_current(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data);
int kvs_cursor_seek(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir);
int kvs_cursor_first(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir);
int kvs_cursor_next(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir);

int kvs_cursor_seekr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir);
int kvs_cursor_firstr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir);
int kvs_cursor_nextr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir);

int kvs_cursor_put(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, unsigned const flags);
int kvs_cursor_del(KVS_cursor *const cursor, unsigned const flags);

typedef enum KVS_cursor_op {
	KVS_GET_CURRENT,
	KVS_FIRST,
	KVS_LAST,
	KVS_NEXT,
	KVS_PREV,
	KVS_SET, // Seeks preserving input key.
	KVS_SET_KEY, // Seeks overwriting input key with DB copy.
	KVS_SET_RANGE,
} KVS_cursor_op;
static int kvs_cursor_get(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, KVS_cursor_op const op) {
	int rc;
	switch(op) {
	case KVS_GET_CURRENT: return kvs_cursor_current(cursor, key, data);
	case KVS_FIRST: return kvs_cursor_first(cursor, key, data, +1);
	case KVS_LAST: return kvs_cursor_first(cursor, key, data, -1);
	case KVS_NEXT: return kvs_cursor_next(cursor, key, data, +1);
	case KVS_PREV: return kvs_cursor_next(cursor, key, data, -1);
	case KVS_SET: return kvs_cursor_seek(cursor, key, data, 0);
	case KVS_SET_KEY:
		rc = kvs_cursor_seek(cursor, key, data, 0);
		if(rc < 0) return rc;
		return kvs_cursor_current(cursor, key, data);
	case KVS_SET_RANGE: return kvs_cursor_seek(cursor, key, data, +1);
	default: return KVS_EINVAL;
	}
}

static char const *kvs_strerror(int const rc) {
	switch(rc) {
	case KVS_KEYEXIST: return "Database item already exists";
	case KVS_NOTFOUND: return "Database item not found";
	case KVS_CORRUPTED: return "Database file corrupted";
	case KVS_PANIC: return "Database panic";
	case KVS_VERSION_MISMATCH: return "Database version mismatch";
	case KVS_INVALID: return "Invalid database file type";
	case KVS_MAP_FULL: return "Database map full";
	case KVS_READERS_FULL: return "Too many database readers";
	case KVS_TXN_FULL: return "Database transaction full";
	case KVS_INCOMPATIBLE: return "Database incompatible";
	case KVS_BAD_TXN: return "Invalid database transaction";
	case KVS_BAD_VALSIZE: return "Database bad value size";

	case KVS_ENOENT: return "No entity";
	case KVS_EEXIST: return "Already exists";
	case KVS_EIO: return "IO";
	case KVS_ENOMEM: return "No memory";
	case KVS_EACCES: return "Access";
	case KVS_EBUSY: return "Busy";
	case KVS_EINVAL: return "Bad input value";
	case KVS_ENOSPC: return "No space";
	case KVS_ENOTSUP: return "Not supported";
	case KVS_ENAMETOOLONG: return "Name too long";

	default: return NULL;
	}
}

#endif
