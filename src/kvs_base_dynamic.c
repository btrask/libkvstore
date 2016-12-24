// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "kvs_base_custom.h"

KVS_base const *const kvs_base_default = (KVS_BASE_DEFAULT);

struct KVS_env {
	KVS_base const *isa;
};
struct KVS_txn {
	KVS_base const *isa;
};
struct KVS_cursor {
	KVS_base const *isa;
};

KVS_base const *kvs_base_find(char const *const name) {
	if(!name) return kvs_base_default;
	if(0 == strcmp(name, "default")) return kvs_base_default;
#ifdef KVS_BASE_MDB
	if(0 == strcmp(name, "mdb")) return kvs_base_mdb;
#endif
#ifdef KVS_BASE_LEVELDB
	if(0 == strcmp(name, "leveldb")) return kvs_base_leveldb;
#endif
#ifdef KVS_BASE_ROCKSDB
	if(0 == strcmp(name, "rocksdb")) return kvs_base_rocksdb;
#endif
#ifdef KVS_BASE_HYPER
//	if(0 == strcmp(name, "hyper")) return kvs_base_hyper;
#endif
#ifdef KVS_BASE_LSMDB
	if(0 == strcmp(name, "lsmdb")) return kvs_base_lsmdb;
#endif
#ifdef KVS_BASE_DEBUG
	if(0 == strcmp(name, "debug")) return kvs_base_debug;
#endif
#ifdef KVS_BASE_DISTRIBUTED
	if(0 == strcmp(name, "distributed")) return kvs_base_distributed;
#endif
#ifdef KVS_BASE_DUMMY
	if(0 == strcmp(name, "dummy")) return kvs_base_dummy;
#endif
	return NULL;
}

int kvs_env_init_base(char const *const basename, KVS_env *const env) {
	return kvs_env_init_custom(kvs_base_find(basename), env);
}
int kvs_env_create_base(char const *const basename, KVS_env **const out) {
	return kvs_env_create_custom(kvs_base_find(basename), out);
}
int kvs_env_init_custom(KVS_base const *const base, KVS_env *const env) {
	if(!base || !base->env_init) return KVS_EINVAL;
	int rc = base->env_init(env);
	if(rc < 0) return rc;
	assert(env->isa);

	// Set standard settings to ensure as much uniformity as possible.
	unsigned flags = 0; // Synchronous, read-write
	int mode = 0600;
	kvs_env_set_config(env, KVS_CFG_FLAGS, &flags);
	kvs_env_set_config(env, KVS_CFG_FILEMODE, &mode);
	return 0;
}
int kvs_env_create_custom(KVS_base const *const base, KVS_env **const out) {
	if(!base) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	KVS_env *env = calloc(1, kvs_env_size(base));
	if(!env) return KVS_ENOMEM;
	int rc = kvs_env_init_custom(base, env);
	if(rc < 0) return rc;
	*out = env; env = NULL;
	return 0;
}

size_t kvs_env_size(KVS_base const *const base) {
	assert(base);
	return base->env_size();
}
int kvs_env_init(KVS_env *const env) {
	if(!kvs_base_default) return KVS_PANIC;
	return kvs_env_init_custom(kvs_base_default, env);
}
int kvs_env_create(KVS_env **const out) {
	if(!kvs_base_default) return KVS_PANIC;
	return kvs_env_create_custom(kvs_base_default, out);
}
int kvs_env_get_config(KVS_env *const env, char const *const type, void *data) {
	if(!env || !env->isa) return KVS_EINVAL;
	return env->isa->env_get_config(env, type, data);
}
int kvs_env_set_config(KVS_env *const env, char const *const type, void *data) {
	if(!env || !env->isa) return KVS_EINVAL;
	return env->isa->env_set_config(env, type, data);
}
int kvs_env_open0(KVS_env *const env) {
	if(!env || !env->isa) return KVS_EINVAL;
	return env->isa->env_open0(env);
}
int kvs_env_open(KVS_env *const env, char const *const name, unsigned flags, int mode) {
	if(!env || !env->isa) return KVS_EINVAL;
	kvs_env_set_config(env, KVS_CFG_FILENAME, (char *)name);
	kvs_env_set_config(env, KVS_CFG_FLAGS, &flags);
	kvs_env_set_config(env, KVS_CFG_FILEMODE, &mode);
	return kvs_env_open0(env);
}
KVS_base const *kvs_env_base(KVS_env *const env) {
	if(!env) return NULL;
	return env->isa;
}
void kvs_env_destroy(KVS_env *const env) {
	if(!env || !env->isa) return;
	env->isa->env_destroy(env);
	env->isa = NULL;
}
void kvs_env_close(KVS_env *env) {
	if(!env || !env->isa) return;
	kvs_env_destroy(env);
	free(env); env = NULL;
}

size_t kvs_txn_size(KVS_env *const env) {
	assert(env);
	return env->isa->txn_size(env);
}
int kvs_txn_begin_init(KVS_env *const env, KVS_txn *const parent, unsigned const flags, KVS_txn *const txn) {
	if(!env || !env->isa) return KVS_EINVAL;
	int rc = env->isa->txn_begin_init(env, parent, flags, txn);
	if(rc < 0) return rc;
	assert(txn->isa);
	return 0;
}
int kvs_txn_begin(KVS_env *const env, KVS_txn *const parent, unsigned const flags, KVS_txn **const out) {
	KVS_txn *txn = calloc(1, kvs_txn_size(env));
	if(!txn) return KVS_ENOMEM;
	int rc = kvs_txn_begin_init(env, parent, flags, txn);
	if(rc < 0) goto cleanup;
	*out = txn; txn = NULL;
cleanup:
	free(txn); txn = NULL;
	return rc;
}
int kvs_txn_commit_destroy(KVS_txn *const txn) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	int rc = txn->isa->txn_commit_destroy(txn);
	txn->isa = NULL;
	return rc;
}
int kvs_txn_commit(KVS_txn *txn) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	int rc = kvs_txn_commit_destroy(txn);
	free(txn); txn = NULL;
	return rc;
}
void kvs_txn_abort_destroy(KVS_txn *const txn) {
	if(!txn || !txn->isa) return;
	txn->isa->txn_abort_destroy(txn);
	txn->isa = NULL;
}
void kvs_txn_abort(KVS_txn *txn) {
	if(!txn || !txn->isa) return;
	kvs_txn_abort_destroy(txn);
	free(txn); txn = NULL;
}
int kvs_txn_env(KVS_txn *const txn, KVS_env **const out) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	return txn->isa->txn_env(txn, out);
}
int kvs_txn_parent(KVS_txn *const txn, KVS_txn **const out) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	return txn->isa->txn_parent(txn, out);
}
int kvs_txn_get_flags(KVS_txn *const txn, unsigned *const flags) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	return txn->isa->txn_get_flags(txn, flags);
}
int kvs_txn_cmp(KVS_txn *const txn, KVS_val const *const a, KVS_val const *const b) {
	assert(txn); // Can't return errors.
	return txn->isa->txn_cmp(txn, a, b);
}
int kvs_txn_cursor(KVS_txn *const txn, KVS_cursor **const out) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	return txn->isa->txn_cursor(txn, out);
}

int kvs_get(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	return txn->isa->get(txn, key, data);
}
int kvs_put(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data, unsigned const flags) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	return txn->isa->put(txn, key, data, flags);
}
int kvs_del(KVS_txn *const txn, KVS_val const *const key, unsigned const flags) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	return txn->isa->del(txn, key, flags);
}
int kvs_cmd(KVS_txn *const txn, unsigned char const *const buf, size_t const len) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	int rc = txn->isa->cmd(txn, buf, len);
	assert(txn->isa); // Simple check that the transaction wasn't committed or aborted.
	return rc;
}

int kvs_countr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	return txn->isa->countr(txn, range, out);
}
int kvs_delr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	return txn->isa->delr(txn, range, out);
}

size_t kvs_cursor_size(KVS_txn *const txn) {
	assert(txn);
	return txn->isa->cursor_size(txn);
}
int kvs_cursor_init(KVS_txn *const txn, KVS_cursor *const cursor) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	int rc = txn->isa->cursor_init(txn, cursor);
	if(rc < 0) return rc;
	assert(cursor->isa);
	return 0;
}
int kvs_cursor_open(KVS_txn *const txn, KVS_cursor **const out) {
	if(!txn || !txn->isa) return KVS_EINVAL;
	KVS_cursor *cursor = calloc(1, kvs_cursor_size(txn));
	if(!cursor) return KVS_ENOMEM;
	int rc = kvs_cursor_init(txn, cursor);
	if(rc < 0) goto cleanup;
	*out = cursor; cursor = NULL;
cleanup:
	free(cursor); cursor = NULL;
	return rc;
}
void kvs_cursor_destroy(KVS_cursor *const cursor) {
	if(!cursor || !cursor->isa) return;
	cursor->isa->cursor_destroy(cursor);
	cursor->isa = NULL;
}
void kvs_cursor_close(KVS_cursor *cursor) {
	if(!cursor || !cursor->isa) return;
	kvs_cursor_destroy(cursor);
	free(cursor); cursor = NULL;
}
int kvs_cursor_clear(KVS_cursor *const cursor) {
	if(!cursor || !cursor->isa) return KVS_EINVAL;
	return cursor->isa->cursor_clear(cursor);
}
int kvs_cursor_txn(KVS_cursor *const cursor, KVS_txn **const out) {
	if(!cursor || !cursor->isa) return KVS_EINVAL;
	return cursor->isa->cursor_txn(cursor, out);
}
int kvs_cursor_cmp(KVS_cursor *const cursor, KVS_val const *const a, KVS_val const *const b) {
	assert(cursor); // Can't return errors.
	return cursor->isa->cursor_cmp(cursor, a, b);
}

int kvs_cursor_current(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data) {
	if(!cursor || !cursor->isa) return KVS_EINVAL;
	return cursor->isa->cursor_current(cursor, key, data);
}
int kvs_cursor_seek(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor || !cursor->isa) return KVS_EINVAL;
	return cursor->isa->cursor_seek(cursor, key, data, dir);
}
int kvs_cursor_first(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor || !cursor->isa) return KVS_EINVAL;
	return cursor->isa->cursor_first(cursor, key, data, dir);
}
int kvs_cursor_next(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor || !cursor->isa) return KVS_EINVAL;
	return cursor->isa->cursor_next(cursor, key, data, dir);
}

int kvs_cursor_seekr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor || !cursor->isa) return KVS_EINVAL;
	return cursor->isa->cursor_seekr(cursor, range, key, data, dir);
}
int kvs_cursor_firstr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor || !cursor->isa) return KVS_EINVAL;
	return cursor->isa->cursor_firstr(cursor, range, key, data, dir);
}
int kvs_cursor_nextr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor || !cursor->isa) return KVS_EINVAL;
	return cursor->isa->cursor_nextr(cursor, range, key, data, dir);
}

int kvs_cursor_put(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, unsigned const flags) {
	if(!cursor || !cursor->isa) return KVS_EINVAL;
	return cursor->isa->cursor_put(cursor, key, data, flags);
}
int kvs_cursor_del(KVS_cursor *const cursor, unsigned const flags) {
	if(!cursor || !cursor->isa) return KVS_EINVAL;
	return cursor->isa->cursor_del(cursor, flags);
}

