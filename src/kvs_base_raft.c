// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

#include <raft.h>

#include "kvs_base_custom.h"
#include "common.h"

enum {
	PFX_META = 'R',
};
enum {
	META_VOTED = 'V',
	META_TERM = 'T',
};

struct KVS_env {
	KVS_base const *isa;
	pthread_mutex_t mutex[1];
	pthread_cond_t cond[1];
	raft_server_t *raft;
	// Inner env
};
struct KVS_txn {
	KVS_base const *isa;
	KVS_env *env;
	KVS_txn *parent;
	KVS_txn *child;
	KVS_cursor *cursor;
	// Inner txn
};
struct KVS_cursor {
	KVS_base const *isa;
	KVS_txn *txn;
	// Inner cursor
};
#define ENV_INNER(env) ((env)+1)
#define TXN_INNER(txn) ((txn)+1)
#define CURSOR_INNER(cursor) ((cursor)+1)

static int err(int x) {
	if(x < 0) return -errno;
	return x;
}
static int initialize(KVS_env *const env) {
	assert(env);
	KVS_env *const env = user_data;
	KSV_env *raw = NULL;
	KVS_txn *txn = NULL;
	int rc = ksv_env_get_config(env, KSV_CFG_INNERDB, &raw);
	if(rc < 0) goto cleanup;
	rc = kvs_txn_begin(raw, NULL, DB_RDONLY, &txn);
	if(rc < 0) goto cleanup;


	for(;;) {
		raft_entry_t entry = {
		
		};
		raft_append_entry(env->raft, &entry);
	}

	raft_vote_for_nodeid(env->raft, 0); // TODO
	raft_set_current_term(env->raft, 0); // TODO

/*	unsigned char k[2] = { PFX_META, META_VOTED };
	unsigned char v[4];
	v[3] = (node >>  0) & 0xff;
	v[2] = (node >>  8) & 0xff;
	v[1] = (node >> 16) & 0xff;
	v[0] = (node >> 24) & 0xff;
	KVS_val key = { sizeof(k), k };
	KVS_val val = { sizeof(v), v };
	rc = kvs_put(txn, &key, &val, 0);
	if(rc < 0) goto cleanup;*/

	rc = kvs_txn_commit(txn); txn = NULL;
	if(rc < 0) goto cleanup;
cleanup:
	kvs_txn_abort(txn); txn = NULL;
	raw = NULL;
	return rc;
}
static int commithook(void *ctx, KVS_env *const env, FILE *const log) {
	bool locked = false;
	long len = 0;
	unsigned char *buf = NULL;
	int rc = 0;

	rc = err(fseek(log, 0, SEEK_END));
	if(rc < 0) goto cleanup;
	len = ftell(log);
	if(len < 0) {
		rc = KVS_EIO;
		goto cleanup;
	}
	buf = malloc(len+1);
	if(!buf) {
		rc = KVS_ENOMEM;
		goto cleanup;
	}
	rc = err(fseek(log, 0, SEEK_SET));
	if(rc < 0) goto cleanup;
	// TODO


	pthread_mutex_lock(env->mutex); locked = true;
	if(raft_is_leader(env->raft)) {
		raft_entry_t entry = {
			.term = raft_get_current_term(env->raft),
			.id = rand(), // TODO
			.type = RAFT_LOGTYPE_NORMAL,
			.data = { buf, len },
		};
		msg_entry_response_t response[1];
		rc = raft_recv_entry(env->raft, &entry, response);
		if(0 != rc) {
			rc = KVS_PANIC;
			goto cleanup;
		}

		for(;;) {
			pthread_cond_wait(env->cond, env->mutex);
			rc = raft_msg_entry_response_committed(env->raft, response);
			if(0 == rc) continue;
			else if(1 == rc) rc = 0;
			else if(-1 == rc) rc = KVS_BAD_TXN; // "Retry"
			else rc = KVS_PANIC;
			goto cleanup;
		}
	} else {
		for(;;) {
			raft_entry_t entry = {
				.term = raft_get_current_term(env->raft),
				.id = rand(), // TODO
				.type = RAFT_LOGTYPE_NORMAL,
				.data = { buf, len },
			};
			raft_node_t *leader = raft_get_current_leader_node(env->raft);
			void *x = raft_node_get_udata(leader);
			pthread_mutex_unlock(env->mutex); locked = false;
			// TODO: send log to leader
			UNUSED(entry);
			UNUSED(x);
			pthread_mutex_lock(env->mutex); locked = true;
		}
	}

cleanup:
	if(locked) {
		pthread_mutex_unlock(env->mutex); locked = false;
	}
	free(buf); buf = NULL;
	return rc;
}

static int send_requestvote(raft_server_t *raft, void *user_data, raft_node_t  *node, msg_requestvote_t *msg) {
	KVS_env *const env = user_data;
	UNUSED(env); // TODO
	return 0;
}
static int send_appendentries(raft_server_t *raft, void *user_data, raft_node_t *node, msg_appendentries_t *msg) {
	KVS_env *const env = user_data;

	// TODO: is this even right?
//	e = raft_recv_appendentries_response(env->raft, conn->node, &m.aer);
	pthread_cond_broadcast(env->cond);
	UNUSED(env);

	return 0;
}

static int applylog(raft_server_t *raft, void *user_data, raft_entry_t *entry, int entry_idx) {
	KVS_env *const env = user_data;
	FILE *log = fmemopen(entry->data.buf, entry->data.len, "rb");
	if(!log) return RAFT_ERR_SHUTDOWN;
	KVS_apply_data data = {
		.txn_id = {{ 0, NULL }},
		.log = log,
	};
	int rc = kvs_env_set_config(env, KVS_CFG_COMMITAPPLY, &data);
	if(rc < 0) return RAFT_ERR_SHUTDOWN;
	return 0;
}

static int persist_vote(raft_server_t *raft, void *user_data, int node) {
	KVS_env *const env = user_data;
	KSV_env *raw = NULL;
	KVS_txn *txn = NULL;
	int rc = ksv_env_get_config(env, KSV_CFG_INNERDB, &raw);
	if(rc < 0) goto cleanup;
	rc = kvs_txn_begin(raw, NULL, DB_RDWR, &txn);
	if(rc < 0) goto cleanup;

	unsigned char k[2] = { PFX_META, META_VOTED };
	unsigned char v[4];
	v[3] = (node >>  0) & 0xff;
	v[2] = (node >>  8) & 0xff;
	v[1] = (node >> 16) & 0xff;
	v[0] = (node >> 24) & 0xff;
	KVS_val key = { sizeof(k), k };
	KVS_val val = { sizeof(v), v };
	rc = kvs_put(txn, &key, &val, 0);
	if(rc < 0) goto cleanup;

	rc = kvs_txn_commit(txn); txn = NULL;
	if(rc < 0) goto cleanup;
cleanup:
	kvs_txn_abort(txn); txn = NULL;
	raw = NULL;
	if(rc < 0) return RAFT_ERR_SHUTDOWN;
	return 0;
}
static int persist_term(raft_server_t *raft, void *user_data, int node) {
	KVS_env *const env = user_data;
	UNUSED(env); // TODO
	return 0;
}
static int log_offer(raft_server_t *raft, void *user_data, raft_entry_t *entry, int entry_idx) {
	KVS_env *const env = user_data;
	UNUSED(env); // TODO
	return 0;
}
static int log_pop(raft_server_t *raft, void *user_data, raft_entry_t *entry, int entry_idx) {
	KVS_env *const env = user_data;
	UNUSED(env); // TODO
	return 0;
}
static int node_has_sufficient_logs(raft_server_t *raft, void *user_data, raft_node_t *node) {
	KVS_env *const env = user_data;
	UNUSED(env); // TODO
	return 0;
}

KVS_FN size_t kvs__env_size(void) {
	return sizeof(struct KVS_env)+kvs_env_size(kvs_base_distributed);
}
KVS_FN int kvs__env_init(KVS_env *const env) {
	if(!env) return KVS_EINVAL;
	int rc = 0;
	env->isa = kvs_base_raft;

	env->raft = raft_new();
	if(!env->raft) {
		rc = KVS_ENOMEM;
		goto cleanup;
	}
	raft_cbs_t cbs = {
		.send_requestvote = send_requestvote,
		.send_appendentries = send_appendentries,
		.applylog = applylog,
		.persist_vote = persist_vote,
		.persist_term = persist_term,
		.log_offer = log_offer,
		.log_pop = log_pop,
		.node_has_sufficient_logs = node_has_sufficient_logs,
	};
	raft_set_callbacks(env->raft, &cbs, env);
	rc = initialize(env);
	if(rc < 0) goto cleanup;

	rc = kvs_env_init_custom(kvs_base_distributed, ENV_INNER(env));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) kvs_env_destroy(env);
	return 0;
}
KVS_FN int kvs__env_get_config(KVS_env *const env, char const *const type, void *data) {
	if(!env) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	return kvs_env_get_config(ENV_INNER(env), type, data);
}
KVS_FN int kvs__env_set_config(KVS_env *const env, char const *const type, void *data) {
	if(!env) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	return kvs_env_set_config(ENV_INNER(env), type, data);
}
KVS_FN int kvs__env_open0(KVS_env *const env) {
	if(!env) return KVS_EINVAL;
	return kvs_env_open0(ENV_INNER(env));
}
KVS_FN void kvs__env_destroy(KVS_env *const env) {
	if(!env) return;
	kvs_env_destroy(ENV_INNER(env));
	if(env->raft) {
		raft_free(env->raft); env->raft = NULL;
	}
	env->isa = NULL;
	assert_zeroed(env, 1);
}

KVS_FN size_t kvs__txn_size(KVS_env *const env) {
	assert(env);
	return sizeof(struct KVS_txn)+kvs_txn_size(ENV_INNER(env));
}
KVS_FN int kvs__txn_begin_init(KVS_env *const env, KVS_txn *const parent, unsigned const flags, KVS_txn *const txn) {
	if(!env) return KVS_EINVAL;
	if(!txn) return KVS_EINVAL;
	if(parent && parent->child) return KVS_BAD_TXN;
	assert_zeroed(txn, 1);
	int rc = 0;
	txn->isa = kvs_base_raft;
	txn->env = env;
	txn->parent = parent;
	txn->child = NULL;

	rc = kvs_txn_begin_init(ENV_INNER(env), parent ? TXN_INNER(parent) : NULL, flags, TXN_INNER(txn));
	if(rc < 0) goto cleanup;

	if(parent) parent->child = txn;
cleanup:
	if(rc < 0) kvs_txn_abort_destroy(txn);
	return rc;
}
KVS_FN int kvs__txn_commit_destroy(KVS_txn *const txn) {
	if(!txn) return KVS_EINVAL;
	int rc = 0;
	if(txn->child) {
		rc = kvs_txn_commit(txn->child); txn->child = NULL;
		if(rc < 0) goto cleanup;
	}
	kvs_cursor_close(txn->cursor); txn->cursor = NULL;
	rc = kvs_txn_commit_destroy(TXN_INNER(txn));
	if(rc < 0) goto cleanup;
cleanup:
	kvs_txn_abort_destroy(txn);
	return rc;
}
KVS_FN void kvs__txn_abort_destroy(KVS_txn *const txn) {
	if(!txn) return;
	if(txn->child) {
		kvs_txn_abort(txn->child); txn->child = NULL;
	}
	kvs_cursor_close(txn->cursor); txn->cursor = NULL;
	kvs_txn_abort_destroy(TXN_INNER(txn));
	if(txn->parent) txn->parent->child = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->isa = NULL;
	assert_zeroed(txn, 1);
}
KVS_FN int kvs__txn_env(KVS_txn *const txn, KVS_env **const out) {
	if(!txn) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	*out = txn->env;
	return 0;
}
KVS_FN int kvs__txn_parent(KVS_txn *const txn, KVS_txn **const out) {
	if(!txn) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	*out = txn->parent;
	return 0;
}
KVS_FN int kvs__txn_get_flags(KVS_txn *const txn, unsigned *const flags) {
	if(!txn) return KVS_EINVAL;
	return kvs_txn_get_flags(TXN_INNER(txn), flags);
}
KVS_FN int kvs__txn_cmp(KVS_txn *const txn, KVS_val const *const a, KVS_val const *const b) {
	assert(txn);
	return kvs_txn_cmp(TXN_INNER(txn), a, b);
}
KVS_FN int kvs__txn_cursor(KVS_txn *const txn, KVS_cursor **const out) {
	if(!txn) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	if(!txn->cursor) {
		int rc = kvs_cursor_open(txn, &txn->cursor);
		if(rc < 0) return rc;
	}
	*out = txn->cursor;
	return 0;
}

KVS_FN int kvs__get(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data) {
	return kvs_helper_get(txn, key, data);
}
KVS_FN int kvs__put(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data, unsigned const flags) {
	return kvs_helper_put(txn, key, data, flags);
}
KVS_FN int kvs__del(KVS_txn *const txn, KVS_val const *const key, unsigned const flags) {
	if(!txn) return KVS_EINVAL;
	return kvs_helper_del(TXN_INNER(txn), key, flags);
}
KVS_FN int kvs__cmd(KVS_txn *const txn, unsigned char const *const buf, size_t const len) {
	return kvs_helper_cmd(txn, buf, len);
}

KVS_FN int kvs__countr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	return kvs_helper_countr(txn, range, out);
}
KVS_FN int kvs__delr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	return kvs_helper_delr(txn, range, out);
}

KVS_FN size_t kvs__cursor_size(KVS_txn *const txn) {
	assert(txn);
	return sizeof(struct KVS_cursor)+kvs_cursor_size(TXN_INNER(txn));
}
KVS_FN int kvs__cursor_init(KVS_txn *const txn, KVS_cursor *const cursor) {
	if(!txn) return KVS_EINVAL;
	if(!cursor) return KVS_EINVAL;
	assert_zeroed(cursor, 1);
	int rc = 0;
	cursor->isa = kvs_base_raft;
	cursor->txn = txn;

	rc = kvs_cursor_init(TXN_INNER(txn), CURSOR_INNER(cursor));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) kvs_cursor_destroy(cursor);
	return rc;
}
KVS_FN void kvs__cursor_destroy(KVS_cursor *const cursor) {
	if(!cursor) return;
	kvs_cursor_destroy(CURSOR_INNER(cursor));
	cursor->txn = NULL;
	cursor->isa = NULL;
	assert_zeroed(cursor, 1);
}
KVS_FN int kvs__cursor_clear(KVS_cursor *const cursor) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_clear(CURSOR_INNER(cursor));
}
KVS_FN int kvs__cursor_txn(KVS_cursor *const cursor, KVS_txn **const out) {
	if(!cursor) return KVS_EINVAL;
	if(!out) return KVS_EINVAL;
	*out = cursor->txn;
	return 0;
}
KVS_FN int kvs__cursor_cmp(KVS_cursor *const cursor, KVS_val const *const a, KVS_val const *const b) {
	assert(cursor);
	return kvs_cursor_cmp(CURSOR_INNER(cursor), a, b);
}

KVS_FN int kvs__cursor_current(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_current(CURSOR_INNER(cursor), key, data);
}
KVS_FN int kvs__cursor_seek(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_seek(CURSOR_INNER(cursor), key, data, dir);
}
KVS_FN int kvs__cursor_first(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_first(CURSOR_INNER(cursor), key, data, dir);
}
KVS_FN int kvs__cursor_next(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_next(CURSOR_INNER(cursor), key, data, dir);
}

KVS_FN int kvs__cursor_seekr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	return kvs_helper_cursor_seekr(cursor, range, key, data, dir);
}
KVS_FN int kvs__cursor_firstr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	return kvs_helper_cursor_firstr(cursor, range, key, data, dir);
}
KVS_FN int kvs__cursor_nextr(KVS_cursor *const cursor, KVS_range const *const range, KVS_val *const key, KVS_val *const data, int const dir) {
	return kvs_helper_cursor_nextr(cursor, range, key, data, dir);
}

KVS_FN int kvs__cursor_put(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	return kvs_cursor_put(CURSOR_INNER(cursor), key, data, flags);
}
KVS_FN int kvs__cursor_del(KVS_cursor *const cursor, unsigned const flags) {
	return kvs_helper_cursor_del(cursor, flags);
}

KVS_BASE_V0(raft)

