// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "liblmdb/lmdb.h"
#include "kvs_helper.h"
#include "common.h"

#define KVS_PATH_MAX (1023+1)

#define TXNID_MAX 256
#define KEY_MAX 510
#define VAL_MAX (1024*1024*1)
#define CMD_MAX (1024*1024*1)

enum {
	PFX_META = 'M',
	PFX_DATA = 0x00, // For compressability
};
enum {
	META_TXNID = 'I',
};

typedef enum {
	MODE_RDONLY = '-',
	MODE_RECORDING = 'R',
	MODE_COMMAND = 'C',
	MODE_APPLY = 'A',
} MODE;

struct KVS_env {
	KVS_base const *isa;
	KVS_env *sub;
	KVS_commit_data commit[1];
	char *logpath;
	bool conflict_free;
};
struct KVS_txn {
	KVS_base const *isa;
	KVS_helper_txn helper[1];
	MODE mode;
	FILE *log;
	long length;
	// Inner txn
};
struct KVS_cursor {
	KVS_base const *isa;
	KVS_txn *txn;
	bool has_reserve;
	// Inner cursor
};
#define TXN_INNER(txn) ((txn)+1)
#define CURSOR_INNER(c) ((c)+1)

static int put_cr(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const val, unsigned const flags, bool const conflict_free) {
	unsigned xflags = conflict_free ? KVS_NOOVERWRITE : 0;
	KVS_val const wr = val ? *val : (KVS_val){ 0, NULL };
	KVS_val rd = wr; // Even if val is null, we need to check.
	int rc = kvs_cursor_put(cursor, key, &rd, flags | xflags);
	if(val) *val = rd;
	if(conflict_free && KVS_KEYEXIST == rc) {
		// In conflict free (unordered) mode, we can't overwrite values.
		// However, if the new value is the same, that's OK.
		if(wr.size != rd.size) return rc;
		if(KVS_RESERVE & flags) return KVS_ENOTSUP; // TODO
		int x = kvs_cursor_cmp(cursor, &wr, &rd);
		if(0 == x) rc = 0;
	}
	return rc;
}
static void reserve_finish(KVS_cursor *const cursor) {
	if(!cursor) return;
	if(!cursor->has_reserve) return;
	KVS_val key[1], val[1];
	size_t len;
	int rc = kvs_cursor_current(CURSOR_INNER(cursor), key, val);
	assert(rc >= 0);
	KVS_txn *const txn = cursor->txn;
	if(MODE_RECORDING == txn->mode) {
		rc = fprintf(txn->log, "\nP:%llu;%llu;",
			(unsigned long long)key->size,
			(unsigned long long)val->size);
		if(rc < 0) goto cleanup;
		len = fwrite(key->data, 1, key->size, txn->log);
		if(len < key->size) rc = KVS_EIO;
		if(rc < 0) goto cleanup;
		len = fwrite(val->data, 1, val->size, txn->log);
		if(len < val->size) rc = KVS_EIO;
		if(rc < 0) goto cleanup;
		txn->length = ftell(txn->log);
		assert(txn->length >= 0);
	}
cleanup:
	assert(rc >= 0);
	// Note: Errors are hard to deal with correctly in this case.
	// We could try "reserving" space in the log, and then going
	// back and overwriting it, but that wouldn't necessarily be
	// any less error-prone.
	cursor->has_reserve = false;
}

static int err(int x) {
	if(x < 0) return -errno;
	return x;
}
static int apply_internal(KVS_env *const env, KVS_apply_data const *const data) {
	if(!env) return KVS_EINVAL;
	if(!data) return KVS_EINVAL;
	FILE *const log = data->log;
	if(!log) return KVS_EINVAL;

	KVS_txn *txn = NULL;
	KVS_cursor *cursor = NULL;
	KVS_val key[1], val[1];
	unsigned char txnid[TXNID_MAX];
	unsigned char *keybuf = NULL;
	unsigned char *valbuf = NULL;
	size_t len;
	int rc = 0;

	rc = kvs_txn_begin(env, NULL, KVS_RDWR, &txn);
	if(rc < 0) goto cleanup;
	txn->mode = MODE_APPLY;
	rc = kvs_txn_cursor(txn, &cursor);
	if(rc < 0) goto cleanup;

	unsigned char meta[2] = { PFX_META, META_TXNID };
	*key = (KVS_val){ sizeof(meta), meta };

	char const expected_type = env->conflict_free ? 'U' : 'O';
	char type = 0;
	unsigned txnidlen = 0;
	fscanf(log, "%c:%u;", &type, &txnidlen);
	if(expected_type != type) {
		rc = KVS_INCOMPATIBLE;
		goto cleanup;
	}
	if(txnidlen > TXNID_MAX) {
		rc = KVS_INCOMPATIBLE;
		goto cleanup;
	}
	len = fread(txnid, 1, txnidlen, log);
	if(len < txnidlen) {
		rc = KVS_EIO;
		goto cleanup;
	}

	*val = (KVS_val){ 0, NULL };
	rc = kvs_get(kvs_prefix_txn_raw(TXN_INNER(txn)), key, val);
	if(KVS_NOTFOUND == rc) rc = 0;
	if(rc < 0) goto cleanup;
	if(txnidlen != val->size) {
		rc = KVS_BAD_TXN;
		goto cleanup;
	}
	rc = memcmp(val->data, txnid, txnidlen);
	if(0 != rc) {
		rc = KVS_BAD_TXN;
		goto cleanup;
	}

	if(!env->conflict_free) {
		*val = *data->txn_id;
		rc = kvs_put(kvs_prefix_txn_raw(TXN_INNER(txn)), key, val, 0);
		if(rc < 0) goto cleanup;
	}

	for(;;) {
		char type = 0;
		unsigned long long keylen = 0, vallen = 0;
		fscanf(log, "\n%c:", &type);
		if(0 == type) {
			break;
		} else if('P' == type) {
			fscanf(log, "%llu;", &keylen);
			fscanf(log, "%llu;", &vallen);
			if(0 == keylen) rc = KVS_BAD_VALSIZE;
			if(keylen > KEY_MAX) rc = KVS_BAD_VALSIZE;
			if(vallen > VAL_MAX) rc = KVS_BAD_VALSIZE;
		} else if('D' == type) {
			fscanf(log, "%llu;", &keylen);
			if(0 == keylen) rc = KVS_BAD_VALSIZE;
			if(keylen > KEY_MAX) rc = KVS_BAD_VALSIZE;
			if(env->conflict_free) rc = KVS_BAD_TXN;
		} else if('!' == type) {
			fscanf(log, "%llu;", &keylen);
			if(keylen > CMD_MAX) rc = KVS_BAD_VALSIZE;
		} else {
			rc = KVS_CORRUPTED;
		}
		if(rc < 0) goto cleanup;

		// Ensure allocations are non-zero (undefined behavior).
		keybuf = malloc(keylen+1);
		valbuf = malloc(vallen+1);
		if(!keybuf || !valbuf) {
			rc = KVS_ENOMEM;
			goto cleanup;
		}
		keybuf[0] = PFX_DATA;
		len = fread(keybuf, 1, keylen, log);
		if(len < keylen) {
			rc = KVS_EIO;
			goto cleanup;
		}
		len = fread(valbuf, 1, vallen, log);
		if(len < vallen) {
			rc = KVS_EIO;
			goto cleanup;
		}

		*key = (KVS_val){ keylen, keybuf };
		*val = (KVS_val){ vallen, valbuf };
		if('P' == type) rc = put_cr(cursor, key, val, 0, env->conflict_free);
		if('D' == type) rc = kvs_del(txn, key, 0);
		if('!' == type) rc = kvs_cmd(txn, keybuf, keylen);
		free(keybuf); keybuf = NULL;
		free(valbuf); valbuf = NULL;
		if(rc < 0) goto cleanup;
	}

	rc = kvs_txn_commit(txn); txn = NULL;
	if(rc < 0) goto cleanup;
cleanup:
	cursor = NULL;
	kvs_txn_abort(txn); txn = NULL;
	free(keybuf); keybuf = NULL;
	free(valbuf); valbuf = NULL;
	return rc;
}
static int default_commit(void *ctx, KVS_env *const env, FILE *const log) {
	KVS_apply_data data = {
		.txn_id = {{ 0, NULL }},
		.log = log,
	};
	return kvs_env_set_config(env, KVS_ENV_COMMITAPPLY, &data);
}


KVS_FN size_t kvs__env_size(void) {
	return sizeof(struct KVS_env);
}
KVS_FN int kvs__env_init(KVS_env *const env) {
	if(!env) return KVS_EINVAL;
	assert_zeroed(env, 1);
	KVS_env *inner = NULL;
	int rc = 0;
	env->isa = kvs_base_distributed;
	env->commit->fn = default_commit;
	env->conflict_free = false;

	rc = kvs_env_create_custom(kvs_base_prefix, &env->sub);
	if(rc < 0) goto cleanup;
	rc = kvs_env_create_base("mdb", &inner);
	if(rc < 0) goto cleanup;
	rc = kvs_env_set_config(env->sub, KVS_ENV_INNERDB, inner);
	if(rc < 0) goto cleanup;
	inner = NULL;

	unsigned char buf[1] = { PFX_DATA };
	KVS_val pfx = { sizeof(buf), buf };
	rc = kvs_env_set_config(env->sub, KVS_ENV_PREFIX, &pfx);
	if(rc < 0) goto cleanup;

cleanup:
	kvs_env_close(inner); inner = NULL;
	if(rc < 0) kvs_env_destroy(env);
	return rc;
}
KVS_FN int kvs__env_get_config(KVS_env *const env, char const *const type, void *data) {
	if(!env) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	if(0 == strcmp(type, KVS_ENV_COMMITHOOK)) {
		*(KVS_commit_data *)data = *env->commit; return 0;
	} else if(0 == strcmp(type, KVS_ENV_COMMITAPPLY)) {
		return KVS_EINVAL;
	} else if(0 == strcmp(type, KVS_ENV_TXNID)) {
		unsigned char buf[2] = { PFX_META, META_TXNID };
		KVS_val key = { sizeof(buf), buf };
		KVS_txn *txn = NULL;
		int rc = kvs_txn_begin(kvs_prefix_env_raw(env->sub),
			NULL, KVS_RDONLY, &txn);
		if(rc < 0) return rc;
		rc = kvs_get(txn, &key, data);
		kvs_txn_abort(txn);
		return rc;
	} else if(0 == strcmp(type, KVS_ENV_CONFLICTFREE)) {
		*(int *)data = env->conflict_free; return 0;
	} else if(0 == strcmp(type, KVS_ENV_PREFIX)) {
		return KVS_ENOTSUP;
	} else {
		return kvs_env_get_config(env->sub, type, data);
	}
}
KVS_FN int kvs__env_set_config(KVS_env *const env, char const *const type, void *data) {
	if(!env) return KVS_EINVAL;
	if(!type) return KVS_EINVAL;
	if(0 == strcmp(type, KVS_ENV_TXNSIZE)) {
		return KVS_ENOTSUP; // TODO
	} else if(0 == strcmp(type, KVS_ENV_COMMITHOOK)) {
		*env->commit = *(KVS_commit_data *)data; return 0;
	} else if(0 == strcmp(type, KVS_ENV_COMMITAPPLY)) {
		return apply_internal(env, data);
	} else if(0 == strcmp(type, KVS_ENV_TXNID)) {
		unsigned char buf[2] = { PFX_META, META_TXNID };
		KVS_val key = { sizeof(buf), buf };
		KVS_val val = *(KVS_val *)data;
		KVS_txn *txn = NULL;
		int rc = kvs_txn_begin(kvs_prefix_env_raw(env->sub),
			NULL, KVS_RDWR, &txn);
		if(rc < 0) return rc;
		rc = kvs_put(txn, &key, &val, 0);
		if(rc < 0) { kvs_txn_abort(txn); return rc; }
		return kvs_txn_commit(txn);
	} else if(0 == strcmp(type, KVS_ENV_CONFLICTFREE)) {
		env->conflict_free = *(int *)data; return 0;
	} else if(0 == strcmp(type, KVS_ENV_PREFIX)) {
		return KVS_ENOTSUP;
	} else {
		return kvs_env_set_config(env->sub, type, data);
	}
}
KVS_FN int kvs__env_open0(KVS_env *const env) {
	if(!env) return KVS_EINVAL;
	unsigned flags = 0;
	int rc = kvs_env_get_config(env, KVS_ENV_FLAGS, &flags);
	if(rc < 0) goto cleanup;
	rc = kvs_env_open0(env->sub);
	if(rc < 0) goto cleanup;

	if(!(KVS_RDONLY & flags)) {
		char const *dbpath = NULL;
		char path[KVS_PATH_MAX];
		rc = kvs_env_get_config(env->sub, KVS_ENV_FILENAME, &dbpath);
		if(rc < 0) goto cleanup;

		rc = err(snprintf(path, sizeof(path), "%s-log", dbpath));
		if(rc >= sizeof(path)) rc = KVS_ENAMETOOLONG;
		if(rc < 0) goto cleanup;
		env->logpath = strdup(path);
		if(!env->logpath) {
			rc = KVS_ENOMEM;
			goto cleanup;
		}
	}
cleanup:
	return rc;
}
KVS_FN void kvs__env_destroy(KVS_env *const env) {
	if(!env) return;
	kvs_env_close(env->sub); env->sub = NULL;
	env->commit->fn = NULL;
	env->commit->ctx = NULL;
	free(env->logpath); env->logpath = NULL;
	env->conflict_free = 0;
	env->isa = NULL;
	assert_zeroed(env, 1);
}

KVS_FN size_t kvs__txn_size(KVS_env *const env) {
	if(!env) return 0;
	return sizeof(struct KVS_txn)+kvs_txn_size(env->sub);
}
KVS_FN int kvs__txn_init(KVS_env *const env, KVS_txn *const txn) {
	if(!env) return KVS_EINVAL;
	if(!txn) return KVS_EINVAL;
	assert_zeroed(txn, 1);
	txn->isa = kvs_base_distributed;
	txn->helper->env = env;
	return 0;
}
KVS_FN int kvs__txn_get_config(KVS_txn *const txn, char const *const type, void *data) {
	if(!txn) return KVS_EINVAL;
	return kvs_helper_txn_get_config(txn, txn->helper, type, data);
}
KVS_FN int kvs__txn_set_config(KVS_txn *const txn, char const *const type, void *data) {
	if(!txn) return KVS_EINVAL;
	return kvs_helper_txn_set_config(txn, txn->helper, type, data);
}
KVS_FN int kvs__txn_begin0(KVS_txn *const txn) {
	if(!txn) return KVS_EINVAL;
	if(!txn->helper->env) return KVS_EINVAL;
	if(txn->helper->parent && txn->helper->parent->helper->child) return KVS_BAD_TXN;
	int rc = kvs_txn_begin_init(txn->helper->env->sub, txn->helper->parent ? TXN_INNER(txn->helper->parent) : NULL, txn->helper->flags, TXN_INNER(txn));
	if(rc < 0) goto cleanup;

	if(KVS_RDONLY & txn->helper->flags) {
		txn->mode = MODE_RDONLY;
	} else if(txn->helper->parent) {
		txn->mode = txn->helper->parent->mode;
		txn->log = txn->helper->parent->log;
		txn->length = txn->helper->parent->length;
	} else {
		txn->mode = MODE_RECORDING;
		remove(txn->helper->env->logpath);
		txn->log = fopen(txn->helper->env->logpath, "w+b");
		if(!txn->log) {
			rc = -errno;
			goto cleanup;
		}

		int const type = txn->helper->env->conflict_free ? 'U' : 'O';
		unsigned char buf[2] = { PFX_META, META_TXNID };
		KVS_val key = { sizeof(buf), buf };
		KVS_val val = { 0, NULL };
		rc = kvs_get(kvs_prefix_txn_raw(TXN_INNER(txn)),
			&key, &val);
		if(KVS_NOTFOUND == rc) rc = 0;
		if(rc < 0) goto cleanup;
		rc = fprintf(txn->log, "%c:%u;", type, (unsigned)val.size);
		if(rc < 0) {
			rc = KVS_EIO;
			goto cleanup;
		}
		size_t len = fwrite(val.data, 1, val.size, txn->log);
		if(len < val.size) rc = KVS_EIO;
		if(rc < 0) goto cleanup;
		txn->length = ftell(txn->log);
		assert(txn->length >= 0);
	}

	if(txn->helper->parent) txn->helper->parent->helper->child = txn;
cleanup:
	if(rc < 0) kvs_txn_abort_destroy(txn);
	return rc;
}
KVS_FN int kvs__txn_commit_destroy(KVS_txn *const txn) {
	if(!txn) return KVS_EINVAL;
	if(MODE_RDONLY == txn->mode) goto cleanup;
	assert(MODE_COMMAND != txn->mode);
	FILE *log = NULL;
	int rc = kvs_helper_txn_commit(txn->helper);
	if(rc < 0) goto cleanup;

	if(txn->helper->parent) {
		rc = kvs_txn_commit_destroy(TXN_INNER(txn));
		if(rc < 0) goto cleanup;
		txn->log = NULL;
		txn->helper->parent->length = txn->length;
		goto cleanup;
	}

	if(MODE_RECORDING == txn->mode) {
		KVS_env *const env = txn->helper->env;
		size_t length = txn->length; txn->length = 0;
		log = txn->log; txn->log = NULL;
		kvs_txn_abort_destroy(txn);

		rc = err(fflush(log));
		if(rc < 0) goto cleanup;
		rc = err(ftruncate(fileno(log), length));
		if(rc < 0) goto cleanup;

		rc = err(fseek(log, 0, SEEK_SET));
		if(rc < 0) goto cleanup;
		if(!env->commit->fn) {
			rc = KVS_PANIC;
			goto cleanup;
		}
		rc = env->commit->fn(env->commit->ctx, env, log);
		if(rc < 0) goto cleanup;
	} else if(MODE_APPLY == txn->mode) {
		rc = kvs_txn_commit_destroy(TXN_INNER(txn));
		if(rc < 0) goto cleanup;
	} else {
		assert(0);
	}

cleanup:
	if(log) { fclose(log); log = NULL; }
	kvs_txn_abort_destroy(txn);
	return rc;
}
KVS_FN void kvs__txn_abort_destroy(KVS_txn *const txn) {
	if(!txn) return;
	assert(MODE_COMMAND != txn->mode);
	kvs_helper_txn_abort(txn->helper);
	if(!txn->log) {
		// Do nothing
	} else if(txn->helper->parent) {
		int rc = err(fseek(txn->log, txn->helper->parent->length, SEEK_SET));
		assert(rc >= 0);
		txn->log = NULL;
	} else {
		fclose(txn->log); txn->log = NULL;
	}
	kvs_txn_abort_destroy(TXN_INNER(txn));
	txn->mode = 0;
	txn->length = 0;
	txn->isa = NULL;
	assert_zeroed(txn, 1);
}
KVS_FN int kvs__txn_cmp(KVS_txn *const txn, KVS_val const *const a, KVS_val const *const b) {
	return kvs_txn_cmp(TXN_INNER(txn), a, b);
}

KVS_FN int kvs__get(KVS_txn *const txn, KVS_val const *const key, KVS_val *const data) {
	return kvs_helper_get(txn, key, data);
}
KVS_FN int kvs__put(KVS_txn *const txn, KVS_val const *const key, KVS_val *const val, unsigned const flags) {
	return kvs_helper_put(txn, key, val, flags);
}
KVS_FN int kvs__del(KVS_txn *const txn, KVS_val const *const key, unsigned const flags) {
	if(!txn) return KVS_EINVAL;
	if(txn->helper->env->conflict_free) return KVS_ENOTSUP;
	size_t len;
	int rc = 0;
	if(MODE_RECORDING == txn->mode) {
		rc = fprintf(txn->log, "\nD:%llu;",
			(unsigned long long)key->size);
		if(rc < 0) {
			rc = KVS_EIO;
			goto cleanup;
		}
		len = fwrite(key->data, 1, key->size, txn->log);
		if(len < key->size) {
			rc = KVS_EIO;
			goto cleanup;
		}
	}
	rc = kvs_del(TXN_INNER(txn), key, flags);
	if(rc < 0) goto cleanup;
	if(MODE_RECORDING == txn->mode) {
		txn->length = ftell(txn->log);
		assert(txn->length >= 0);
	}
cleanup:
	if(MODE_RECORDING == txn->mode && rc < 0) {
		int x = err(fseek(txn->log, txn->length, SEEK_SET));
		assert(x >= 0);
	}
	return rc;
}
KVS_FN int kvs__cmd(KVS_txn *const txn, unsigned char const *const buf, size_t const blen) {
	if(!txn) return KVS_EINVAL;
	if(MODE_RDONLY == txn->mode) return KVS_EACCES;
	MODE const orig = txn->mode;
	size_t len;
	int rc = 0;
	if(MODE_RECORDING == txn->mode) {
		rc = fprintf(txn->log, "\n!:%llu;",
			(unsigned long long)blen);
		if(rc < 0) {
			rc = KVS_EIO;
			goto cleanup;
		}
		len = fwrite(buf, 1, blen, txn->log);
		if(len < blen) {
			rc = KVS_EIO;
			goto cleanup;
		}
	}
	txn->mode = MODE_COMMAND;
	rc = kvs_helper_cmd(txn, buf, blen);
cleanup:
	txn->mode = orig;
	if(MODE_RECORDING == txn->mode) {
		if(rc < 0) {
			int x = err(fseek(txn->log, txn->length, SEEK_SET));
			assert(x >= 0);
		} else {
			txn->length = ftell(txn->log);
			assert(txn->length >= 0);
		}
	}
	return rc;
}

KVS_FN int kvs__countr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	return kvs_helper_countr(txn, range, out);
}
KVS_FN int kvs__delr(KVS_txn *const txn, KVS_range const *const range, uint64_t *const out) {
	return kvs_helper_delr(txn, range, out);
}

KVS_FN size_t kvs__cursor_size(KVS_txn *const txn) {
	return sizeof(struct KVS_cursor)+kvs_cursor_size(TXN_INNER(txn));
}
KVS_FN int kvs__cursor_init(KVS_txn *const txn, KVS_cursor *const cursor) {
	if(!txn) return KVS_EINVAL;
	if(!cursor) return KVS_EINVAL;
	assert_zeroed(cursor, 1);
	int rc = 0;
	cursor->isa = kvs_base_distributed;
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
	reserve_finish(cursor);
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
	// Not necessary to reserve_finish() here.
	return kvs_cursor_current(CURSOR_INNER(cursor), key, data);
}
KVS_FN int kvs__cursor_seek(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	reserve_finish(cursor);
	return kvs_cursor_seek(CURSOR_INNER(cursor), key, data, dir);
}
KVS_FN int kvs__cursor_first(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	reserve_finish(cursor);
	return kvs_cursor_first(CURSOR_INNER(cursor), key, data, dir);
}
KVS_FN int kvs__cursor_next(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const data, int const dir) {
	if(!cursor) return KVS_EINVAL;
	reserve_finish(cursor);
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

KVS_FN int kvs__cursor_put(KVS_cursor *const cursor, KVS_val *const key, KVS_val *const val, unsigned const flags) {
	if(!cursor) return KVS_EINVAL;
	KVS_txn *const txn = cursor->txn;
	reserve_finish(cursor);

	if(flags & ~(KVS_NOOVERWRITE|KVS_CURRENT|KVS_NOOVERWRITE)) return KVS_ENOTSUP;
	bool const conflict_free = cursor->txn->helper->env->conflict_free;
	size_t len;
	int rc = 0;
	if(KVS_RESERVE & flags) {
		cursor->has_reserve = true;
		return kvs_cursor_put(CURSOR_INNER(cursor), key, val, flags);
	}
	if(KVS_CURRENT & flags) {
		rc = kvs_cursor_current(CURSOR_INNER(cursor), key, NULL);
		if(rc < 0) return rc;
	}
	if(MODE_RECORDING == txn->mode) {
		rc = fprintf(txn->log, "\nP:%llu;%llu;",
			(unsigned long long)key->size,
			(unsigned long long)val->size);
		if(rc < 0) goto cleanup;
		len = fwrite(key->data, 1, key->size, txn->log);
		if(len < key->size) rc = KVS_EIO;
		if(rc < 0) goto cleanup;
		len = fwrite(val->data, 1, val->size, txn->log);
		if(len < val->size) rc = KVS_EIO;
		if(rc < 0) goto cleanup;
	}
	rc = put_cr(CURSOR_INNER(cursor), key, val, flags & ~KVS_CURRENT, conflict_free);
	if(rc < 0) goto cleanup;
	if(MODE_RECORDING == txn->mode) {
		txn->length = ftell(txn->log);
		assert(txn->length >= 0);
	}
cleanup:
	if(MODE_RECORDING == txn->mode && rc < 0) {
		int x = err(fseek(txn->log, txn->length, SEEK_SET));
		assert(x >= 0);
	}
	return rc;
}
KVS_FN int kvs__cursor_del(KVS_cursor *const cursor, unsigned const flags) {
	reserve_finish(cursor);
	return kvs_helper_cursor_del(cursor, flags);
}

KVS_BASE_V0(distributed)

