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
#include "db_base_internal.h"
#include "db_base_prefix.h"
#include "common.h"

#define DB_PATH_MAX (1023+1)

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

struct DB_env {
	DB_base const *isa;
	DB_env *sub;
	DB_commit_data commit[1];
	char *logpath;
	bool conflict_free;
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
	DB_txn *child;
	FILE *log;
	long length;
	DB_cursor *cursor;
	MODE mode;
	// Inner txn
};
struct DB_cursor {
	DB_base const *isa;
	DB_txn *txn;
	bool has_reserve;
	// Inner cursor
};
#define TXN_INNER(txn) ((txn)+1)
#define CURSOR_INNER(c) ((c)+1)

static int put_cr(DB_cursor *const cursor, DB_val *const key, DB_val *const val, unsigned const flags, bool const conflict_free) {
	unsigned xflags = conflict_free ? DB_NOOVERWRITE : 0;
	DB_val const wr = val ? *val : (DB_val){ 0, NULL };
	DB_val rd = wr; // Even if val is null, we need to check.
	int rc = db_cursor_put(cursor, key, &rd, flags | xflags);
	if(val) *val = rd;
	if(conflict_free && DB_KEYEXIST == rc) {
		// In conflict free (unordered) mode, we can't overwrite values.
		// However, if the new value is the same, that's OK.
		if(wr.size != rd.size) return rc;
		if(DB_RESERVE & flags) return DB_ENOTSUP; // TODO
		int x = db_cursor_cmp(cursor, &wr, &rd);
		if(0 == x) rc = 0;
	}
	return rc;
}
static void reserve_finish(DB_cursor *const cursor) {
	if(!cursor) return;
	if(!cursor->has_reserve) return;
	DB_val key[1], val[1];
	size_t len;
	int rc = db_cursor_current(CURSOR_INNER(cursor), key, val);
	assert(rc >= 0);
	DB_txn *const txn = cursor->txn;
	if(MODE_RECORDING == txn->mode) {
		rc = fprintf(txn->log, "\nP:%llu;%llu;",
			(unsigned long long)key->size,
			(unsigned long long)val->size);
		if(rc < 0) goto cleanup;
		len = fwrite(key->data, 1, key->size, txn->log);
		if(len < key->size) rc = DB_EIO;
		if(rc < 0) goto cleanup;
		len = fwrite(val->data, 1, val->size, txn->log);
		if(len < val->size) rc = DB_EIO;
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
static int apply_internal(DB_env *const env, DB_apply_data const *const data) {
	if(!env) return DB_EINVAL;
	if(!data) return DB_EINVAL;
	FILE *const log = data->log;
	if(!log) return DB_EINVAL;

	DB_txn *txn = NULL;
	DB_cursor *cursor = NULL;
	DB_val key[1], val[1];
	unsigned char txnid[TXNID_MAX];
	unsigned char *keybuf = NULL;
	unsigned char *valbuf = NULL;
	size_t len;
	int rc = 0;

	rc = db_txn_begin(env, NULL, DB_RDWR, &txn);
	if(rc < 0) goto cleanup;
	txn->mode = MODE_APPLY;
	rc = db_txn_cursor(txn, &cursor);
	if(rc < 0) goto cleanup;

	unsigned char meta[2] = { PFX_META, META_TXNID };
	*key = (DB_val){ sizeof(meta), meta };

	char const expected_type = env->conflict_free ? 'U' : 'O';
	char type = 0;
	unsigned txnidlen = 0;
	fscanf(log, "%c:%u;", &type, &txnidlen);
	if(expected_type != type) {
		rc = DB_INCOMPATIBLE;
		goto cleanup;
	}
	if(txnidlen > TXNID_MAX) {
		rc = DB_INCOMPATIBLE;
		goto cleanup;
	}
	len = fread(txnid, 1, txnidlen, log);
	if(len < txnidlen) {
		rc = DB_EIO;
		goto cleanup;
	}

	*val = (DB_val){ 0, NULL };
	rc = db_get(db_prefix_txn_raw(TXN_INNER(txn)), key, val);
	if(DB_NOTFOUND == rc) rc = 0;
	if(rc < 0) goto cleanup;
	if(txnidlen != val->size) {
		rc = DB_BAD_TXN;
		goto cleanup;
	}
	rc = memcmp(val->data, txnid, txnidlen);
	if(0 != rc) {
		rc = DB_BAD_TXN;
		goto cleanup;
	}

	if(!env->conflict_free) {
		*val = *data->txn_id;
		rc = db_put(db_prefix_txn_raw(TXN_INNER(txn)), key, val, 0);
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
			if(0 == keylen) rc = DB_BAD_VALSIZE;
			if(keylen > KEY_MAX) rc = DB_BAD_VALSIZE;
			if(vallen > VAL_MAX) rc = DB_BAD_VALSIZE;
		} else if('D' == type) {
			fscanf(log, "%llu;", &keylen);
			if(0 == keylen) rc = DB_BAD_VALSIZE;
			if(keylen > KEY_MAX) rc = DB_BAD_VALSIZE;
			if(env->conflict_free) rc = DB_BAD_TXN;
		} else if('!' == type) {
			fscanf(log, "%llu;", &keylen);
			if(keylen > CMD_MAX) rc = DB_BAD_VALSIZE;
		} else {
			rc = DB_CORRUPTED;
		}
		if(rc < 0) goto cleanup;

		// Ensure allocations are non-zero (undefined behavior).
		keybuf = malloc(keylen+1);
		valbuf = malloc(vallen+1);
		if(!keybuf || !valbuf) {
			rc = DB_ENOMEM;
			goto cleanup;
		}
		keybuf[0] = PFX_DATA;
		len = fread(keybuf, 1, keylen, log);
		if(len < keylen) {
			rc = DB_EIO;
			goto cleanup;
		}
		len = fread(valbuf, 1, vallen, log);
		if(len < vallen) {
			rc = DB_EIO;
			goto cleanup;
		}

		*key = (DB_val){ keylen, keybuf };
		*val = (DB_val){ vallen, valbuf };
		if('P' == type) rc = put_cr(cursor, key, val, 0, env->conflict_free);
		if('D' == type) rc = db_del(txn, key, 0);
		if('!' == type) rc = db_cmd(txn, keybuf, keylen);
		free(keybuf); keybuf = NULL;
		free(valbuf); valbuf = NULL;
		if(rc < 0) goto cleanup;
	}

	rc = db_txn_commit(txn); txn = NULL;
	if(rc < 0) goto cleanup;
cleanup:
	cursor = NULL;
	db_txn_abort(txn); txn = NULL;
	free(keybuf); keybuf = NULL;
	free(valbuf); valbuf = NULL;
	return rc;
}
static int default_commit(void *ctx, DB_env *const env, FILE *const log) {
	DB_apply_data data = {
		.txn_id = {{ 0, NULL }},
		.log = log,
	};
	return db_env_set_config(env, DB_CFG_COMMITAPPLY, &data);
}


DB_FN size_t db__env_size(void) {
	return sizeof(struct DB_env);
}
DB_FN int db__env_init(DB_env *const env) {
	if(!env) return DB_EINVAL;
	assert_zeroed(env, 1);
	DB_env *inner = NULL;
	int rc = 0;
	env->isa = db_base_distributed;
	env->commit->fn = default_commit;
	env->conflict_free = false;

	rc = db_env_create_custom(db_base_prefix, &env->sub);
	if(rc < 0) goto cleanup;
	rc = db_env_create_base("mdb", &inner);
	if(rc < 0) goto cleanup;
	rc = db_env_set_config(env->sub, DB_CFG_INNERDB, inner);
	if(rc < 0) goto cleanup;
	inner = NULL;

	unsigned char buf[1] = { PFX_DATA };
	DB_val pfx = { sizeof(buf), buf };
	rc = db_env_set_config(env->sub, DB_CFG_PREFIX, &pfx);
	if(rc < 0) goto cleanup;

cleanup:
	db_env_close(inner); inner = NULL;
	if(rc < 0) db_env_destroy(env);
	return rc;
}
DB_FN int db__env_get_config(DB_env *const env, char const *const type, void *data) {
	if(!env) return DB_EINVAL;
	if(!type) return DB_EINVAL;
	if(0 == strcmp(type, DB_CFG_COMMITHOOK)) {
		*(DB_commit_data *)data = *env->commit; return 0;
	} else if(0 == strcmp(type, DB_CFG_COMMITAPPLY)) {
		return DB_EINVAL;
	} else if(0 == strcmp(type, DB_CFG_TXNID)) {
		unsigned char buf[2] = { PFX_META, META_TXNID };
		DB_val key = { sizeof(buf), buf };
		DB_txn *txn = NULL;
		int rc = db_txn_begin(db_prefix_env_raw(env->sub),
			NULL, DB_RDONLY, &txn);
		if(rc < 0) return rc;
		rc = db_get(txn, &key, data);
		db_txn_abort(txn);
		return rc;
	} else if(0 == strcmp(type, DB_CFG_CONFLICTFREE)) {
		*(int *)data = env->conflict_free; return 0;
	} else if(0 == strcmp(type, DB_CFG_PREFIX)) {
		return DB_ENOTSUP;
	} else {
		return db_env_get_config(env->sub, type, data);
	}
}
DB_FN int db__env_set_config(DB_env *const env, char const *const type, void *data) {
	if(!env) return DB_EINVAL;
	if(!type) return DB_EINVAL;
	if(0 == strcmp(type, DB_CFG_TXNSIZE)) {
		return DB_ENOTSUP; // TODO
	} else if(0 == strcmp(type, DB_CFG_COMMITHOOK)) {
		*env->commit = *(DB_commit_data *)data; return 0;
	} else if(0 == strcmp(type, DB_CFG_COMMITAPPLY)) {
		return apply_internal(env, data);
	} else if(0 == strcmp(type, DB_CFG_TXNID)) {
		unsigned char buf[2] = { PFX_META, META_TXNID };
		DB_val key = { sizeof(buf), buf };
		DB_val val = *(DB_val *)data;
		DB_txn *txn = NULL;
		int rc = db_txn_begin(db_prefix_env_raw(env->sub),
			NULL, DB_RDWR, &txn);
		if(rc < 0) return rc;
		rc = db_put(txn, &key, &val, 0);
		if(rc < 0) { db_txn_abort(txn); return rc; }
		return db_txn_commit(txn);
	} else if(0 == strcmp(type, DB_CFG_CONFLICTFREE)) {
		env->conflict_free = *(int *)data; return 0;
	} else if(0 == strcmp(type, DB_CFG_PREFIX)) {
		return DB_ENOTSUP;
	} else {
		return db_env_set_config(env->sub, type, data);
	}
}
DB_FN int db__env_open0(DB_env *const env) {
	if(!env) return DB_EINVAL;
	unsigned flags = 0;
	int rc = db_env_get_config(env, DB_CFG_FLAGS, &flags);
	if(rc < 0) goto cleanup;
	rc = db_env_open0(env->sub);
	if(rc < 0) goto cleanup;

	if(!(DB_RDONLY & flags)) {
		char const *dbpath = NULL;
		char path[DB_PATH_MAX];
		rc = db_env_get_config(env->sub, DB_CFG_FILENAME, &dbpath);
		if(rc < 0) goto cleanup;

		rc = err(snprintf(path, sizeof(path), "%s-log", dbpath));
		if(rc >= sizeof(path)) rc = DB_ENAMETOOLONG;
		if(rc < 0) goto cleanup;
		env->logpath = strdup(path);
		if(!env->logpath) {
			rc = DB_ENOMEM;
			goto cleanup;
		}
	}
cleanup:
	return rc;
}
DB_FN void db__env_destroy(DB_env *const env) {
	if(!env) return;
	db_env_close(env->sub); env->sub = NULL;
	env->commit->fn = NULL;
	env->commit->ctx = NULL;
	free(env->logpath); env->logpath = NULL;
	env->conflict_free = 0;
	env->isa = NULL;
	assert_zeroed(env, 1);
}

DB_FN size_t db__txn_size(DB_env *const env) {
	return sizeof(struct DB_txn)+db_txn_size(env->sub);
}
DB_FN int db__txn_begin_init(DB_env *const env, DB_txn *const parent, unsigned const flags, DB_txn *const txn) {
	if(!env) return DB_EINVAL;
	if(!txn) return DB_EINVAL;
	if(parent && parent->child) return DB_BAD_TXN;
	assert_zeroed(txn, 1);
	int rc = 0;
	txn->isa = db_base_distributed;
	txn->env = env;
	txn->parent = parent;
	txn->child = NULL;

	rc = db_txn_begin_init(env->sub, parent ? TXN_INNER(parent) : NULL, 0, TXN_INNER(txn));
	if(rc < 0) goto cleanup;

	if(DB_RDONLY & flags) {
		txn->mode = MODE_RDONLY;
	} else if(parent) {
		txn->mode = parent->mode;
		txn->log = parent->log;
		txn->length = parent->length;
	} else {
		txn->mode = MODE_RECORDING;
		remove(env->logpath);
		txn->log = fopen(env->logpath, "w+b");
		if(!txn->log) {
			rc = -errno;
			goto cleanup;
		}

		int const type = txn->env->conflict_free ? 'U' : 'O';
		unsigned char buf[2] = { PFX_META, META_TXNID };
		DB_val key = { sizeof(buf), buf };
		DB_val val = { 0, NULL };
		rc = db_get(db_prefix_txn_raw(TXN_INNER(txn)),
			&key, &val);
		if(DB_NOTFOUND == rc) rc = 0;
		if(rc < 0) goto cleanup;
		rc = fprintf(txn->log, "%c:%u;", type, (unsigned)val.size);
		if(rc < 0) {
			rc = DB_EIO;
			goto cleanup;
		}
		size_t len = fwrite(val.data, 1, val.size, txn->log);
		if(len < val.size) rc = DB_EIO;
		if(rc < 0) goto cleanup;
		txn->length = ftell(txn->log);
		assert(txn->length >= 0);
	}

	if(parent) parent->child = txn;
cleanup:
	if(rc < 0) db_txn_abort_destroy(txn);
	return rc;
}
DB_FN int db__txn_commit_destroy(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	if(MODE_RDONLY == txn->mode) goto cleanup;
	assert(MODE_COMMAND != txn->mode);
	DB_env *const env = txn->env;
	FILE *log = NULL;
	size_t length = 0;
	int rc = 0;
	if(txn->child) {
		rc = db_txn_commit(txn->child); txn->child = NULL;
		if(rc < 0) goto cleanup;
	}

	if(txn->parent) {
		db_cursor_close(txn->cursor); txn->cursor = NULL;
		rc = db_txn_commit_destroy(TXN_INNER(txn));
		if(rc < 0) goto cleanup;
		txn->log = NULL;
		txn->parent->length = txn->length;
		goto cleanup;
	}

	if(MODE_RECORDING == txn->mode) {
		log = txn->log; txn->log = NULL;
		length = txn->length; txn->length = 0;
		db_txn_abort_destroy(txn);

		rc = err(fflush(log));
		if(rc < 0) goto cleanup;
		rc = err(ftruncate(fileno(log), length));
		if(rc < 0) goto cleanup;

		rc = err(fseek(log, 0, SEEK_SET));
		if(rc < 0) goto cleanup;
		if(!env->commit->fn) {
			rc = DB_PANIC;
			goto cleanup;
		}
		rc = env->commit->fn(env->commit->ctx, env, log);
		if(rc < 0) goto cleanup;
	} else if(MODE_APPLY == txn->mode) {
		rc = db_txn_commit_destroy(TXN_INNER(txn));
		if(rc < 0) goto cleanup;
	} else {
		assert(0);
	}

cleanup:
	if(log) { fclose(log); log = NULL; }
	db_txn_abort_destroy(txn);
	return rc;
}
DB_FN void db__txn_abort_destroy(DB_txn *const txn) {
	if(!txn) return;
	assert(MODE_COMMAND != txn->mode);
	if(txn->child) {
		db_txn_abort(txn->child); txn->child = NULL;
	}
	if(!txn->log) {
		// Do nothing
	} else if(txn->parent) {
		int rc = err(fseek(txn->log, txn->parent->length, SEEK_SET));
		assert(rc >= 0);
		txn->log = NULL;
	} else {
		fclose(txn->log); txn->log = NULL;
	}
	db_cursor_close(txn->cursor); txn->cursor = NULL;
	db_txn_abort_destroy(TXN_INNER(txn));
	if(txn->parent) txn->parent->child = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->mode = 0;
	txn->length = 0;
	txn->isa = NULL;
	assert_zeroed(txn, 1);
}
DB_FN int db__txn_env(DB_txn *const txn, DB_env **const out) {
	if(!txn) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	*out = txn->env;
	return 0;
}
DB_FN int db__txn_parent(DB_txn *const txn, DB_txn **const out) {
	if(!txn) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	*out = txn->parent;
	return 0;
}
DB_FN int db__txn_get_flags(DB_txn *const txn, unsigned *const flags) {
	if(!txn) return DB_EINVAL;
	return db_txn_get_flags(TXN_INNER(txn), flags);
}
DB_FN int db__txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	return db_txn_cmp(TXN_INNER(txn), a, b);
}
DB_FN int db__txn_cursor(DB_txn *const txn, DB_cursor **const out) {
	if(!txn) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	if(!txn->cursor) {
		int rc = db_cursor_open(txn, &txn->cursor);
		if(rc < 0) return rc;
	}
	*out = txn->cursor;
	return 0;
}

DB_FN int db__get(DB_txn *const txn, DB_val const *const key, DB_val *const data) {
	return db_helper_get(txn, key, data);
}
DB_FN int db__put(DB_txn *const txn, DB_val const *const key, DB_val *const val, unsigned const flags) {
	return db_helper_put(txn, key, val, flags);
}
DB_FN int db__del(DB_txn *const txn, DB_val const *const key, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	if(txn->env->conflict_free) return DB_ENOTSUP;
	size_t len;
	int rc = 0;
	if(MODE_RECORDING == txn->mode) {
		rc = fprintf(txn->log, "\nD:%llu;",
			(unsigned long long)key->size);
		if(rc < 0) {
			rc = DB_EIO;
			goto cleanup;
		}
		len = fwrite(key->data, 1, key->size, txn->log);
		if(len < key->size) {
			rc = DB_EIO;
			goto cleanup;
		}
	}
	rc = db_del(TXN_INNER(txn), key, flags);
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
DB_FN int db__cmd(DB_txn *const txn, unsigned char const *const buf, size_t const blen) {
	if(!txn) return DB_EINVAL;
	if(MODE_RDONLY == txn->mode) return DB_EACCES;
	MODE const orig = txn->mode;
	size_t len;
	int rc = 0;
	if(MODE_RECORDING == txn->mode) {
		rc = fprintf(txn->log, "\n!:%llu;",
			(unsigned long long)blen);
		if(rc < 0) {
			rc = DB_EIO;
			goto cleanup;
		}
		len = fwrite(buf, 1, blen, txn->log);
		if(len < blen) {
			rc = DB_EIO;
			goto cleanup;
		}
	}
	txn->mode = MODE_COMMAND;
	rc = db_helper_cmd(txn, buf, blen);
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

DB_FN int db__countr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_countr(txn, range, out);
}
DB_FN int db__delr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_delr(txn, range, out);
}

DB_FN size_t db__cursor_size(DB_txn *const txn) {
	return sizeof(struct DB_cursor)+db_cursor_size(TXN_INNER(txn));
}
DB_FN int db__cursor_init(DB_txn *const txn, DB_cursor *const cursor) {
	if(!txn) return DB_EINVAL;
	if(!cursor) return DB_EINVAL;
	assert_zeroed(cursor, 1);
	int rc = 0;
	cursor->isa = db_base_distributed;
	cursor->txn = txn;

	rc = db_cursor_init(TXN_INNER(txn), CURSOR_INNER(cursor));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) db_cursor_destroy(cursor);
	return rc;
}
DB_FN void db__cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	db_cursor_destroy(CURSOR_INNER(cursor));
	cursor->txn = NULL;
	cursor->isa = NULL;
	assert_zeroed(cursor, 1);
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	reserve_finish(cursor);
	return db_cursor_clear(CURSOR_INNER(cursor));
}
DB_FN int db__cursor_txn(DB_cursor *const cursor, DB_txn **const out) {
	if(!cursor) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	*out = cursor->txn;
	return 0;
}
DB_FN int db__cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	assert(cursor);
	return db_cursor_cmp(CURSOR_INNER(cursor), a, b);
}

DB_FN int db__cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	// Not necessary to reserve_finish() here.
	return db_cursor_current(CURSOR_INNER(cursor), key, data);
}
DB_FN int db__cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	reserve_finish(cursor);
	return db_cursor_seek(CURSOR_INNER(cursor), key, data, dir);
}
DB_FN int db__cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	reserve_finish(cursor);
	return db_cursor_first(CURSOR_INNER(cursor), key, data, dir);
}
DB_FN int db__cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	reserve_finish(cursor);
	return db_cursor_next(CURSOR_INNER(cursor), key, data, dir);
}

DB_FN int db__cursor_seekr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	return db_helper_cursor_seekr(cursor, range, key, data, dir);
}
DB_FN int db__cursor_firstr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	return db_helper_cursor_firstr(cursor, range, key, data, dir);
}
DB_FN int db__cursor_nextr(DB_cursor *const cursor, DB_range const *const range, DB_val *const key, DB_val *const data, int const dir) {
	return db_helper_cursor_nextr(cursor, range, key, data, dir);
}

DB_FN int db__cursor_put(DB_cursor *const cursor, DB_val *const key, DB_val *const val, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	DB_txn *const txn = cursor->txn;
	reserve_finish(cursor);

	if(flags & ~(DB_NOOVERWRITE|DB_CURRENT|DB_NOOVERWRITE)) return DB_ENOTSUP;
	bool const conflict_free = cursor->txn->env->conflict_free;
	size_t len;
	int rc = 0;
	if(DB_RESERVE & flags) {
		cursor->has_reserve = true;
		return db_cursor_put(CURSOR_INNER(cursor), key, val, flags);
	}
	if(DB_CURRENT & flags) {
		rc = db_cursor_current(CURSOR_INNER(cursor), key, NULL);
		if(rc < 0) return rc;
	}
	if(MODE_RECORDING == txn->mode) {
		rc = fprintf(txn->log, "\nP:%llu;%llu;",
			(unsigned long long)key->size,
			(unsigned long long)val->size);
		if(rc < 0) goto cleanup;
		len = fwrite(key->data, 1, key->size, txn->log);
		if(len < key->size) rc = DB_EIO;
		if(rc < 0) goto cleanup;
		len = fwrite(val->data, 1, val->size, txn->log);
		if(len < val->size) rc = DB_EIO;
		if(rc < 0) goto cleanup;
	}
	rc = put_cr(CURSOR_INNER(cursor), key, val, flags & ~DB_CURRENT, conflict_free);
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
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	reserve_finish(cursor);
	return db_helper_cursor_del(cursor, flags);
}

DB_BASE_V0(distributed)

