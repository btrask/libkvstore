// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "liblmdb/lmdb.h"
#include "db_base_internal.h"
#include "db_wrbuf.h"
#include "db_base_prefix.h"
#include "common.h"

#define DB_PATH_MAX (1023+1)

#define TXNID_MAX 256
#define KEY_MAX 510
#define VAL_MAX (1024*1024*1)
#define CMD_MAX (1024*1024*1)

enum {
	PFX_META = 'M',
	PFX_MAIN = 0x00, // For compressability
};
enum {
	META_TXNID = 'I',
};

struct DB_env {
	DB_base const *isa;
	DB_env *main;
	DB_env *temp;
	DB_commit_data commit[1];
	unsigned flags;
	char *path;
	int mode;
	bool ordered;
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
	DB_txn *child;
	DB_txn *main;
	DB_txn *temp;
	FILE *log;
	long length;
	DB_cursor *cursor;
};
struct DB_cursor {
	DB_base const *isa;
	DB_txn *txn;
	bool has_reserve;
	// Inner cursor
};
#define CURSOR_INNER(c) ((c)+1)

static int put_ordered(DB_cursor *const cursor, DB_val *const key, DB_val *const val, unsigned const flags, bool const ordered) {
	unsigned xflags = ordered ? 0 : DB_NOOVERWRITE;
	DB_val const wr = val ? *val : (DB_val){ 0, NULL };
	DB_val rd = wr; // Even if val is null, we need to check.
	int rc = db_cursor_put(cursor, key, &rd, flags | xflags);
	if(val) *val = rd;
	if(!ordered && DB_KEYEXIST == rc) {
		// In unordered mode, we can't overwrite values.
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
	if(!cursor->txn->temp) return;
	if(!cursor->has_reserve) return;
	DB_val key[1], val[1];
	size_t len;
	int rc = db_cursor_current(CURSOR_INNER(cursor), key, val);
	assert(rc >= 0);
	DB_txn *const txn = cursor->txn;
	if(!txn->log) goto cleanup;

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

	rc = db_txn_begin(env->main, NULL, DB_RDWR, &txn);
	if(rc < 0) goto cleanup;
	rc = db_txn_cursor(txn, &cursor);
	if(rc < 0) goto cleanup;

	unsigned char meta[2] = { PFX_META, META_TXNID };
	*key = (DB_val){ sizeof(meta), meta };
	if(env->ordered) {
		char type = 0;
		unsigned txnidlen = 0;
		fscanf(log, "%c:%u;", &type, &txnidlen);
		if('O' != type) {
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
		rc = db_get(db_prefix_txn_raw(txn), key, val);
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
	} else {
		char type = 0;
		fscanf(log, "%c:", &type);
		if('U' != type) {
			rc = DB_INCOMPATIBLE;
			goto cleanup;
		}
	}
	*val = *data->txn_id;
	rc = db_put(db_prefix_txn_raw(txn), key, val, 0);
	if(rc < 0) goto cleanup;

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
			if(!env->ordered) rc = DB_BAD_TXN;
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
		keybuf[0] = PFX_MAIN;
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
		if('P' == type) rc = put_ordered(cursor, key, val, 0, env->ordered);
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
	return db_env_set_config(env, DB_CFG_APPLY, &data);
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
	env->flags = 0;
	env->path = NULL;
	env->mode = 0600;
	env->commit->fn = default_commit;
	env->ordered = true;

	rc = db_env_create_custom(db_base_prefix, &env->main);
	if(rc < 0) goto cleanup;
	rc = db_env_create_base("mdb", &inner);
	if(rc < 0) goto cleanup;
	rc = db_env_set_config(env->main, DB_CFG_INNERDB, inner);
	if(rc < 0) goto cleanup;
	inner = NULL;

	unsigned char buf[1] = { PFX_MAIN };
	DB_val pfx = { sizeof(buf), buf };
	rc = db_env_set_config(env->main, DB_CFG_PREFIX, &pfx);
	if(rc < 0) goto cleanup;

cleanup:
	db_env_close(inner); inner = NULL;
	if(rc < 0) db_env_destroy(env);
	return rc;
}
DB_FN int db__env_get_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_COMMIT: *(DB_commit_data *)data = *env->commit; return 0;
	case DB_CFG_APPLY: return DB_EINVAL;
	case DB_CFG_TXNID: {
		unsigned char buf[2] = { PFX_META, META_TXNID };
		DB_val key = { sizeof(buf), buf };
		DB_txn *txn = NULL;
		int rc = db_txn_begin(db_prefix_env_raw(env->main),
			NULL, DB_RDONLY, &txn);
		if(rc < 0) return rc;
		rc = db_get(txn, &key, data);
		db_txn_abort(txn);
		return rc;
	} case DB_CFG_TXNORDER: *(int *)data = env->ordered; return 0;
	case DB_CFG_KEYSIZE: {
		int rc = db_env_get_config(env->main, type, data);
		if(rc < 0) return rc;
		(*(size_t *)data)--; // For prefix
		return 0;
	} case DB_CFG_FLAGS: *(unsigned *)data = env->flags; return 0;
	case DB_CFG_FILENAME: *(char const **)data = env->path; return 0;
	case DB_CFG_FILEMODE: *(int *)data = env->mode; return 0;
	case DB_CFG_PREFIX: return DB_ENOTSUP;
	default: return db_env_get_config(env->main, type, data);
	}
}
DB_FN int db__env_set_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_TXNSIZE: return DB_ENOTSUP; // TODO
	case DB_CFG_COMMIT: *env->commit = *(DB_commit_data *)data; return 0;
	case DB_CFG_APPLY: return apply_internal(env, data);
	case DB_CFG_TXNID: {
		unsigned char buf[2] = { PFX_META, META_TXNID };
		DB_val key = { sizeof(buf), buf };
		DB_val val = *(DB_val *)data;
		DB_txn *txn = NULL;
		int rc = db_txn_begin(db_prefix_env_raw(env->main),
			NULL, DB_RDWR, &txn);
		if(rc < 0) return rc;
		rc = db_put(txn, &key, &val, 0);
		if(rc < 0) { db_txn_abort(txn); return rc; }
		return db_txn_commit(txn);
	} case DB_CFG_TXNORDER: env->ordered = *(int *)data; return 0;
	case DB_CFG_KEYSIZE: {
		(*(size_t *)data)++; // For prefix
		return db_env_get_config(env->main, type, data);
	} case DB_CFG_FLAGS: env->flags = *(unsigned *)data; return 0;
	case DB_CFG_FILENAME:
		free(env->path);
		env->path = data ? strdup(data) : NULL;
		if(data && !env->path) return DB_ENOMEM;
		return 0;
	case DB_CFG_FILEMODE: env->mode = *(int *)data; return 0;
	case DB_CFG_PREFIX: return DB_ENOTSUP;
	default: return db_env_set_config(env->main, type, data);
	}
}
DB_FN int db__env_open0(DB_env *const env) {
	if(!env) return DB_EINVAL;
	if(!env->path) return DB_EINVAL;
	char path[DB_PATH_MAX];
	int rc;

	rc = err(mkdir(env->path, env->mode | 0111)); // 0111 ensures dir is listable.
	if(DB_EEXIST == rc) {
		rc = 0;
	} else if(rc < 0) {
		goto cleanup;
	} else {
		// TODO: fsync
	}

	rc = err(snprintf(path, sizeof(path), "%s/main", env->path));
	if(rc >= sizeof(path)) rc = DB_ENAMETOOLONG;
	if(rc < 0) goto cleanup;
	db_env_set_config(env->main, DB_CFG_FLAGS, &env->flags);
	db_env_set_config(env->main, DB_CFG_FILENAME, path);
	db_env_set_config(env->main, DB_CFG_FILEMODE, &env->mode);
	rc = db_env_open0(env->main);
	if(rc < 0) goto cleanup;

	if(!(DB_RDONLY & env->flags)) {
		rc = db_env_create_base("mdb", &env->temp);
		if(rc < 0) goto cleanup;

		rc = err(snprintf(path, sizeof(path), "%s/temp", env->path));
		if(rc >= sizeof(path)) rc = DB_ENAMETOOLONG;
		if(rc < 0) goto cleanup;
		db_env_set_config(env->temp, DB_CFG_FILENAME, path);
		db_env_set_config(env->temp, DB_CFG_FILEMODE, &env->mode);
		rc = db_env_open0(env->temp);
		if(rc < 0) goto cleanup;
	}

cleanup:
	return rc;
}
DB_FN void db__env_destroy(DB_env *const env) {
	if(!env) return;
	db_env_close(env->main); env->main = NULL;
	db_env_close(env->temp); env->temp = NULL;
	env->commit->fn = NULL;
	env->commit->ctx = NULL;
	env->flags = 0;
	free(env->path); env->path = NULL;
	env->mode = 0;
	env->ordered = 0;
	env->isa = NULL;
	assert_zeroed(env, 1);
}

DB_FN size_t db__txn_size(DB_env *const env) {
	return sizeof(struct DB_txn);
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

	rc = db_txn_begin(env->main, parent ? parent->main : NULL, DB_RDONLY, &txn->main);
	if(rc < 0) goto cleanup;
	if(!(DB_RDONLY & flags)) {
		rc = db_txn_begin(env->temp, parent ? parent->temp : NULL, flags, &txn->temp);
		if(rc < 0) goto cleanup;

		if(parent) {
			txn->log = parent->log;
			txn->length = parent->length;
		} else {
			// TODO: We're keeping these purely for debugging.
			static int x = 0;
			char path[DB_PATH_MAX];
			rc = err(snprintf(path, sizeof(path), "%s/log-%d", env->path, x++));
			if(rc >= sizeof(path)) rc = DB_ENAMETOOLONG;
			if(rc < 0) goto cleanup;
			txn->log = fopen(path, "w+b");
			if(!txn->log) rc = -errno;
			if(rc < 0) goto cleanup;
			//remove(path);

			if(txn->env->ordered) {
				unsigned char buf[2] = { PFX_META, META_TXNID };
				DB_val key = { sizeof(buf), buf };
				DB_val val = { 0, NULL };
				rc = db_get(db_prefix_txn_raw(txn->main),
					&key, &val);
				if(DB_NOTFOUND == rc) rc = 0;
				if(rc < 0) goto cleanup;
				rc = fprintf(txn->log, "O:%u;", (unsigned)val.size);
				if(rc < 0) {
					rc = DB_EIO;
					goto cleanup;
				}
				size_t len = fwrite(val.data, 1, val.size, txn->log);
				if(len < val.size) rc = DB_EIO;
				if(rc < 0) goto cleanup;
				txn->length = ftell(txn->log);
				assert(txn->length >= 0);
			} else {
				rc = fprintf(txn->log, "U:");
				if(rc < 0) {
					rc = DB_EIO;
					goto cleanup;
				}
			}
		}
	}

	if(parent) parent->child = txn;
cleanup:
	if(rc < 0) db_txn_abort_destroy(txn);
	return rc;
}
DB_FN int db__txn_commit_destroy(DB_txn *const txn) {
	if(!txn) return DB_EINVAL;
	DB_env *const env = txn->env;
	FILE *log = NULL;
	size_t length = 0;
	int rc = 0;
	if(!txn->temp) goto cleanup; // DB_RDONLY
	if(txn->child) {
		rc = db_txn_commit(txn->child); txn->child = NULL;
		if(rc < 0) goto cleanup;
	}

	if(txn->parent) {
		db_cursor_close(txn->cursor); txn->cursor = NULL;
		rc = db_txn_commit(txn->temp); txn->temp = NULL;
		if(rc < 0) goto cleanup;
		txn->log = NULL;
		txn->parent->length = txn->length;
		goto cleanup;
	}

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

cleanup:
	fclose(log); log = NULL;
	db_txn_abort_destroy(txn);
	return rc;
}
DB_FN void db__txn_abort_destroy(DB_txn *const txn) {
	if(!txn) return;
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
	db_txn_abort(txn->main); txn->main = NULL;
	db_txn_abort(txn->temp); txn->temp = NULL;
	if(txn->parent) txn->parent->child = NULL;
	txn->isa = NULL;
	txn->env = NULL;
	txn->parent = NULL;
	txn->length = 0;
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
	return db_txn_get_flags(txn->temp, flags);
}
DB_FN int db__txn_cmp(DB_txn *const txn, DB_val const *const a, DB_val const *const b) {
	return db_txn_cmp(txn->temp, a, b);
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
	if(!txn->temp) return DB_EACCES;
	if(!txn->env->ordered) return DB_ENOTSUP;
	size_t len;
	int rc = 0;
	if(txn->log) {
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
	rc = db_wrbuf_del(txn->temp, key, flags);
	if(rc < 0) goto cleanup;
	if(txn->log) {
		txn->length = ftell(txn->log);
		assert(txn->length >= 0);
	}
cleanup:
	if(txn->log && rc < 0) {
		int x = err(fseek(txn->log, txn->length, SEEK_SET));
		assert(x >= 0);
	}
	return rc;
}
DB_FN int db__cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len) {
	if(!txn) return DB_EINVAL;
/*	if(!txn->env->cmd->fn) return DB_EINVAL;

	FILE *log = txn->log; txn->log = NULL;
	int rc = txn->env->cmd->fn(txn->env->cmd->ctx, txn, buf, len); // TODO
	assert(txn->isa); // Simple check that we weren't committed/aborted.
	txn->log = log;
//cleanup:
	return rc;*/
	return DB_ENOTSUP; // TODO
}

DB_FN int db__countr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_countr(txn, range, out);
}
DB_FN int db__delr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_delr(txn, range, out);
}

DB_FN size_t db__cursor_size(DB_txn *const txn) {
	DB_wrbuf_txn wrbuftxn = {
		.isa = db_base_wrbuf,
		.main = txn->main,
		.temp = txn->temp,
	};
	return sizeof(struct DB_cursor)+db_cursor_size((DB_txn *)&wrbuftxn);
}
DB_FN int db__cursor_init(DB_txn *const txn, DB_cursor *const cursor) {
	if(!txn) return DB_EINVAL;
	if(!cursor) return DB_EINVAL;
	assert_zeroed(cursor, 1);
	DB_wrbuf_txn wrbuftxn = {
		.isa = db_base_wrbuf,
		.main = txn->main,
		.temp = txn->temp,
	};
	int rc = 0;
	cursor->isa = db_base_distributed;
	cursor->txn = txn;

	rc = db_cursor_init((DB_txn *)&wrbuftxn, CURSOR_INNER(cursor));
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) db_cursor_destroy(cursor);
	return rc;
}
DB_FN void db__cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	db_cursor_destroy(CURSOR_INNER(cursor));
	cursor->isa = NULL;
	cursor->txn = NULL;
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
	if(!txn->temp) return DB_EACCES;
	reserve_finish(cursor);

	if(flags & ~(DB_NOOVERWRITE|DB_CURRENT|DB_NOOVERWRITE)) return DB_ENOTSUP;
	bool const ordered = cursor->txn->env->ordered;
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
	if(txn->log) {
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
	rc = put_ordered(CURSOR_INNER(cursor), key, val, flags & ~DB_CURRENT, ordered);
	if(rc < 0) goto cleanup;
	if(txn->log) {
		txn->length = ftell(txn->log);
		assert(txn->length >= 0);
	}
cleanup:
	if(txn->log && rc < 0) {
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

