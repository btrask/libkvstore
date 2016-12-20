// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/sha.h>

#include "liblmdb/lmdb.h"
#include "db_base_internal.h"
#include "db_wrbuf.h"
#include "common.h"

#define DB_PATH_MAX (1023+1)

#define KEY_MAX 510
#define VAL_MAX (1024*1024*1)
#define CMD_MAX (1024*1024*1)

#define DB_VAL_STORAGE(val, len) \
	unsigned char __buf_##val[(len)]; \
	*(val) = (DB_val){ 0, __buf_##val };

enum {
	PFX_META = 0x00,
	PFX_MAIN = 0x01,
};
enum {
	META_TXNHASH = 0x00,
};

struct DB_env {
	DB_base const *isa;
	DB_env *main;
	DB_env *temp;
	DB_cmd_data cmd[1];
	DB_commit_data commit[1];
	unsigned flags;
	char *path;
	int mode;
};
struct DB_txn {
	DB_base const *isa;
	DB_env *env;
	DB_txn *parent;
	DB_txn *child;
	DB_txn *main;
	DB_txn *temp;
	FILE *data;
	long length;
	DB_cursor *cursor;
};
struct DB_cursor {
	DB_base const *isa;
	DB_txn *txn;
	DB_wrbuf wrbuf[1];
};

static int err(int x) {
	if(x < 0) return -errno;
	return x;
}

static int fhash(FILE *const file, unsigned char *const out) {
	SHA256_CTX algo[1];
	unsigned char buf[1024*4];
	size_t len;
	int rc;
	rc = SHA256_Init(algo);
	assert(rc >= 0);
	for(;;) {
		len = fread(buf, 1, sizeof(buf), file);
		rc = SHA256_Update(algo, buf, len);
		assert(rc >= 0);
		if(len < sizeof(buf)) {
			if(feof(file)) break;
			return -1;
		}
	}
	rc = SHA256_Final(out, algo);
	assert(rc >= 0);
	return 0;
}

DB_FN int db__apply(DB_env *const env, FILE *const data, unsigned char const *const hash) {
	if(!env) return DB_EINVAL;
	if(!data) return DB_EINVAL;
	if(!hash) return DB_EINVAL;

	DB_txn *txn = NULL;
	DB_val key[1], val[1];
	unsigned char digest[SHA256_DIGEST_LENGTH];
	unsigned char *keybuf = NULL;
	unsigned char *valbuf = NULL;
	size_t len;
	int rc = 0;

	rc = fhash(data, digest);
	if(rc < 0) {
		rc = DB_EIO;
		goto cleanup;
	}
	rc = memcmp(hash, digest, sizeof(digest));
	if(0 != rc) {
		rc = DB_CORRUPTED;
		goto cleanup;
	}
	rc = err(fseek(data, 0, SEEK_SET));
	if(rc < 0) goto cleanup;

	rc = db_txn_begin(env->main, NULL, DB_RDWR, &txn);
	if(rc < 0) goto cleanup;

	unsigned hashlen = 0;
	fscanf(data, "X:%u;", &hashlen);
	if(sizeof(digest) != hashlen) rc = DB_CORRUPTED;
	if(rc < 0) goto cleanup;

	len = fread(digest, 1, sizeof(digest), data);
	if(len < sizeof(digest)) rc = DB_EIO;
	if(rc < 0) goto cleanup;

	unsigned char meta[2] = { PFX_META, META_TXNHASH };
	*key = (DB_val){ sizeof(meta), meta };
	*val = (DB_val){ 0, NULL };
	rc = db_get(txn, key, val);
	if(DB_NOTFOUND == rc) rc = 0;
	if(rc < 0) goto cleanup;
	if(sizeof(digest) != val->size) {
		rc = DB_CORRUPTED;
		goto cleanup;
	}
	rc = memcmp(val->data, digest, sizeof(digest));
	if(0 != rc) {
		rc = DB_CORRUPTED;
		goto cleanup;
	}

	*val = (DB_val){ sizeof(digest), (void *)hash };
	rc = db_put(txn, key, val, 0);
	if(rc < 0) goto cleanup;

	for(;;) {
		char type = 0;
		unsigned long long keylen = 0, vallen = 0;
		fscanf(data, "\n%c:", &type);
		if(0 == type) {
			break;
		} else if('P' == type) {
			fscanf(data, "%llu;", &keylen);
			fscanf(data, "%llu;", &vallen);
			if(0 == keylen) rc = DB_BAD_VALSIZE;
			if(keylen > KEY_MAX) rc = DB_BAD_VALSIZE;
			if(vallen > VAL_MAX) rc = DB_BAD_VALSIZE;
		} else if('D' == type) {
			fscanf(data, "%llu;", &keylen);
			if(0 == keylen) rc = DB_BAD_VALSIZE;
			if(keylen > KEY_MAX) rc = DB_BAD_VALSIZE;
		} else if('!' == type) {
			fscanf(data, "%llu;", &keylen);
			if(keylen > CMD_MAX) rc = DB_BAD_VALSIZE;
		} else {
			rc = DB_CORRUPTED;
		}
		if(rc < 0) goto cleanup;

		// 1. Allocations must be non-zero (undefined behavior).
		// 2. Keys for put or del will be prefixed with PFX_MAIN.
		// 3. Commands are stored in keybuf but not prefixed.
		keybuf = malloc(1+keylen);
		valbuf = malloc(1+vallen);
		if(!keybuf || !valbuf) {
			rc = DB_ENOMEM;
			goto cleanup;
		}
		keybuf[0] = PFX_MAIN;
		len = fread(1+keybuf, 1, keylen, data);
		if(len < keylen) {
			rc = DB_EIO;
			goto cleanup;
		}
		len = fread(0+valbuf, 1, vallen, data);
		if(len < vallen) {
			rc = DB_EIO;
			goto cleanup;
		}

		*key = (DB_val){ 1+keylen, 0+keybuf };
		*val = (DB_val){ 0+vallen, 0+valbuf };
		if('P' == type) rc = db_put(txn, key, val, 0);
		if('D' == type) rc = db_del(txn, key, 0);
		if('!' == type) rc = db_cmd(txn, 1+keybuf, 0+keylen);
		free(keybuf); keybuf = NULL;
		free(valbuf); valbuf = NULL;
		if(rc < 0) goto cleanup;
	}

	// TODO: Write new hash

	rc = db_txn_commit(txn); txn = NULL;
	if(rc < 0) goto cleanup;
cleanup:
	free(keybuf); keybuf = NULL;
	free(valbuf); valbuf = NULL;
	return rc;
}
#define db_apply db__apply // TODO
static int default_commit(void *ctx, DB_env *const env, FILE *const data, unsigned char const *const hash) {
	return db_apply(env, data, hash);
}


DB_FN size_t db__env_size(void) {
	return sizeof(struct DB_env);
}
DB_FN int db__env_init(DB_env *const env) {
	if(!env) return DB_EINVAL;
	assert_zeroed(env, 1);
	int rc = 0;
	env->isa = db_base_distributed;
	env->flags = 0;
	env->path = NULL;
	env->mode = 0600;
	env->commit->fn = default_commit;

	rc = db_env_create_base("mdb", &env->main);
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) db_env_destroy(env);
	return rc;
}
DB_FN int db__env_get_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	switch(type) {
	case DB_CFG_COMMAND: *(DB_cmd_data *)data = *env->cmd; return 0;
	case DB_CFG_INNERDB: *(DB_env **)data = env->main; return 0;
	case DB_CFG_COMMIT: *(DB_commit_data *)data = *env->commit; return 0;
	case DB_CFG_FLAGS: *(unsigned *)data = env->flags; return 0;
	case DB_CFG_FILENAME: *(char const **)data = env->path; return 0;
	case DB_CFG_FILEMODE: *(int *)data = env->mode; return 0;
	default: return db_env_get_config(env->main, type, data);
	}
}
DB_FN int db__env_set_config(DB_env *const env, unsigned const type, void *data) {
	if(!env) return DB_EINVAL;
	// TODO: We should have a way of swapping out the inner env.
	// And also a way of getting it to configure directly?
	// Ownership becomes a little bit complex...
	switch(type) {
	case DB_CFG_TXNSIZE: return DB_ENOTSUP; // TODO
	case DB_CFG_COMMAND: *env->cmd = *(DB_cmd_data *)data; return 0;
	case DB_CFG_INNERDB:
		db_env_close(env->main);
		env->main = (DB_env *)data;
		return 0;
	case DB_CFG_COMMIT: *env->commit = *(DB_commit_data *)data; return 0;
	case DB_CFG_FLAGS: env->flags = *(unsigned *)data; return 0;
	case DB_CFG_FILENAME:
		free(env->path);
		env->path = data ? strdup(data) : NULL;
		if(data && !env->path) return DB_ENOMEM;
		return 0;
	case DB_CFG_FILEMODE: env->mode = *(int *)data; return 0;
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
	env->cmd->fn = NULL;
	env->cmd->ctx = NULL;
	env->commit->fn = NULL;
	env->commit->ctx = NULL;
	env->flags = 0;
	free(env->path); env->path = NULL;
	env->mode = 0;
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
			txn->data = parent->data;
			txn->length = parent->length;
		} else {
			// TODO: We're keeping these purely for debugging.
			static int x = 0;
			char path[DB_PATH_MAX];
			rc = err(snprintf(path, sizeof(path), "%s/data-%d", env->path, x++));
			if(rc >= sizeof(path)) rc = DB_ENAMETOOLONG;
			if(rc < 0) goto cleanup;
			txn->data = fopen(path, "w+b");
			if(!txn->data) rc = -errno;
			if(rc < 0) goto cleanup;
			//remove(path);

			unsigned char buf[2] = { PFX_META, META_TXNHASH };
			DB_val key = { sizeof(buf), buf };
			DB_val val = { 0, NULL };
			rc = db_get(txn->main, &key, &val);
			if(DB_NOTFOUND == rc) rc = 0;
			if(rc < 0) goto cleanup;
			rc = fprintf(txn->data, "X:%u;", (unsigned)val.size);
			if(rc < 0) {
				rc = DB_EIO;
				goto cleanup;
			}
			size_t len = fwrite(val.data, 1, val.size, txn->data);
			if(len < val.size) rc = DB_EIO;
			if(rc < 0) goto cleanup;
			txn->length = ftell(txn->data);
			assert(txn->length >= 0);
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
	FILE *data = NULL;
	size_t length = 0;
	unsigned char digest[SHA256_DIGEST_LENGTH];
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
		txn->data = NULL;
		txn->parent->length = txn->length;
		goto cleanup;
	}

	data = txn->data; txn->data = NULL;
	length = txn->length; txn->length = 0;
	db_txn_abort_destroy(txn);

	rc = err(fflush(data));
	if(rc < 0) goto cleanup;
	rc = err(ftruncate(fileno(data), length));
	if(rc < 0) goto cleanup;

	rc = err(fseek(data, 0, SEEK_SET));
	if(rc < 0) goto cleanup;
	rc = fhash(data, digest);
	if(rc < 0) {
		rc = DB_EIO;
		goto cleanup;
	}

	rc = err(fseek(data, 0, SEEK_SET));
	if(rc < 0) goto cleanup;
	if(!env->commit->fn) {
		rc = DB_PANIC;
		goto cleanup;
	}
	rc = env->commit->fn(env->commit->ctx, env, data, digest);
	if(rc < 0) goto cleanup;

cleanup:
	fclose(data); data = NULL;
	db_txn_abort_destroy(txn);
	return rc;
}
DB_FN void db__txn_abort_destroy(DB_txn *const txn) {
	if(!txn) return;
	if(txn->child) {
		db_txn_abort(txn->child); txn->child = NULL;
	}
	if(!txn->data) {
		// Do nothing
	} else if(txn->parent) {
		int rc = err(fseek(txn->data, txn->parent->length, SEEK_SET));
		assert(rc >= 0);
		txn->data = NULL;
	} else {
		fclose(txn->data); txn->data = NULL;
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
DB_FN int db__txn_upgrade(DB_txn *const txn, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	return DB_ENOTSUP;
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
	if(!txn) return DB_EINVAL;
	if(flags & ~DB_NOOVERWRITE) return DB_ENOTSUP; // TODO
	if(!txn->temp) return DB_EACCES;
	size_t len;
	int rc = 0;
	if(txn->data) {
		rc = fprintf(txn->data, "\nP:%llu;%llu;",
			(unsigned long long)key->size,
			(unsigned long long)val->size);
		if(rc < 0) goto cleanup;
		len = fwrite(key->data, 1, key->size, txn->data);
		if(len < key->size) rc = DB_EIO;
		if(rc < 0) goto cleanup;
		len = fwrite(val->data, 1, val->size, txn->data);
		if(len < val->size) rc = DB_EIO;
		if(rc < 0) goto cleanup;
	}
	rc = db_helper_put(txn, key, val, flags);
	if(rc < 0) goto cleanup;
	if(txn->data) {
		txn->length = ftell(txn->data);
		assert(txn->length >= 0);
	}
cleanup:
	if(txn->data && rc < 0) {
		int x = err(fseek(txn->data, txn->length, SEEK_SET));
		assert(x >= 0);
	}
	return rc;
}
DB_FN int db__del(DB_txn *const txn, DB_val const *const key, unsigned const flags) {
	if(!txn) return DB_EINVAL;
	if(flags) return DB_ENOTSUP; // TODO
	if(!txn->temp) return DB_EACCES;
	size_t len;
	int rc = 0;
	if(txn->data) {
		rc = fprintf(txn->data, "\nD:%llu;",
			(unsigned long long)key->size);
		if(rc < 0) {
			rc = DB_EIO;
			goto cleanup;
		}
		len = fwrite(key->data, 1, key->size, txn->data);
		if(len < key->size) {
			rc = DB_EIO;
			goto cleanup;
		}
	}
	rc = db_wrbuf_del_direct(txn->temp, key, flags);
	if(rc < 0) goto cleanup;
	if(txn->data) {
		txn->length = ftell(txn->data);
		assert(txn->length >= 0);
	}
cleanup:
	if(txn->data && rc < 0) {
		int x = err(fseek(txn->data, txn->length, SEEK_SET));
		assert(x >= 0);
	}
	return rc;
}
DB_FN int db__cmd(DB_txn *const txn, unsigned char const *const buf, size_t const len) {
	if(!txn) return DB_EINVAL;
	if(!txn->env->cmd->fn) return DB_EINVAL;

	FILE *data = txn->data; txn->data = NULL;
	int rc = txn->env->cmd->fn(txn->env->cmd->ctx, txn, buf, len); // TODO
	assert(txn->isa); // Simple check that we weren't committed/aborted.
	txn->data = data;
//cleanup:
	return rc;
}

DB_FN int db__countr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_countr(txn, range, out);
}
DB_FN int db__delr(DB_txn *const txn, DB_range const *const range, uint64_t *const out) {
	return db_helper_delr(txn, range, out); // TODO
}

DB_FN size_t db__cursor_size(DB_txn *const txn) {
	return sizeof(struct DB_cursor);
}
DB_FN int db__cursor_init(DB_txn *const txn, DB_cursor *const cursor) {
	if(!txn) return DB_EINVAL;
	if(!cursor) return DB_EINVAL;
	assert_zeroed(cursor, 1);
	DB_cursor *t = NULL;
	DB_cursor *m = NULL;
	int rc = 0;
	cursor->isa = db_base_distributed;
	cursor->txn = txn;

	if(txn->temp) {
		rc = db_cursor_open(txn->temp, &t);
		if(rc < 0) goto cleanup;
	}
	rc = db_cursor_open(txn->main, &m);
	if(rc < 0) goto cleanup;
	rc = db_wrbuf_init(cursor->wrbuf, t, m);
	if(rc < 0) goto cleanup;
cleanup:
	if(rc < 0) {
		db_cursor_close(t); t = NULL;
		db_cursor_close(m); m = NULL;
		db_cursor_destroy(cursor);
	}
	return rc;
}
DB_FN void db__cursor_destroy(DB_cursor *const cursor) {
	if(!cursor) return;
	db_wrbuf_destroy(cursor->wrbuf);
	cursor->isa = NULL;
	cursor->txn = NULL;
	assert_zeroed(cursor, 1);
}
DB_FN int db__cursor_clear(DB_cursor *const cursor) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_clear(cursor->wrbuf);
}
DB_FN int db__cursor_txn(DB_cursor *const cursor, DB_txn **const out) {
	if(!cursor) return DB_EINVAL;
	if(!out) return DB_EINVAL;
	*out = cursor->txn;
	return 0;
}
DB_FN int db__cursor_cmp(DB_cursor *const cursor, DB_val const *const a, DB_val const *const b) {
	assert(cursor);
	return db_cursor_cmp(cursor->wrbuf->main, a, b);
}

DB_FN int db__cursor_current(DB_cursor *const cursor, DB_val *const key, DB_val *const data) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_current(cursor->wrbuf, key, data);
}
DB_FN int db__cursor_seek(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_seek(cursor->wrbuf, key, data, dir);
}
DB_FN int db__cursor_first(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_first(cursor->wrbuf, key, data, dir);
}
DB_FN int db__cursor_next(DB_cursor *const cursor, DB_val *const key, DB_val *const data, int const dir) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_next(cursor->wrbuf, key, data, dir);
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

DB_FN int db__cursor_put(DB_cursor *const cursor, DB_val *const key, DB_val *const data, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_put(cursor->wrbuf, key, data, flags); // TODO
}
DB_FN int db__cursor_del(DB_cursor *const cursor, unsigned const flags) {
	if(!cursor) return DB_EINVAL;
	return db_wrbuf_del(cursor->wrbuf, flags); // TODO
}

DB_BASE_V0(distributed)

