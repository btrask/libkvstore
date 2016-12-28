// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <kvstore/kvs_base.h>

#define numberof(x) (sizeof(x) / sizeof(*(x)))

#define E(expr) CHECK((rc = (expr)) >= 0, #expr)
#define RES(err, expr) ((rc = expr) == (err) || (CHECK(rc >= 0, #expr), 0))
#define CHECK(test, msg) ((test) ? (void)0 : ((void)fprintf(stderr, \
	"%s:%d: %s: %s (%d)\n", __FILE__, __LINE__, msg, kvs_strerror(rc), rc), abort()))

static void bind(KVS_val *const x, uint32_t *const n) {
	x->size = sizeof(*n);
	x->data = n;
}
static uint32_t read(KVS_val const *const x) {
	assert(sizeof(uint32_t) == x->size);
	return *(uint32_t *)x->data;
}

int main(int const argc, char const *const argv[]) {
	assert(3 == argc);
	char const *const base = argv[1];
	char const *const path = argv[2];

	KVS_env *env = NULL;
	KVS_txn *txn = NULL;
	KVS_val key[1], val[1];
	uint32_t section;
	int rc;

	E(kvs_env_create_base(base, &env));
	E(kvs_env_open(env, path, 0, 0600));

	printf("Nested transactions\n");
	section = 4201;
	bind(key, &section);
	KVS_txn *nested[5] = {};
	KVS_txn *parent = NULL;
	for(uint32_t i = 0; i < numberof(nested); i++) {
		E(kvs_txn_begin(env, parent, KVS_RDWR, &nested[i]));
		if(parent) {
			E(kvs_get(nested[i], key, val));
			CHECK(read(val) == i-1, "get");
		}
		bind(val, &i);
		E(kvs_put(nested[i], key, val, 0));
		parent = nested[i];
	}
	E(kvs_txn_commit(nested[0]));
	E(kvs_txn_begin(env, NULL, KVS_RDONLY, &txn));
	E(kvs_get(txn, key, val));
	CHECK(read(val) == numberof(nested)-1, "get");
	kvs_txn_abort(txn); txn = NULL;

	kvs_env_close(env); env = NULL;
	return 0;
}

