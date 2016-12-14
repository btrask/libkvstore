// Copyright 2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <kvstore/db_base.h>
#include <kvstore/db_range.h>

#define numberof(x) (sizeof(x) / sizeof(*(x)))

#define E(expr) CHECK((rc = (expr)) >= 0, #expr)
#define RES(err, expr) ((rc = expr) == (err) || (CHECK(rc >= 0, #expr), 0))
#define CHECK(test, msg) ((test) ? (void)0 : ((void)fprintf(stderr, \
	"%s:%d: %s: %s\n", __FILE__, __LINE__, msg, db_strerror(rc)), abort()))

static void bind(DB_val *const x, uint32_t *const n) {
	x->size = sizeof(*n);
	x->data = n;
}
static uint32_t read(DB_val const *const x) {
	assert(sizeof(uint32_t) == x->size);
	return *(uint32_t *)x->data;
}

int main(int const argc, char const *const argv[]) {
	assert(3 == argc);
	char const *const base = argv[1];
	char const *const path = argv[2];

	DB_env *env = NULL;
	DB_txn *txn = NULL;
	DB_val key[1], val[1];
	uint32_t section;
	int rc;

	E(db_env_create_base(base, &env));
	E(db_env_open(env, path, 0, 0600));

	printf("Nested transactions\n");
	section = 4201;
	bind(key, &section);
	DB_txn *nested[5] = {};
	DB_txn *parent = NULL;
	for(uint32_t i = 0; i < numberof(nested); i++) {
		E(db_txn_begin(env, parent, DB_RDWR, &nested[i]));
		if(i > 0) {
			E(db_get(nested[i], key, val));
			CHECK(read(val) == i-1, "get");
		}
		bind(val, &i);
		E(db_put(nested[i], key, val, 0));
		parent = nested[i];
	}
	E(db_txn_commit(nested[0]));
	E(db_txn_begin(env, NULL, DB_RDONLY, &txn));
	E(db_get(txn, key, val));
	CHECK(read(val) == numberof(nested)-1, "get");
	db_txn_abort(txn); txn = NULL;

	db_env_close(env); env = NULL;
	return 0;
}

