/* mtest.c - memory-mapped database tester/toy */
/*
 * Copyright 2011-2016 Howard Chu, Symas Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <kvstore/db_base.h>

#define E(expr) CHECK((rc = (expr)) >= 0, #expr)
#define RES(err, expr) ((rc = expr) == (err) || (CHECK(rc >= 0, #expr), 0))
#define CHECK(test, msg) ((test) ? (void)0 : ((void)fprintf(stderr, \
	"%s:%d: %s: %s\n", __FILE__, __LINE__, msg, db_strerror(rc)), abort()))

int main(int argc,char * argv[])
{
	int i = 0, j = 0, rc;
	DB_env *env;
	DB_val key, data;
	DB_txn *txn;
//	DB_stat mst;
	DB_cursor *cursor, *cur2;
	DB_cursor_op op;
	int count;
	int *values;
	char sval[32] = "";

	srand(time(NULL));

	    count = (rand()%384) + 64;
	    values = (int *)malloc(count*sizeof(int));

	    for(i = 0;i<count;i++) {
			values[i] = rand()%1024;
	    }
    
		E(db_env_create(&env));
		size_t size = 10485760;
		E(db_env_config(env, DB_CFG_MAPSIZE, &size));
//		E(db_env_set_maxreaders(env, 1));
//		E(db_env_set_mapsize(env, 10485760));
		E(db_env_open(env, "./testdb", 0 /*DB_FIXEDMAP*/ /*|MDB_NOSYNC*/, 0664));

		E(db_txn_begin(env, NULL, 0, &txn));
//		E(db_dbi_open(txn, NULL, 0, &dbi));
   
		key.size = sizeof(int);
		key.data = sval;

		printf("Adding %d values\n", count);
	    for (i=0;i<count;i++) {	
			sprintf(sval, "%03x %d foo bar", values[i], values[i]);
			/* Set <data> in each iteration, since DB_NOOVERWRITE may modify it */
			data.size = sizeof(sval);
			data.data = sval;
			if (RES(DB_KEYEXIST, db_put(txn, &key, &data, DB_NOOVERWRITE))) {
				j++;
				data.size = sizeof(sval);
				data.data = sval;
			}
	    }
		if (j) printf("%d duplicates skipped\n", j);
		E(db_txn_commit(txn));
//		E(db_env_stat(env, &mst));

		E(db_txn_begin(env, NULL, DB_RDONLY, &txn));
		E(db_cursor_open(txn, &cursor));
		while ((rc = db_cursor_next(cursor, &key, &data, +1)) == 0) {
			printf("key: %p %.*s, data: %p %.*s\n",
				key.data,  (int) key.size,  (char *) key.data,
				data.data, (int) data.size, (char *) data.data);
		}
		CHECK(rc == DB_NOTFOUND, "db_cursor_get");
		db_cursor_close(cursor);
		db_txn_abort(txn);

		j=0;
		key.data = sval;
	    for (i= count - 1; i > -1; i-= (rand()%5)) {
			j++;
			txn=NULL;
			E(db_txn_begin(env, NULL, 0, &txn));
			sprintf(sval, "%03x ", values[i]);
			if (RES(DB_NOTFOUND, db_del(txn, &key, 0))) {
				j--;
				db_txn_abort(txn);
			} else {
				E(db_txn_commit(txn));
			}
	    }
	    free(values);
		printf("Deleted %d values\n", j);

//		E(db_env_stat(env, &mst));
		E(db_txn_begin(env, NULL, DB_RDONLY, &txn));
		E(db_cursor_open(txn, &cursor));
		printf("Cursor next\n");
		while ((rc = db_cursor_next(cursor, &key, &data, +1)) == 0) {
			printf("key: %.*s, data: %.*s\n",
				(int) key.size,  (char *) key.data,
				(int) data.size, (char *) data.data);
		}
		CHECK(rc == DB_NOTFOUND, "db_cursor_get");
		printf("Cursor last\n");
		E(db_cursor_first(cursor, &key, &data, -1));
		printf("key: %.*s, data: %.*s\n",
			(int) key.size,  (char *) key.data,
			(int) data.size, (char *) data.data);
		printf("Cursor prev\n");
		while ((rc = db_cursor_next(cursor, &key, &data, -1)) == 0) {
			printf("key: %.*s, data: %.*s\n",
				(int) key.size,  (char *) key.data,
				(int) data.size, (char *) data.data);
		}
		CHECK(rc == DB_NOTFOUND, "db_cursor_get");
		printf("Cursor last/prev\n");
		E(db_cursor_first(cursor, &key, &data, -1));
			printf("key: %.*s, data: %.*s\n",
				(int) key.size,  (char *) key.data,
				(int) data.size, (char *) data.data);
		E(db_cursor_next(cursor, &key, &data, -1));
			printf("key: %.*s, data: %.*s\n",
				(int) key.size,  (char *) key.data,
				(int) data.size, (char *) data.data);

		db_cursor_close(cursor);
		db_txn_abort(txn);

		printf("Deleting with cursor\n");
		E(db_txn_begin(env, NULL, 0, &txn));
		E(db_cursor_open(txn, &cur2));
		for (i=0; i<50; i++) {
			if (RES(DB_NOTFOUND, db_cursor_next(cur2, &key, &data, +1)))
				break;
			printf("key: %p %.*s, data: %p %.*s\n",
				key.data,  (int) key.size,  (char *) key.data,
				data.data, (int) data.size, (char *) data.data);
			E(db_del(txn, &key, 0));
		}

		printf("Restarting cursor in txn\n");
		for (op=DB_FIRST, i=0; i<=32; op=DB_NEXT, i++) {
			if (RES(DB_NOTFOUND, db_cursor_get(cur2, &key, &data, op)))
				break;
			printf("key: %p %.*s, data: %p %.*s\n",
				key.data,  (int) key.size,  (char *) key.data,
				data.data, (int) data.size, (char *) data.data);
		}
		db_cursor_close(cur2);
		E(db_txn_commit(txn));

		printf("Restarting cursor outside txn\n");
		E(db_txn_begin(env, NULL, 0, &txn));
		E(db_cursor_open(txn, &cursor));
		for (op=DB_FIRST, i=0; i<=32; op=DB_NEXT, i++) {
			if (RES(DB_NOTFOUND, db_cursor_get(cursor, &key, &data, op)))
				break;
			printf("key: %p %.*s, data: %p %.*s\n",
				key.data,  (int) key.size,  (char *) key.data,
				data.data, (int) data.size, (char *) data.data);
		}
		db_cursor_close(cursor);
		db_txn_abort(txn);

//		db_dbi_close(env, dbi);
		db_env_close(env);

	return 0;
}
