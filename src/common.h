// Copyright 2014-2015 Ben Trask
// MIT licensed (see LICENSE for details)

#ifndef COMMON_H
#define COMMON_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define numberof(x) (sizeof(x) / sizeof(*(x)))

#define STR_LEN(str) (str), (sizeof(str)-1)

#define MIN(a, b) ({ \
	__typeof__(a) const __a = (a); \
	__typeof__(b) const __b = (b); \
	__a < __b ? __a : __b; \
})
#define MAX(a, b) ({ \
	__typeof__(a) const __a = (a); \
	__typeof__(b) const __b = (b); \
	__a > __b ? __a : __b; \
})

#ifdef NDEBUG
#define assertf(x, fmt, ...) (void)0
#define assert_zeroed(ptr, count) (void)0
#else
#define assertf(x, fmt, ...) do { \
	if(0 == (x)) { \
		fprintf(stderr, "%s:%d %s: assertion '%s' failed\n", \
			__FILE__, __LINE__, __PRETTY_FUNCTION__, #x); \
		fprintf(stderr, fmt, ##__VA_ARGS__); \
		fprintf(stderr, "\n"); \
		abort(); \
	} \
} while(0)
#define assert_zeroed(ptr, count) do { \
	void const *const __p = (ptr); \
	size_t const __c = (count); \
	for(size_t __i = 0; __i < sizeof(*(ptr)) * __c; __i++) { \
		if(0 == ((unsigned char const *)__p)[__i]) continue; \
		fprintf(stderr, "%s:%d Buffer at %p not zeroed (%zu of %zu * %zu)\n", \
			__FILE__, __LINE__, __p, __i, sizeof(*(ptr)), __c); \
		abort(); \
	} \
} while(0)
#endif

#define HERE() fprintf(stderr, "%s:%d\n", __FILE__, __LINE__)

#define UNUSED(x) ((void)(x))

#define FREE(ptrptr) do { \
	__typeof__(ptrptr) const __x = (ptrptr); \
	free(*__x); *__x = NULL; \
} while(0)

#endif
