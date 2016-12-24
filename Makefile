# Copyright 2016 Ben Trask
# MIT licensed (see LICENSE for details)

USE_MDB ?= 1
USE_LEVELDB ?= 1
USE_ROCKSDB ?= 0
USE_HYPER ?= 0
USE_DEBUG ?= 1
USE_DISTRIBUTED ?= 1
USE_DUMMY ?= 1

DESTDIR ?=
PREFIX ?= /usr/local

.SUFFIXES:
.SECONDARY:

ROOT_DIR := .
BUILD_DIR := $(ROOT_DIR)/build
SRC_DIR := $(ROOT_DIR)/src
DEPS_DIR := $(ROOT_DIR)/deps
INCLUDE_DIR := $(BUILD_DIR)/include

CFLAGS += -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=500
CFLAGS += -g -fno-omit-frame-pointer
CFLAGS += -fstack-protector
CFLAGS += -fPIC
CFLAGS += -I$(DEPS_DIR)
CFLAGS += -I$(INCLUDE_DIR)
CFLAGS += -DKVS_DYNAMIC

WARNINGS := -Werror -Wall -Wextra -Wunused -Wuninitialized -Wvla

# TODO: Unsupported under Clang.
#WARNINGS += -Wlogical-op

# Disabled because it causes a lot of problems on Raspbian (GCC 4.6.3)
# without much perceivable benefit.
#WARNINGS += -Wshadow

# TODO: Useful with GCC but Clang doesn't like it.
#WARNINGS += -Wmaybe-uninitialized

# Causes all string literals to be marked const.
# This would be way too annoying if we don't use const everywhere already.
# The only problem is uv_buf_t, which is const sometimes and not others.
WARNINGS += -Wwrite-strings

# A function's interface is an abstraction and shouldn't strictly reflect
# its implementation. I don't believe in cluttering the code with UNUSED(X).
WARNINGS += -Wno-unused-parameter

# Seems too noisy for static functions in headers.
WARNINGS += -Wno-unused-function

# For OS X.
WARNINGS += -Wno-deprecated

# Checking that an unsigned variable is less than a constant which happens
# to be zero should be okay.
WARNINGS += -Wno-type-limits

# Usually happens for a ssize_t after already being checked for non-negative,
# or a constant that I don't want to stick a "u" on.
WARNINGS += -Wno-sign-compare

# Checks that format strings are literals amongst other things.
WARNINGS += -Wformat=2


SHARED_LIBS :=
STATIC_LIBS :=
LIBS := -lpthread
OBJECTS := \
	$(BUILD_DIR)/src/kvs_base_dynamic.o \
	$(BUILD_DIR)/src/kvs_helper.o \
	$(BUILD_DIR)/src/kvs_wrbuf.o \
	$(BUILD_DIR)/src/kvs_base_prefix.o \
	$(BUILD_DIR)/src/kvs_schema.o

SHARED_LIBS += $(DEPS_DIR)/liblmdb/liblmdb.so
STATIC_LIBS += $(DEPS_DIR)/liblmdb/liblmdb.a


ifeq ($(DB),rocksdb)
  CFLAGS += -DKVS_BASE_DEFAULT=kvs_base_leveldb
else ifeq ($(DB),hyper)
  CFLAGS += -DKVS_BASE_DEFAULT=kvs_base_leveldb
else ifeq ($(DB),leveldb)
  CFLAGS += -DKVS_BASE_DEFAULT=kvs_base_leveldb
else ifeq ($(DB),debug)
  CFLAGS += -DKVS_BASE_DEFAULT=kvs_base_debug
else ifeq ($(DB),distributed)
  CFLAGS += -DKVS_BASE_DEFAULT=kvs_base_distributed
else ifeq ($(DB),mdb)
  CFLAGS += -DKVS_BASE_DEFAULT=kvs_base_mdb
else ifndef DB
  CFLAGS += -DKVS_BASE_DEFAULT=kvs_base_mdb
else
  $(error Unknown back-end $(DB))
endif

ifeq ($(USE_MDB),1)
  CFLAGS += -DKVS_BASE_MDB
  OBJECTS += $(BUILD_DIR)/src/kvs_base_mdb.o
endif

ifeq ($(USE_LEVELDB),1)
  CFLAGS += -DKVS_BASE_LEVELDB
  CFLAGS += -I$(DEPS_DIR)/leveldb/include -I$(DEPS_DIR)/snappy/include
  SHARED_LIBS += $(DEPS_DIR)/leveldb/out-shared/libleveldb.so $(DEPS_DIR)/snappy/.libs/libsnappy.so
  STATIC_LIBS += $(DEPS_DIR)/leveldb/out-static/libleveldb.a $(DEPS_DIR)/snappy/.libs/libsnappy.a
  LIBS += -lstdc++
  OBJECTS += $(BUILD_DIR)/src/kvs_base_leveldb.o
endif

ifeq ($(USE_ROCKSDB),1)
  CFLAGS += -DKVS_BASE_ROCKSDB
  SHARED_LIBS += $(DEPS_DIR)/snappy/.libs/libsnappy.so
  STATIC_LIBS += $(DEPS_DIR)/snappy/.libs/libsnappy.a
  LIBS += -lrocksdb
  LIBS += -lz
  LIBS += -lstdc++
  OBJECTS += $(BUILD_DIR)/src/kvs_base_leveldb.o
endif

ifeq ($(USE_HYPER),1)
  CFLAGS += -DKVS_BASE_HYPER
  SHARED_LIBS += $(DEPS_DIR)/snappy/.libs/libsnappy.so
  STATIC_LIBS += $(DEPS_DIR)/snappy/.libs/libsnappy.a
  LIBS += -lhyperleveldb
  LIBS += -lstdc++
  OBJECTS += $(BUILD_DIR)/src/kvs_base_leveldb.o
endif

ifeq ($(USE_DEBUG),1)
  CFLAGS += -DKVS_BASE_DEBUG
  OBJECTS += $(BUILD_DIR)/src/kvs_base_debug.o
endif

ifeq ($(USE_DISTRIBUTED),1)
  CFLAGS += -DKVS_BASE_DISTRIBUTED
  OBJECTS += $(BUILD_DIR)/src/kvs_base_distributed.o
endif

ifeq ($(USE_DUMMY),1)
  CFLAGS += -DKVS_BASE_DUMMY
  OBJECTS += $(BUILD_DIR)/src/kvs_base_dummy.o
endif

HEADERS := \
	$(INCLUDE_DIR)/kvstore/kvs_base.h \
	$(INCLUDE_DIR)/kvstore/kvs_base_custom.h \
	$(INCLUDE_DIR)/kvstore/kvs_schema.h

.PHONY: all
all: $(BUILD_DIR)/libkvstore.so $(BUILD_DIR)/libkvstore.a $(HEADERS)

$(BUILD_DIR)/libkvstore.so: $(OBJECTS) $(STATIC_LIBS)
	@- mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -shared $^ -o $@

$(BUILD_DIR)/libkvstore.a: $(OBJECTS) $(STATIC_LIBS)
	@- mkdir -p $(dir $@)
	$(AR) rs $@ $(OBJECTS)

$(BUILD_DIR)/%.o: $(ROOT_DIR)/%.c | $(HEADERS)
	@- mkdir -p $(dir $@)
	@- mkdir -p $(dir $(BUILD_DIR)/h/$*.d)
	$(CC) -c $(CFLAGS) $(WARNINGS) -MMD -MP -MF $(BUILD_DIR)/h/$*.d -o $@ $<

# TODO: Find files in subdirectories without using shell?
-include $(shell find $(BUILD_DIR)/h -name "*.d")

$(INCLUDE_DIR)/kvstore/%.h: $(SRC_DIR)/%.h
	@- mkdir -p $(dir $@)
	cp $^ $@

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf ./testdb ./testdb-lock

.PHONY: distclean
distclean: clean
	- $(MAKE) clean -C $(DEPS_DIR)/leveldb
	- $(MAKE) clean -C $(DEPS_DIR)/liblmdb
	- $(MAKE) distclean -C $(DEPS_DIR)/snappy

.PHONY: test
test: mtest.run general.run

.PHONY: %.run
%.run: $(BUILD_DIR)/test/%
	rm -rf ./testdb ./testdb-lock
	$^ mdb ./testdb > $^.mdb.log
	rm -rf ./testdb ./testdb-lock
	$^ debug ./testdb > $^.debug.log 2>&1
	rm -rf ./testdb ./testdb-lock
	$^ leveldb ./testdb > $^.leveldb.log

$(BUILD_DIR)/test/%: $(BUILD_DIR)/test/%.o $(BUILD_DIR)/libkvstore.a $(STATIC_LIBS)
	@- mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@

$(DESTDIR)$(PREFIX)/include/%: $(INCLUDE_DIR)/%
	@- mkdir -p $(dir $@)
	cp $^ $@

$(DESTDIR)$(PREFIX)/lib/%: $(BUILD_DIR)/%
	@- mkdir -p $(dir $@)
	cp $^ $@

.PHONY: install
install: $(DESTDIR)$(PREFIX)/include/kvstore/kvs_base.h $(DESTDIR)$(PREFIX)/include/kvstore/kvs_base_custom.h $(DESTDIR)$(PREFIX)/include/kvstore/kvs_schema.h $(DESTDIR)$(PREFIX)/lib/libkvstore.so $(DESTDIR)$(PREFIX)/lib/libkvstore.a

.PHONY: uninstall
uninstall:
	rm -rf $(DESTDIR)$(PREFIX)/include/kvstore
	rm $(DESTDIR)$(PREFIX)/lib/libkvstore.so
	rm $(DESTDIR)$(PREFIX)/lib/libkvstore.a



$(DEPS_DIR)/liblmdb/liblmdb.a: | mdb
.PHONY: mdb
mdb:
	XCFLAGS="-fPIC" $(MAKE) -C $(DEPS_DIR)/liblmdb --no-print-directory

$(DEPS_DIR)/leveldb/out-shared/libleveldb.so: | leveldb
$(DEPS_DIR)/leveldb/out-static/libleveldb.a: | leveldb
.PHONY: leveldb
leveldb: snappy
	CFLAGS="-fPIC -DSNAPPY -I../snappy/" CXXFLAGS="-fPIC -DSNAPPY -I../snappy/" LIBS="-L../snappy/.libs/ -lsnappy" $(MAKE) -C $(DEPS_DIR)/leveldb --no-print-directory

$(DEPS_DIR)/snappy/.libs/libsnappy.so: | snappy
$(DEPS_DIR)/snappy/.libs/libsnappy.a: | snappy
.PHONY: snappy
snappy:
	$(MAKE) -C $(DEPS_DIR)/snappy --no-print-directory

