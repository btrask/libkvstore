# Copyright 2016 Ben Trask
# MIT licensed (see LICENSE for details)

ROOT_DIR := .
BUILD_DIR := $(ROOT_DIR)/build
SRC_DIR := $(ROOT_DIR)/src
DEPS_DIR := $(ROOT_DIR)/deps
INCLUDE_DIR := $(ROOT_DIR)/include


CFLAGS += -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=500
CFLAGS += -g -fno-omit-frame-pointer
CFLAGS += -fstack-protector
CFLAGS += -fPIC
CFLAGS += -I$(DEPS_DIR)

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

# We define our own Objective-C root class (SLNObject) because we don't use
# Apple's frameworks. Warning only used by Clang. GCC complains about it when
# it stops on an unrelated error, but otherwise it doesn't cause any problems.
WARNINGS += -Wno-objc-root-class

# We use use the isa instance variable when checking that all of the other
# instance variables are zeroed.
WARNINGS += -Wno-deprecated-objc-isa-usage

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
LIBS := -lssl
OBJECTS := $(SRC_DIR)/db_ext.c $(SRC_DIR)/db_schema.c

STATIC_LIBS += $(DEPS_DIR)/liblmdb/liblmdb.a

ifeq ($(DB),rocksdb)
  CFLAGS += -DUSE_ROCKSDB
  SHARED_LIBS += $(DEPS_DIR)/snappy/.libs/libsnappy.so
  STATIC_LIBS += $(DEPS_DIR)/snappy/.libs/libsnappy.a
  LIBS += -lrocksdb
  LIBS += -lz
  LIBS += -lstdc++
  OBJECTS += $(BUILD_DIR)/src/db_base_leveldb.o
else ifeq ($(DB),hyper)
  SHARED_LIBS += $(DEPS_DIR)/snappy/.libs/libsnappy.so
  STATIC_LIBS += $(DEPS_DIR)/snappy/.libs/libsnappy.a
  LIBS += -lhyperleveldb
  LIBS += -lstdc++
  OBJECTS += $(BUILD_DIR)/src/db_base_leveldb.o
else ifeq ($(DB),leveldb)
  CFLAGS += -I$(DEPS_DIR)/leveldb/include -I$(DEPS_DIR)/snappy/include
  SHARED_LIBS += $(DEPS_DIR)/leveldb/libleveldb.so $(DEPS_DIR)/snappy/.libs/libsnappy.so
  STATIC_LIBS += $(DEPS_DIR)/leveldb/libleveldb.a $(DEPS_DIR)/snappy/.libs/libsnappy.a
  LIBS += -lstdc++
  OBJECTS += $(BUILD_DIR)/src/db_base_leveldb.o
else
  OBJECTS += $(BUILD_DIR)/src/db_base_mdb.o
endif

.PHONY: all
all: $(BUILD_DIR)/libkvstore.so $(BUILD_DIR)/libkvstore.a $(INCLUDE_DIR)/kvstore/db_base.h $(INCLUDE_DIR)/kvstore/db_ext.h $(INCLUDE_DIR)/kvstore/db_schema.h

$(BUILD_DIR)/libkvstore.so: $(OBJECTS) $(SHARED_LIBS)
	@- mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -shared $^ -o $@

$(BUILD_DIR)/libkvstore.a: $(OBJECTS) $(STATIC_LIBS)
	@- mkdir -p $(dir $@)
	$(AR) rs $@ $^

$(BUILD_DIR)/src/%.o: $(SRC_DIR)/%.c
	@- mkdir -p $(dir $@)
	@- mkdir -p $(dir $(BUILD_DIR)/h/src/$*.d)
	$(CC) -c $(CFLAGS) $(WARNINGS) -MMD -MP -MF $(BUILD_DIR)/h/src/$*.d -o $@ $<

# TODO: Find files in subdirectories without using shell?
-include $(shell find $(BUILD_DIR)/h -name "*.d")

$(INCLUDE_DIR)/kvstore/%.h: $(SRC_DIR)/%.h
	@- mkdir -p $(dir $@)
	cp $^ $@

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(INCLUDE_DIR)

.PHONY: distclean
distclean: clean
	- $(MAKE) distclean -C $(DEPS_DIR)/libressl-portable
	- $(MAKE) distclean -C $(DEPS_DIR)/uv


$(DEPS_DIR)/liblmdb/liblmdb.a: | mdb
.PHONY: mdb
mdb:
	$(MAKE) -C $(DEPS_DIR)/liblmdb --no-print-directory

$(DEPS_DIR)/leveldb/libleveldb.a: | leveldb
.PHONY: leveldb
leveldb:
	$(MAKE) -C $(DEPS_DIR)/leveldb --no-print-directory

$(DEPS_DIR)/snappy/.libs/libsnappy.a: | snappy
.PHONY: snappy
snappy:
	$(MAKE) -C $(DEPS_DIR)/snappy --no-print-directory

