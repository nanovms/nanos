mkpath	= $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT	= $(patsubst %/,%,$(dir $(mkpath)))
SRC	= $(ROOT)/src

# To reveal verbose build messages, override Q= in command line.
Q	?= @

GO	?= go
CC	?= cc
NASM	?= nasm
LD	?= ld
HOSTCC	?= cc
STRIP	?= strip
OBJCOPY	?= objcopy
DD	?= dd
CAT	?= cat
RM	?= rm

CFLAGS	= -fno-stack-protector -g -O -fdata-sections -ffunction-sections $(includes)
LDFLAGS	= --gc-sections

IMAGE	= $(ROOT)/output/image/image
FS	= $(ROOT)/output/image/fs

BOOTIMG	= $(ROOT)/output/boot/boot.img
STAGE3	= $(ROOT)/output/stage3/stage3.img

# Host utilities.

MKFS	= $(ROOT)/output/mkfs/bin/mkfs
DUMP	= $(ROOT)/output/mkfs/bin/dump
CONTGEN	= $(ROOT)/output/contgen/bin/contgen

# Examples

TARGET	= webgs

FST	= $(ROOT)/output/examples/fst
HWG	= $(ROOT)/output/examples/hwg
HW	= $(ROOT)/output/examples/hw
HWS	= $(ROOT)/output/examples/hws
WEB	= $(ROOT)/output/examples/web
WEBS	= $(ROOT)/output/examples/webs
WEBG	= $(ROOT)/output/examples/webg
WEBGS	= $(ROOT)/output/examples/webgs

# Tests

OBJCACHE_TEST	= $(ROOT)/output/test/objcache_test
NETWORK_TEST	= $(ROOT)/output/test/network_test
ID_HEAP_TEST	= $(ROOT)/output/test/id_heap_test
PATH_TEST	= $(ROOT)/output/test/path_test

# Generated depedencies

CLOSURE_TMPL	= $(OUT)/runtime/closure_templates.h

# Vendored librarries
VENDOR		= $(ROOT)/vendor

LWIP		= $(VENDOR)/lwip
