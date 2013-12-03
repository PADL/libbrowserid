AUTOMAKE_OPTIONS = foreign

if TARGET_MACOSX
noinst_HEADERS = cfjson.h
noinst_LTLIBRARIES = libcfjson.la

libcfjson_la_CPPFLAGS  = -I$(top_srcdir) -I$(top_srcdir)/libcfjson -I$(top_srcdir)/libbrowserid
libcfjson_la_OBJCFLAGS = -Werror -Wall -Wunused-parameter
libcfjson_la_SOURCES   = cfjson.m
endif

